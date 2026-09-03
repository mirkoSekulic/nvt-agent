package dockerbackend

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun"
	"gopkg.in/yaml.v3"
)

var errRegistryIdentityCollision = errors.New("broker registry identity collision")

type brokerPolicy struct {
	Agents []brokerAgent `yaml:"agents"`
}

type brokerAgent struct {
	ID          string        `yaml:"id"`
	TokenSHA256 string        `yaml:"token-sha256"`
	Role        string        `yaml:"role,omitempty"`
	PairedAgent string        `yaml:"paired-agent,omitempty"`
	Grants      []brokerGrant `yaml:"grants,omitempty"`
}

type brokerGrant struct {
	Provider              string                    `yaml:"provider"`
	Repositories          []string                  `yaml:"repositories,omitempty"`
	Resources             []string                  `yaml:"resources,omitempty"`
	Capabilities          []string                  `yaml:"capabilities,omitempty"`
	Preparations          []string                  `yaml:"preparations,omitempty"`
	Materialization       string                    `yaml:"materialization,omitempty"`
	EgressHosts           []string                  `yaml:"egress-hosts,omitempty"`
	Git                   bool                      `yaml:"git,omitempty"`
	Permissions           map[string]string         `yaml:"permissions,omitempty"`
	Authorization         *brokerGrantAuthorization `yaml:"authorization,omitempty"`
	Quota                 *brokerGrantQuota         `yaml:"quota,omitempty"`
	AllowInsecureUpstream bool                      `yaml:"allow-insecure-upstream,omitempty"`
}

type brokerGrantQuota struct {
	Requests int64 `yaml:"requests"`
}

type brokerGrantAuthorization struct {
	DefaultAction string                         `yaml:"defaultAction"`
	Rules         []brokerGrantAuthorizationRule `yaml:"rules,omitempty"`
}

type brokerGrantAuthorizationRule struct {
	Operation string `yaml:"operation"`
	Resource  string `yaml:"resource"`
}

func loadIdentityKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 32 || info.Size() > 4096 {
		return nil, errors.New("identity key unavailable")
	}
	key, err := os.ReadFile(path)
	if err != nil || len(key) < 32 || len(key) > 4096 {
		return nil, errors.New("identity key unavailable")
	}
	return key, nil
}

func deriveTokens(key []byte, runID, digest string) identityTokens {
	derive := func(role string) string {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte("nvt.local-controller.identity/v1\x00" + runID + "\x00" + digest + "\x00" + role))
		return "nvt_local_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return identityTokens{agent: derive("agent"), egress: derive("egress")}
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(digest[:])
}

type brokerRegistry struct {
	path string
}

func (registry brokerRegistry) upsert(ctx context.Context, run resolvedrun.ResolvedAgentRun, digest string, tokens identityTokens) error {
	agentID, egressID := brokerIDs(run.RunID)
	agent := brokerAgent{ID: agentID, TokenSHA256: tokenHash(tokens.agent), Grants: make([]brokerGrant, 0, len(run.Broker.Grants))}
	for _, grant := range run.Broker.Grants {
		entry := brokerGrant{
			Provider: grant.Provider, Repositories: append([]string(nil), grant.Repositories...),
			Resources:    append([]string(nil), grant.Resources...),
			Capabilities: append([]string(nil), grant.Capabilities...), Preparations: append([]string(nil), grant.Preparations...),
			Materialization: grant.Materialization, EgressHosts: append([]string(nil), grant.EgressHosts...), Git: grant.Git,
			AllowInsecureUpstream: grant.AllowInsecureUpstream,
		}
		if grant.Authorization != nil {
			entry.Authorization = &brokerGrantAuthorization{DefaultAction: grant.Authorization.DefaultAction}
			for _, rule := range grant.Authorization.Rules {
				entry.Authorization.Rules = append(entry.Authorization.Rules, brokerGrantAuthorizationRule{Operation: rule.Operation, Resource: rule.Resource})
			}
		}
		if len(grant.Permissions) != 0 {
			entry.Permissions = make(map[string]string, len(grant.Permissions))
			for key, value := range grant.Permissions {
				entry.Permissions[key] = value
			}
		}
		if grant.Quota != nil {
			entry.Quota = &brokerGrantQuota{Requests: grant.Quota.Requests}
		}
		agent.Grants = append(agent.Grants, entry)
	}
	entries := []brokerAgent{agent}
	if run.Egress.PairedEgressRequired {
		entries = append(entries, brokerAgent{ID: egressID, TokenSHA256: tokenHash(tokens.egress), Role: "egress", PairedAgent: agentID})
	}
	return registry.mutate(ctx, func(policy *brokerPolicy) error {
		remove := map[string]bool{agentID: true, egressID: true}
		retained := policy.Agents[:0]
		for _, existing := range policy.Agents {
			if remove[existing.ID] {
				expectedHash := tokenHash(tokens.agent)
				if existing.ID == egressID {
					expectedHash = tokenHash(tokens.egress)
				}
				if existing.TokenSHA256 != expectedHash {
					return errRegistryIdentityCollision
				}
				continue
			}
			retained = append(retained, existing)
		}
		policy.Agents = append(retained, entries...)
		return nil
	})
}

func (registry brokerRegistry) remove(ctx context.Context, runID string, tokens identityTokens) error {
	agentID, egressID := brokerIDs(runID)
	return registry.mutate(ctx, func(policy *brokerPolicy) error {
		retained := policy.Agents[:0]
		for _, entry := range policy.Agents {
			if entry.ID == agentID || entry.ID == egressID {
				expectedHash := tokenHash(tokens.agent)
				if entry.ID == egressID {
					expectedHash = tokenHash(tokens.egress)
				}
				if entry.TokenSHA256 != expectedHash {
					return errRegistryIdentityCollision
				}
				continue
			}
			retained = append(retained, entry)
		}
		policy.Agents = retained
		return nil
	})
}

func (registry brokerRegistry) mutate(ctx context.Context, change func(*brokerPolicy) error) error {
	lockPath := strings.TrimSuffix(registry.path, filepath.Ext(registry.path)) + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return errors.New("broker registry unavailable")
	}
	defer lock.Close()
	directoryUID, directoryGID, err := fileOwnership(filepath.Dir(registry.path))
	if err != nil || lock.Chown(directoryUID, directoryGID) != nil || lock.Chmod(0o600) != nil {
		return errors.New("broker registry unavailable")
	}
	if err := acquireRegistryLock(ctx, int(lock.Fd())); err != nil {
		return errors.New("broker registry unavailable")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck
	raw, err := os.ReadFile(registry.path)
	if err != nil {
		return errors.New("broker registry unavailable")
	}
	var policy brokerPolicy
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return errors.New("broker registry unavailable")
	}
	if policy.Agents == nil {
		policy.Agents = []brokerAgent{}
	}
	if err := change(&policy); err != nil {
		return err
	}
	sort.Slice(policy.Agents, func(i, j int) bool { return policy.Agents[i].ID < policy.Agents[j].ID })
	if err := validateBrokerPolicy(policy); err != nil {
		return errors.New("broker registry unavailable")
	}
	encoded, err := yaml.Marshal(policy)
	if err != nil || len(encoded) > 4<<20 {
		return errors.New("broker registry unavailable")
	}
	return atomicWrite(registry.path, encoded, 0o600)
}

func acquireRegistryLock(ctx context.Context, descriptor int) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func validateBrokerPolicy(policy brokerPolicy) error {
	ids, hashes := map[string]bool{}, map[string]bool{}
	for _, agent := range policy.Agents {
		if agent.ID == "" || ids[agent.ID] || len(agent.TokenSHA256) != 71 || !strings.HasPrefix(agent.TokenSHA256, "sha256:") || hashes[agent.TokenSHA256] {
			return errors.New("invalid broker identity")
		}
		ids[agent.ID], hashes[agent.TokenSHA256] = true, true
		if agent.Role == "egress" && (agent.PairedAgent == "" || len(agent.Grants) != 0) {
			return errors.New("invalid paired identity")
		}
	}
	for _, agent := range policy.Agents {
		if agent.Role == "egress" && !ids[agent.PairedAgent] {
			return errors.New("invalid paired identity")
		}
	}
	return nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	ownerPath := path
	if _, err := os.Lstat(ownerPath); errors.Is(err, os.ErrNotExist) {
		ownerPath = directory
	} else if err != nil {
		return err
	}
	uid, gid, err := fileOwnership(ownerPath)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".nvt-local-controller-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chown(uid, gid); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func fileOwnership(path string) (int, int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("file ownership unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func brokerIDs(runID string) (string, string) {
	digest := sha256.Sum256([]byte("nvt.local-controller.broker-id/v1\x00" + runID))
	base := "nvt-local-" + hex.EncodeToString(digest[:12])
	return base, base + "-egress"
}

func registrySummary(registry brokerRegistry) string {
	return fmt.Sprintf("broker-registry:%s", filepath.Base(registry.path))
}
