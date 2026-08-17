package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

type preparedPlaceholderFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode"`
}

type preparedProviderMetadata struct {
	Version   int                                   `json:"version"`
	Providers map[string]preparedProviderOperations `json:"providers"`
}

type preparedProviderOperations struct {
	Identity *preparedProviderIdentity `json:"identity,omitempty"`
}

type preparedProviderIdentity struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type requestedProviderPreparation struct {
	Provider  string
	Operation nvtv1alpha1.AgentRunBrokerPreparationOperation
}

type placeholderFilesResponse struct {
	OK      bool                      `json:"ok"`
	Files   []preparedPlaceholderFile `json:"files"`
	Error   string                    `json:"error"`
	Message string                    `json:"message"`
}

type providerIdentityResponse struct {
	OK      bool   `json:"ok"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

type podCredentialProjectionState struct {
	AutomountServiceAccountToken *bool                         `json:"automountServiceAccountToken,omitempty"`
	ServiceAccountName           string                        `json:"serviceAccountName,omitempty"`
	SecurityContext              *corev1.PodSecurityContext    `json:"securityContext,omitempty"`
	Volumes                      []podCredentialVolumeState    `json:"volumes,omitempty"`
	InitContainers               []podCredentialContainerState `json:"initContainers,omitempty"`
	Containers                   []podCredentialContainerState `json:"containers,omitempty"`
}

type podCredentialContainerState struct {
	Name            string                          `json:"name"`
	Env             []podCredentialEnvState         `json:"env,omitempty"`
	VolumeMounts    []podCredentialVolumeMountState `json:"volumeMounts,omitempty"`
	SecurityContext *corev1.SecurityContext         `json:"securityContext,omitempty"`
	RestartPolicy   *corev1.ContainerRestartPolicy  `json:"restartPolicy,omitempty"`
}

type podCredentialEnvState struct {
	Name       string `json:"name"`
	SecretName string `json:"secretName,omitempty"`
	SecretKey  string `json:"secretKey,omitempty"`
	Optional   *bool  `json:"optional,omitempty"`
}

type podCredentialVolumeState struct {
	Name      string                        `json:"name"`
	Secret    *corev1.SecretVolumeSource    `json:"secret,omitempty"`
	Projected *corev1.ProjectedVolumeSource `json:"projected,omitempty"`
}

type podCredentialVolumeMountState struct {
	Name        string `json:"name"`
	MountPath   string `json:"mountPath"`
	ReadOnly    bool   `json:"readOnly,omitempty"`
	SubPath     string `json:"subPath,omitempty"`
	SubPathExpr string `json:"subPathExpr,omitempty"`
}

const defaultProjectedVolumeMode int32 = 420

// Reconcile renders the AgentRun config, creates the agent Pod, and syncs basic Pod-phase status.
func (r *AgentRunReconciler) reconcileAgentConfigMap(
	ctx context.Context,
	agentRun *nvtv1alpha1.AgentRun,
	preparedFiles []preparedPlaceholderFile,
	preparedMetadata *preparedProviderMetadata,
) error {
	desired, err := DesiredAgentConfigMap(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	if AgentRunLiteralZeroSecret(agentRun) {
		if len(preparedFiles) > 0 {
			encodedPreparedFiles, marshalErr := json.Marshal(preparedFiles)
			if marshalErr != nil {
				return fmt.Errorf("marshal prepared placeholder files: %w", marshalErr)
			}
			if desired.Data == nil {
				desired.Data = map[string]string{}
			}
			desired.Data[preparedPlaceholderFilesKey] = string(encodedPreparedFiles)
		}
		if desired.Annotations == nil {
			desired.Annotations = map[string]string{}
		}
		desired.Annotations[agentConfigPlaceholderCacheAnnotation] = agentConfigPlaceholderCacheKey(agentRun)
		rendered, renderErr := InjectPreparedPlaceholderFiles(desired.Data[agentConfigKey], preparedFiles)
		if renderErr != nil {
			return renderErr
		}
		desired.Data[agentConfigKey] = rendered
	}
	if preparedMetadata != nil {
		encoded, marshalErr := json.Marshal(preparedMetadata)
		if marshalErr != nil {
			return fmt.Errorf("marshal prepared provider metadata: %w", marshalErr)
		}
		if desired.Data == nil {
			desired.Data = map[string]string{}
		}
		if desired.Annotations == nil {
			desired.Annotations = map[string]string{}
		}
		desired.Data[preparedProviderMetadataKey] = string(encoded)
		desired.Annotations[providerMetadataCacheAnnotation] = providerMetadataCacheKey(agentRun)
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		configMap.Labels = desired.Labels
		configMap.Annotations = desired.Annotations
		configMap.OwnerReferences = desired.OwnerReferences
		configMap.Data = desired.Data
		return nil
	})
	if err != nil {
		return fmt.Errorf("reconcile AgentRun config ConfigMap: %w", err)
	}

	return nil
}

func (r *AgentRunReconciler) preparePlaceholderFiles(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) ([]preparedPlaceholderFile, error) {
	providers := []string{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantPlaceholderFile {
			providers = append(providers, grant.Provider)
		}
	}
	if len(providers) == 0 {
		return nil, nil
	}
	cacheKey := agentConfigPlaceholderCacheKey(agentRun)
	existing := &corev1.ConfigMap{}
	configKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: AgentConfigMapName(agentRun.Name)}
	if err := r.Get(ctx, configKey, existing); err == nil {
		if metav1.IsControlledBy(existing, agentRun) && existing.Annotations[agentConfigPlaceholderCacheAnnotation] == cacheKey {
			if raw := existing.Data[preparedPlaceholderFilesKey]; strings.TrimSpace(raw) != "" {
				files, loadErr := loadPreparedPlaceholderFiles(raw)
				if loadErr != nil {
					return nil, fmt.Errorf("load cached prepared placeholder files from ConfigMap %s/%s: %w", existing.Namespace, existing.Name, loadErr)
				}
				if len(files) == 0 {
					return nil, fmt.Errorf("cached AgentRun config ConfigMap %s/%s contains no prepared placeholder files", existing.Namespace, existing.Name)
				}
				return files, nil
			}
		}
	} else if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("get AgentRun config ConfigMap for placeholder cache: %w", err)
	}
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: BrokerTokenSecretName(agentRun.Name)}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return nil, fmt.Errorf("get control-plane broker token for placeholder preparation: %w", err)
	}
	token := secret.Data[brokerTokenKey]
	if len(token) == 0 {
		return nil, fmt.Errorf("control-plane broker token Secret %s/%s is missing %s", secretKey.Namespace, secretKey.Name, brokerTokenKey)
	}
	httpClient, err := r.brokerPreparationHTTPClient(ctx, agentRun.Namespace)
	if err != nil {
		return nil, err
	}
	prepCtx, cancel := context.WithTimeout(ctx, placeholderPreparationTimeout())
	defer cancel()
	prepared := []preparedPlaceholderFile{}
	seenPaths := map[string]string{}
	for _, provider := range providers {
		payload, err := json.Marshal(map[string]string{"provider": provider})
		if err != nil {
			return nil, fmt.Errorf("marshal placeholder request for %s: %w", provider, err)
		}
		status, responseBytes, err := brokerPreparationRequest(prepCtx, httpClient, strings.TrimRight(BrokerURL(), "/")+"/v1/placeholder-files", string(token), payload, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("prepare inert placeholder files for %s: broker request failed", provider)
		}
		var decoded placeholderFilesResponse
		decodeErr := json.Unmarshal(responseBytes, &decoded)
		if decodeErr != nil {
			return nil, fmt.Errorf("decode placeholder response for %s: %w", provider, decodeErr)
		}
		if status < 200 || status >= 300 || !decoded.OK {
			reason := decoded.Error
			if decoded.Message != "" {
				reason = decoded.Message
			}
			return nil, fmt.Errorf("broker denied inert placeholder preparation for %s: %s", provider, reason)
		}
		if len(decoded.Files) == 0 {
			return nil, fmt.Errorf("broker returned no inert placeholder files for %s", provider)
		}
		for _, file := range decoded.Files {
			if err := validatePreparedPlaceholderFile(file); err != nil {
				return nil, fmt.Errorf("invalid inert placeholder file for %s: %w", provider, err)
			}
			if prior, exists := seenPaths[file.Path]; exists {
				return nil, fmt.Errorf("placeholder providers %s and %s both target %s", prior, provider, file.Path)
			}
			seenPaths[file.Path] = provider
			prepared = append(prepared, file)
		}
	}
	return prepared, nil
}

func (r *AgentRunReconciler) prepareProviderMetadata(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (*preparedProviderMetadata, error) {
	requested, err := requestedProviderPreparations(agentRun)
	if err != nil || len(requested) == 0 {
		return nil, err
	}
	cacheKey := providerMetadataCacheKey(agentRun)
	existing := &corev1.ConfigMap{}
	configKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: AgentConfigMapName(agentRun.Name)}
	if err := r.Get(ctx, configKey, existing); err == nil {
		if metav1.IsControlledBy(existing, agentRun) && existing.Annotations[providerMetadataCacheAnnotation] == cacheKey {
			if raw := existing.Data[preparedProviderMetadataKey]; strings.TrimSpace(raw) != "" {
				prepared, loadErr := loadPreparedProviderMetadata(raw, requested)
				if loadErr != nil {
					return nil, fmt.Errorf("load cached prepared provider metadata from ConfigMap %s/%s: %w", existing.Namespace, existing.Name, loadErr)
				}
				return prepared, nil
			}
		}
	} else if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("get AgentRun config ConfigMap for provider identity cache: %w", err)
	}

	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: BrokerTokenSecretName(agentRun.Name)}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return nil, fmt.Errorf("get control-plane broker token for provider identity preparation: %w", err)
	}
	token := secret.Data[brokerTokenKey]
	if len(token) == 0 {
		return nil, fmt.Errorf("control-plane broker token Secret %s/%s is missing %s", secretKey.Namespace, secretKey.Name, brokerTokenKey)
	}
	httpClient, err := r.brokerPreparationHTTPClient(ctx, agentRun.Namespace)
	if err != nil {
		return nil, err
	}
	prepCtx, cancel := context.WithTimeout(ctx, placeholderPreparationTimeout())
	defer cancel()
	prepared := &preparedProviderMetadata{Version: 1, Providers: map[string]preparedProviderOperations{}}
	for _, preparation := range requested {
		payload, marshalErr := json.Marshal(map[string]string{"provider": preparation.Provider})
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal provider metadata preparation request: %w", marshalErr)
		}
		status, responseBytes, requestErr := brokerPreparationRequest(prepCtx, httpClient, strings.TrimRight(BrokerURL(), "/")+"/v1/identity", string(token), payload, 64<<10)
		if requestErr != nil {
			return nil, fmt.Errorf("prepare provider commit identity: broker request failed")
		}
		var decoded providerIdentityResponse
		if len(responseBytes) > 64<<10 || json.Unmarshal(responseBytes, &decoded) != nil {
			return nil, fmt.Errorf("prepare provider commit identity: broker returned an invalid response")
		}
		if status < 200 || status >= 300 || !decoded.OK {
			return nil, fmt.Errorf("prepare provider commit identity: broker denied request (%s)", safeBrokerErrorReason(decoded.Error))
		}
		identity := preparedProviderIdentity{Name: decoded.Name, Email: decoded.Email}
		if err := validatePreparedProviderIdentity(identity); err != nil {
			return nil, fmt.Errorf("prepare provider commit identity: broker returned invalid metadata")
		}
		operations := prepared.Providers[preparation.Provider]
		operations.Identity = &identity
		prepared.Providers[preparation.Provider] = operations
	}
	return prepared, nil
}

func requestedProviderPreparations(agentRun *nvtv1alpha1.AgentRun) ([]requestedProviderPreparation, error) {
	requested := []requestedProviderPreparation{}
	seen := map[string]bool{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		for _, preparation := range grant.Preparations {
			if preparation.Operation != nvtv1alpha1.AgentRunBrokerPreparationIdentity {
				return nil, fmt.Errorf("broker grant %s preparation operation must be identity, got %q", grant.Provider, preparation.Operation)
			}
			key := grant.Provider + "\x00" + string(preparation.Operation)
			if seen[key] {
				return nil, fmt.Errorf("broker grant preparation %s/%s is duplicated", grant.Provider, preparation.Operation)
			}
			seen[key] = true
			requested = append(requested, requestedProviderPreparation{Provider: grant.Provider, Operation: preparation.Operation})
		}
	}
	sort.Slice(requested, func(i, j int) bool {
		if requested[i].Provider == requested[j].Provider {
			return requested[i].Operation < requested[j].Operation
		}
		return requested[i].Provider < requested[j].Provider
	})
	return requested, nil
}

func validatePreparedProviderIdentity(identity preparedProviderIdentity) error {
	for _, value := range []string{identity.Name, identity.Email} {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
			return fmt.Errorf("prepared provider identity contains an empty, unnormalized, or oversized field")
		}
		for _, character := range value {
			if character < 32 || character == 127 {
				return fmt.Errorf("prepared provider identity contains a control character")
			}
		}
	}
	return nil
}

func loadPreparedProviderMetadata(raw string, requested []requestedProviderPreparation) (*preparedProviderMetadata, error) {
	prepared := &preparedProviderMetadata{}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(prepared); err != nil {
		return nil, fmt.Errorf("decode prepared provider metadata JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("decode prepared provider metadata JSON: trailing data")
	}
	if prepared.Version != 1 || len(prepared.Providers) != len(requested) {
		return nil, fmt.Errorf("prepared provider metadata cache does not match requested preparations")
	}
	for _, request := range requested {
		operations, exists := prepared.Providers[request.Provider]
		if !exists || request.Operation != nvtv1alpha1.AgentRunBrokerPreparationIdentity || operations.Identity == nil {
			return nil, fmt.Errorf("prepared provider metadata cache does not match requested preparations")
		}
		if err := validatePreparedProviderIdentity(*operations.Identity); err != nil {
			return nil, err
		}
	}
	return prepared, nil
}

func providerMetadataCacheKey(agentRun *nvtv1alpha1.AgentRun) string {
	grants := []nvtv1alpha1.AgentRunBrokerGrant{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		grants = append(grants, *grant.DeepCopy())
	}
	rendered, err := json.Marshal(grants)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(rendered)
	return hex.EncodeToString(digest[:])
}

func safeBrokerErrorReason(value string) string {
	if value == "" || len(value) > 64 {
		return "provider-identity-unavailable"
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("._-", character)) {
			return "provider-identity-unavailable"
		}
	}
	return value
}

func agentConfigPlaceholderCacheKey(agentRun *nvtv1alpha1.AgentRun) string {
	payload := map[string]any{
		"agent-config": string(agentRun.Spec.Agent.Config.Raw),
		"egress": map[string]any{
			"mode":        string(AgentRunEgressMode(agentRun)),
			"enforcement": agentRun.Spec.EgressEnforcement,
			"transport":   string(AgentRunEgressTransport(agentRun)),
		},
		"grants": normalizePlaceholderCacheGrants(agentRun),
	}
	rendered, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(rendered)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func placeholderPreparationTimeout() time.Duration {
	return 5 * time.Second
}

var brokerPreparationRetryInterval = 100 * time.Millisecond

// brokerPreparationRequest tolerates only the short projection race where the
// broker has not observed its freshly-written agent policy yet. Permanent
// authorization failures are returned immediately; the bearer token and body
// are never included in errors.
func brokerPreparationRequest(ctx context.Context, client *http.Client, url, token string, payload []byte, maxBody int64) (int, []byte, error) {
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return 0, nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
		response.Body.Close()
		if readErr != nil {
			return response.StatusCode, nil, readErr
		}
		if response.StatusCode != http.StatusUnauthorized {
			return response.StatusCode, body, nil
		}
		var reason struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &reason) != nil || reason.Error != "unauthorized" || reason.Message != "invalid broker bearer token" {
			return response.StatusCode, body, nil
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(brokerPreparationRetryInterval):
		}
	}
}

func normalizePlaceholderCacheGrants(agentRun *nvtv1alpha1.AgentRun) []map[string]any {
	normalized := make([]map[string]any, 0, len(AgentRunBrokerGrants(agentRun.Spec.Broker)))
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		normalized = append(normalized, map[string]any{
			"provider":        grant.Provider,
			"materialization": string(AgentRunGrantMaterialization(grant)),
			"git":             grant.Git,
			"egress-hosts":    append([]string(nil), grant.EgressHosts...),
		})
	}
	return normalized
}

func loadPreparedPlaceholderFiles(raw string) ([]preparedPlaceholderFile, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	files := []preparedPlaceholderFile{}
	if err := json.Unmarshal([]byte(raw), &files); err != nil {
		return nil, fmt.Errorf("decode prepared placeholder files JSON: %w", err)
	}
	for _, file := range files {
		if err := validatePreparedPlaceholderFile(file); err != nil {
			return nil, err
		}
	}
	return files, nil
}

func (r *AgentRunReconciler) ensureImmutablePodSecurityState(ctx context.Context, agentRun *nvtv1alpha1.AgentRun, existingPod *corev1.Pod) error {
	desiredPod, err := desiredAgentPodForSecurityProjection(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	desiredState, err := podCredentialProjectionSignature(agentRun, desiredPod)
	if err != nil {
		return err
	}
	actualState, err := podCredentialProjectionSignature(agentRun, existingPod)
	if err != nil {
		reason := err.Error()
		if setErr := r.setAgentRunFailed(ctx, agentRun, reason); setErr != nil {
			return setErr
		}
		if delErr := r.deleteOwnedPodByName(ctx, agentRun, AgentPodName(agentRun.Name), reason); delErr != nil {
			return delErr
		}
		if delErr := r.deleteOwnedPodByName(ctx, agentRun, EgressdPodName(agentRun.Name), reason+" (egressd)"); delErr != nil {
			return delErr
		}
		return fmt.Errorf("%s", reason)
	}
	if desiredState != actualState {
		reason := "security-sensitive AgentRun fields changed after Pod creation"
		if err := r.setAgentRunFailed(ctx, agentRun, reason); err != nil {
			return err
		}
		if err := r.deleteOwnedPodByName(ctx, agentRun, AgentPodName(agentRun.Name), reason); err != nil {
			return err
		}
		if err := r.deleteOwnedPodByName(ctx, agentRun, EgressdPodName(agentRun.Name), reason+" (egressd)"); err != nil {
			return err
		}
		return fmt.Errorf("security-sensitive AgentRun fields changed after Pod creation")
	}
	if existingPod.Annotations != nil && existingPod.Annotations[agentPodSecurityStateAnnotation] == desiredState {
		return nil
	}
	updated := existingPod.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	updated.Annotations[agentPodSecurityStateAnnotation] = desiredState
	if err := r.Update(ctx, updated); err != nil {
		return fmt.Errorf("patch AgentRun Pod security annotation: %w", err)
	}
	return nil
}

func agentRunMaxConcurrentReconciles() int {
	return 2
}

func podCredentialProjectionSignature(agentRun *nvtv1alpha1.AgentRun, pod *corev1.Pod) (string, error) {
	state := podCredentialProjectionState{
		AutomountServiceAccountToken: pod.Spec.AutomountServiceAccountToken,
		ServiceAccountName:           canonicalServiceAccountName(pod.Spec.ServiceAccountName),
		SecurityContext:              pod.Spec.SecurityContext,
		Volumes:                      make([]podCredentialVolumeState, 0, len(pod.Spec.Volumes)),
		InitContainers:               make([]podCredentialContainerState, 0, len(pod.Spec.InitContainers)),
		Containers:                   make([]podCredentialContainerState, 0, len(pod.Spec.Containers)),
	}
	if emptyPodSecurityContext(state.SecurityContext) {
		state.SecurityContext = nil
	}
	credentialVolumes := map[string]bool{}
	for _, volume := range pod.Spec.Volumes {
		switch {
		case volume.Name == brokerCAVolumeName && volume.Secret != nil:
			continue
		case volume.Secret != nil:
			credentialVolumes[volume.Name] = true
			state.Volumes = append(state.Volumes, podCredentialVolumeState{Name: volume.Name, Secret: normalizeSecretVolumeSource(volume.Secret)})
		case volume.Projected != nil:
			if projectedVolumeHasServiceAccountToken(volume.Projected) && AgentRunLiteralZeroSecret(agentRun) {
				return "", fmt.Errorf("literal-zero-secret AgentRun Pod must not project a service-account token volume")
			}
			projected := normalizeProjectedVolumeSource(volume.Projected)
			if projected == nil {
				continue
			}
			credentialVolumes[volume.Name] = true
			state.Volumes = append(state.Volumes, podCredentialVolumeState{Name: volume.Name, Projected: projected})
		}
	}
	for _, container := range pod.Spec.InitContainers {
		state.InitContainers = append(state.InitContainers, podCredentialContainerState{
			Name:            container.Name,
			Env:             credentialEnvState(container.Env),
			VolumeMounts:    credentialVolumeMountState(container.VolumeMounts, credentialVolumes),
			SecurityContext: normalizeSecurityContext(container.SecurityContext),
			RestartPolicy:   container.RestartPolicy,
		})
	}
	for _, container := range pod.Spec.Containers {
		state.Containers = append(state.Containers, podCredentialContainerState{
			Name:            container.Name,
			Env:             credentialEnvState(container.Env),
			VolumeMounts:    credentialVolumeMountState(container.VolumeMounts, credentialVolumes),
			SecurityContext: normalizeSecurityContext(container.SecurityContext),
		})
	}
	rendered, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("marshal pod credential projection signature: %w", err)
	}
	sum := sha256.Sum256(rendered)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalServiceAccountName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "default"
	}
	return name
}

func emptyPodSecurityContext(sc *corev1.PodSecurityContext) bool {
	if sc == nil {
		return true
	}
	zero := corev1.PodSecurityContext{}
	return reflect.DeepEqual(*sc, zero)
}

func normalizeSecurityContext(sc *corev1.SecurityContext) *corev1.SecurityContext {
	if sc == nil {
		return nil
	}
	if reflect.DeepEqual(*sc, corev1.SecurityContext{}) {
		return nil
	}
	copy := sc.DeepCopy()
	return copy
}

func normalizeSecretVolumeSource(src *corev1.SecretVolumeSource) *corev1.SecretVolumeSource {
	if src == nil {
		return nil
	}
	copy := src.DeepCopy()
	if copy.DefaultMode == nil {
		copy.DefaultMode = ptrTo(defaultProjectedVolumeMode)
	}
	return copy
}

func normalizeProjectedVolumeSource(src *corev1.ProjectedVolumeSource) *corev1.ProjectedVolumeSource {
	if src == nil {
		return nil
	}
	copy := src.DeepCopy()
	copy.Sources = normalizeProjectedVolumeSources(copy.Sources)
	if len(copy.Sources) == 0 {
		return nil
	}
	if copy.DefaultMode == nil {
		copy.DefaultMode = ptrTo(defaultProjectedVolumeMode)
	}
	return copy
}

func normalizeProjectedVolumeSources(sources []corev1.VolumeProjection) []corev1.VolumeProjection {
	normalized := make([]corev1.VolumeProjection, 0, len(sources))
	for _, source := range sources {
		switch {
		case source.Secret != nil:
			copy := *source.Secret
			normalized = append(normalized, corev1.VolumeProjection{Secret: &copy})
		}
	}
	return normalized
}

func projectedVolumeHasServiceAccountToken(src *corev1.ProjectedVolumeSource) bool {
	if src == nil {
		return false
	}
	for _, source := range src.Sources {
		if source.ServiceAccountToken != nil {
			return true
		}
	}
	return false
}

func credentialEnvState(env []corev1.EnvVar) []podCredentialEnvState {
	state := []podCredentialEnvState{}
	for _, variable := range env {
		if variable.ValueFrom == nil || variable.ValueFrom.SecretKeyRef == nil {
			continue
		}
		ref := variable.ValueFrom.SecretKeyRef
		state = append(state, podCredentialEnvState{
			Name:       variable.Name,
			SecretName: ref.Name,
			SecretKey:  ref.Key,
			Optional:   ref.Optional,
		})
	}
	return state
}

func credentialVolumeMountState(volumeMounts []corev1.VolumeMount, credentialVolumes map[string]bool) []podCredentialVolumeMountState {
	state := []podCredentialVolumeMountState{}
	for _, mount := range volumeMounts {
		if !credentialVolumes[mount.Name] {
			continue
		}
		state = append(state, podCredentialVolumeMountState{
			Name:        mount.Name,
			MountPath:   mount.MountPath,
			ReadOnly:    mount.ReadOnly,
			SubPath:     mount.SubPath,
			SubPathExpr: mount.SubPathExpr,
		})
	}
	return state
}

func (r *AgentRunReconciler) brokerPreparationHTTPClient(ctx context.Context, namespace string) (*http.Client, error) {
	if r.BrokerHTTPClient != nil {
		return r.BrokerHTTPClient, nil
	}
	client := &http.Client{}
	if !brokerIsTLS() {
		return client, nil
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, clientKeyFor(namespace, BrokerCASecretName()), secret); err != nil {
		return nil, fmt.Errorf("get broker CA Secret for operator preparation: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(secret.Data[brokerCAKey]) {
		return nil, fmt.Errorf("broker CA Secret %s/%s has no valid %s", namespace, BrokerCASecretName(), brokerCAKey)
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	return client, nil
}

func clientKeyFor(namespace, name string) client.ObjectKey {
	return client.ObjectKey{Namespace: namespace, Name: name}
}

func validatePreparedPlaceholderFile(file preparedPlaceholderFile) error {
	if file.Path == "" || strings.HasPrefix(file.Path, "/") || strings.HasPrefix(file.Path, "\\") {
		return fmt.Errorf("path %q must be relative", file.Path)
	}
	for _, segment := range strings.Split(strings.ReplaceAll(file.Path, "\\", "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("path %q contains traversal", file.Path)
		}
	}
	if file.Mode == "" {
		file.Mode = "0600"
	}
	if len(file.Mode) != 4 || strings.Trim(file.Mode, "01234567") != "" {
		return fmt.Errorf("mode %q is not four-digit octal", file.Mode)
	}
	if !strings.Contains(file.Content, "NVT-PLACEHOLDER-NOT-A-KEY") {
		return fmt.Errorf("content for %s does not contain the inert placeholder", file.Path)
	}
	return nil
}

func InjectPreparedPlaceholderFiles(rendered string, files []preparedPlaceholderFile) (string, error) {
	config := map[string]any{}
	if err := yaml.Unmarshal([]byte(rendered), &config); err != nil {
		return "", fmt.Errorf("inject prepared placeholder files: %w", err)
	}
	if len(files) > 0 {
		preseed, _ := config["preseed"].(map[string]any)
		if preseed == nil {
			preseed = map[string]any{}
		}
		entries, _ := preseed["files"].([]any)
		for _, file := range files {
			mode := file.Mode
			if mode == "" {
				mode = "0600"
			}
			entries = append(entries, map[string]any{
				"path": "$HOME/" + file.Path, "content": file.Content, "mode": mode, "overwrite": true,
			})
		}
		preseed["files"] = entries
		config["preseed"] = preseed
	}
	output, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("render prepared placeholder files: %w", err)
	}
	return string(output), nil
}
