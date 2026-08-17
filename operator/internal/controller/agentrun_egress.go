package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

func AgentRunEgressEnforced(agentRun *nvtv1alpha1.AgentRun) bool {
	return agentRun.Spec.EgressEnforcement && AgentRunEgressMode(agentRun) == nvtv1alpha1.AgentRunEgressMediated
}

// AgentRunEgressForwardProxy reports whether the run uses forward-proxy mode.
// Validation guarantees this implies mediated + enforced egress.
func AgentRunEgressForwardProxy(agentRun *nvtv1alpha1.AgentRun) bool {
	transport := AgentRunEgressTransport(agentRun)
	return (transport == nvtv1alpha1.AgentRunEgressTransportForwardProxy || transport == nvtv1alpha1.AgentRunEgressTransportTransparent) && AgentRunEgressEnforced(agentRun)
}

func AgentRunEgressTransport(agentRun *nvtv1alpha1.AgentRun) nvtv1alpha1.AgentRunEgressTransport {
	if agentRun.Spec.EgressTransport != "" {
		return agentRun.Spec.EgressTransport
	}
	return nvtv1alpha1.AgentRunEgressTransportRedirect
}

func AgentRunEgressTransparent(agentRun *nvtv1alpha1.AgentRun) bool {
	return AgentRunEgressEnforced(agentRun) && AgentRunEgressTransport(agentRun) == nvtv1alpha1.AgentRunEgressTransportTransparent
}

// forwardProxyInjectHosts returns the (host, capability) pairs egressd MITMs
// for a forward-proxy run: every egressHost of every injection-capable grant.
type forwardProxyInject struct {
	Host                  string
	Capability            string
	Upstream              string
	AllowInsecureUpstream bool
	MaxRequests           int
	RequireCapabilityHint bool
}

func forwardProxyInjects(agentRun *nvtv1alpha1.AgentRun) []forwardProxyInject {
	hostCounts := map[string]int{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		materialization := AgentRunGrantMaterialization(grant)
		if materialization != nvtv1alpha1.AgentRunGrantHeaderInject && materialization != nvtv1alpha1.AgentRunGrantPlaceholderFile {
			continue
		}
		for _, upstream := range grant.EgressHosts {
			host := upstream
			if h, _, err := net.SplitHostPort(upstream); err == nil {
				host = h
			}
			hostCounts[strings.ToLower(host)]++
		}
	}
	injects := []forwardProxyInject{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		materialization := AgentRunGrantMaterialization(grant)
		if materialization != nvtv1alpha1.AgentRunGrantHeaderInject && materialization != nvtv1alpha1.AgentRunGrantPlaceholderFile {
			continue
		}
		for _, upstream := range grant.EgressHosts {
			host := upstream
			if h, _, err := net.SplitHostPort(upstream); err == nil {
				host = h
			}
			maxRequests := 0
			if grant.Quota != nil {
				maxRequests = grant.Quota.Requests
			}
			injects = append(injects, forwardProxyInject{
				Host:                  host,
				Capability:            grant.Provider,
				Upstream:              upstream,
				AllowInsecureUpstream: grant.AllowInsecureUpstream,
				MaxRequests:           maxRequests,
				RequireCapabilityHint: grant.Git || hostCounts[strings.ToLower(host)] > 1,
			})
		}
	}
	return injects
}

// forwardProxyUpstreamHosts is the set of MITM leaf names the CA must permit.
func forwardProxyUpstreamHosts(agentRun *nvtv1alpha1.AgentRun) []string {
	if !AgentRunEgressForwardProxy(agentRun) {
		return nil
	}
	seen := map[string]bool{}
	hosts := []string{}
	for _, inject := range forwardProxyInjects(agentRun) {
		if !seen[inject.Host] {
			seen[inject.Host] = true
			hosts = append(hosts, inject.Host)
		}
	}
	return hosts
}

// forwardProxyEnv points the agent's proxy env at egressd and computes NO_PROXY.
// NO_PROXY is operator-rendered, never hand-authored, so a missed entry can't
// silently route infra (broker, callback, DNS) through the MITM.
func forwardProxyEnv(agentRun *nvtv1alpha1.AgentRun) []corev1.EnvVar {
	proxyURL := fmt.Sprintf("http://%s:%d", EgressdServiceName(agentRun.Name), egressForwardProxyPort)
	if AgentRunEgressTransparent(agentRun) {
		proxyURL = fmt.Sprintf("http://127.0.0.1:%d", capturedExplicitPort)
	}
	noProxy := forwardProxyNoProxy(agentRun)
	proxyNames := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"}
	if AgentRunEgressTransparent(agentRun) {
		// Plain HTTP must take the normal TCP path so iptables redirects it to
		// captured's transparent listener. egressd's explicit listener is
		// CONNECT-only; HTTPS keeps the explicit path and provider hints.
		proxyNames = []string{"HTTPS_PROXY", "https_proxy"}
	}
	env := []corev1.EnvVar{}
	for _, name := range proxyNames {
		env = append(env, corev1.EnvVar{Name: name, Value: proxyURL})
	}
	if AgentRunEgressTransparent(agentRun) {
		for _, name := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
			env = append(env, corev1.EnvVar{Name: name, Value: ""})
		}
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		env = append(env, corev1.EnvVar{Name: name, Value: noProxy})
	}
	return env
}

func forwardProxyNoProxy(agentRun *nvtv1alpha1.AgentRun) string {
	hosts := []string{
		"localhost", "127.0.0.1", "::1",
		"kubernetes.default.svc",
		".svc", ".svc.cluster.local", ".cluster.local",
		EgressdServiceName(agentRun.Name),
		"nvt-operator",
	}
	if parsed, err := url.Parse(BrokerURL()); err == nil && parsed.Hostname() != "" {
		hosts = append(hosts, parsed.Hostname())
	}
	return strings.Join(hosts, ",")
}

// EgressdPodName returns the own-Pod egressd Pod name for an AgentRun.
func EgressdPodName(agentRunName string) string {
	return agentRunName + "-egressd"
}

// EgressdServiceName returns the per-run egressd Service name.
func EgressdServiceName(agentRunName string) string {
	return agentRunName + "-egressd"
}

// EgressCAConfigMapName returns the operator-published CA ConfigMap name.
func EgressCAConfigMapName(agentRunName string) string {
	return agentRunName + "-egress-ca"
}

// EgressCASecretName returns the private per-run CA Secret mounted only into egressd.
func EgressCASecretName(agentRunName string) string {
	return agentRunName + "-egress-ca-keypair"
}

// enforcementLabels extends the run labels with the pairing selectors the
// NetworkPolicies match on.
func enforcementLabels(agentRunName, role string) map[string]string {
	labels := agentRunLabels(agentRunName)
	labels[roleLabelKey] = role
	return labels
}

// egressdLeafDNSNames are the synthetic Service names the per-agent CA may
// mint leafs for in own-Pod mode. Never upstream names — egressd refuses the
// overlap at config load.
func egressdLeafDNSNames(agentRun *nvtv1alpha1.AgentRun) []string {
	service := EgressdServiceName(agentRun.Name)
	return []string{
		service,
		service + "." + agentRun.Namespace,
		service + "." + agentRun.Namespace + ".svc",
	}
}

func headerInjectGrants(agentRun *nvtv1alpha1.AgentRun) []nvtv1alpha1.AgentRunBrokerGrant {
	grants := []nvtv1alpha1.AgentRunBrokerGrant{}
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if AgentRunGrantMaterialization(grant) == nvtv1alpha1.AgentRunGrantHeaderInject {
			grants = append(grants, grant)
		}
	}
	return grants
}

func (r *AgentRunReconciler) setRunCondition(agentRun *nvtv1alpha1.AgentRun, conditionType string, status metav1.ConditionStatus, reason, message string) bool {
	return meta.SetStatusCondition(&agentRun.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: agentRun.Generation,
	})
}

func enforcementAgentPodGatesHold(agentRun *nvtv1alpha1.AgentRun) bool {
	return meta.IsStatusConditionTrue(agentRun.Status.Conditions, ConditionBrokerPolicyReady) &&
		meta.IsStatusConditionTrue(agentRun.Status.Conditions, ConditionEgressCAPublished)
}

// reconcileEnforcementGates advances the own-Pod machine past egressd
// creation: wait for egressd Ready, then publish the validated Secret-backed
// CA. Returns proceed=true only when the agent Pod may be created this pass.
func (r *AgentRunReconciler) reconcileEnforcementGates(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (ctrl.Result, bool, bool, error) {
	changed := false
	egressdPod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}
	if err := r.Get(ctx, key, egressdPod); err != nil {
		return ctrl.Result{}, false, changed, fmt.Errorf("get egressd Pod: %w", err)
	}
	if !isPodReady(egressdPod) {
		changed = r.setRunCondition(agentRun, ConditionEgressdReady, metav1.ConditionFalse, "EgressdNotReady", "waiting for egressd Pod readiness (CA endpoint /healthz)") || changed
		return ctrl.Result{RequeueAfter: egressdReadyRequeue}, false, changed, nil
	}
	changed = r.setRunCondition(agentRun, ConditionEgressdReady, metav1.ConditionTrue, "EgressdReady", "egressd Pod is ready") || changed

	published, err := r.publishEgressCAConfigMap(ctx, agentRun)
	if err != nil {
		changed = r.setRunCondition(agentRun, ConditionEgressCAPublished, metav1.ConditionFalse, "CAPublishFailed", err.Error()) || changed
		return ctrl.Result{}, false, changed, err
	}
	if !published {
		return ctrl.Result{RequeueAfter: egressdReadyRequeue}, false, changed, nil
	}
	changed = r.setRunCondition(agentRun, ConditionEgressCAPublished, metav1.ConditionTrue, "EgressCAPublished", "CA certificate published to the per-run ConfigMap") || changed
	return ctrl.Result{}, true, changed, nil
}

func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

// publishEgressCAConfigMap publishes ca.crt from the operator-owned per-run CA
// Secret into the ConfigMap mounted by the agent. The private key stays only in
// the Secret mounted into egressd.
func (r *AgentRunReconciler) publishEgressCAConfigMap(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) (bool, error) {
	secret := &corev1.Secret{}
	secretKey := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressCASecretName(agentRun.Name)}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return false, fmt.Errorf("get egress CA Secret: %w", err)
	}
	if !metav1.IsControlledBy(secret, agentRun) {
		return false, fmt.Errorf("egress CA Secret %s/%s exists but is not controlled by AgentRun %s", secret.Namespace, secret.Name, agentRun.Name)
	}
	certPEM := secret.Data[egressCACertKey]
	if err := validateCAKeyPairPEM(certPEM, secret.Data[egressCAKeyKey]); err != nil {
		return false, fmt.Errorf("egress CA Secret contains invalid keypair: %w", err)
	}
	configMap := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressCAConfigMapName(agentRun.Name)}
	err := r.Get(ctx, key, configMap)
	if err == nil {
		if !metav1.IsControlledBy(configMap, agentRun) {
			return false, fmt.Errorf("egress CA ConfigMap %s/%s exists but is not controlled by AgentRun %s", key.Namespace, key.Name, agentRun.Name)
		}
		if configMap.Data[egressCACertKey] == string(certPEM) &&
			reflect.DeepEqual(configMap.Labels, agentRunLabels(agentRun.Name)) {
			return true, nil
		}
		configMap.Labels = agentRunLabels(agentRun.Name)
		configMap.Data = map[string]string{egressCACertKey: string(certPEM)}
		if err := r.Update(ctx, configMap); err != nil {
			return false, fmt.Errorf("update egress CA ConfigMap: %w", err)
		}
		return true, nil
	}
	if !errors.IsNotFound(err) {
		return false, fmt.Errorf("get egress CA ConfigMap: %w", err)
	}
	desired, err := DesiredEgressCAConfigMap(agentRun, r.Scheme, certPEM)
	if err != nil {
		return false, err
	}
	if err := r.Create(ctx, desired); err != nil {
		return false, fmt.Errorf("create egress CA ConfigMap: %w", err)
	}
	return true, nil
}

// validateCACertificatePEM accepts only certificate PEM blocks: anything
// else — a private key above all — must never reach the published ConfigMap.
func validateCACertificatePEM(data []byte) error {
	_, err := parseCACertificatesPEM(data)
	return err
}

func parseCACertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	rest := data
	certs := []*x509.Certificate{}
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate PEM block found")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("trailing non-PEM data after certificates")
	}
	return certs, nil
}

func validateCAKeyPairPEM(certPEM, keyPEM []byte) error {
	certs, err := parseCACertificatesPEM(certPEM)
	if err != nil {
		return err
	}
	if len(keyPEM) == 0 {
		return fmt.Errorf("missing key %s", egressCAKeyKey)
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("no EC private key PEM block found")
	}
	if block.Type != "EC PRIVATE KEY" {
		return fmt.Errorf("unexpected PEM block %q", block.Type)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return fmt.Errorf("trailing non-PEM data after private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	certKey, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is %T, want ECDSA", certs[0].PublicKey)
	}
	if certKey.Curve != key.Curve || certKey.X.Cmp(key.X) != 0 || certKey.Y.Cmp(key.Y) != 0 {
		return fmt.Errorf("%s does not match %s", egressCAKeyKey, egressCACertKey)
	}
	return nil
}

// DesiredEgressCAConfigMap wraps the public CA certificate for the agent Pod
// to mount read-only at the managed egress CA path.
func DesiredEgressCAConfigMap(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme, certPEM []byte) (*corev1.ConfigMap, error) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressCAConfigMapName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Data: map[string]string{egressCACertKey: string(certPEM)},
	}
	if err := controllerutil.SetControllerReference(agentRun, configMap, scheme); err != nil {
		return nil, fmt.Errorf("set egress CA ConfigMap owner: %w", err)
	}
	return configMap, nil
}

func (r *AgentRunReconciler) reconcileEgressCASecret(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	secret := &corev1.Secret{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressCASecretName(agentRun.Name)}
	err := r.Get(ctx, key, secret)
	if err == nil {
		if !metav1.IsControlledBy(secret, agentRun) {
			return fmt.Errorf("egress CA Secret %s/%s exists but is not controlled by AgentRun %s", secret.Namespace, secret.Name, agentRun.Name)
		}
		if err := validateCAKeyPairPEM(secret.Data[egressCACertKey], secret.Data[egressCAKeyKey]); err != nil {
			return fmt.Errorf("egress CA Secret %s/%s has invalid keypair: %w", secret.Namespace, secret.Name, err)
		}
		return nil
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("get egress CA Secret: %w", err)
	}
	// In forward-proxy mode the durable CA must also permit the MITM upstream
	// hosts, or the agent's TLS verification of the minted upstream leaf fails
	// the CA name constraint.
	leafNames := append(egressdLeafDNSNames(agentRun), forwardProxyUpstreamHosts(agentRun)...)
	data, err := generateEgressCASecretData(leafNames)
	if err != nil {
		return err
	}
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressCASecretName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	if err := controllerutil.SetControllerReference(agentRun, desired, r.Scheme); err != nil {
		return fmt.Errorf("set egress CA Secret owner: %w", err)
	}
	if err := r.Create(ctx, desired); err != nil {
		return fmt.Errorf("create egress CA Secret: %w", err)
	}
	return nil
}

func generateEgressCASecretData(leafDNSNames []string) (map[string][]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate egress CA key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate egress CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "nvt-egressd per-run CA"},
		NotBefore:                   time.Now().Add(-5 * time.Minute),
		NotAfter:                    time.Now().Add(30 * 24 * time.Hour),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         append([]string{"localhost"}, leafDNSNames...),
		PermittedIPRanges: []*net.IPNet{
			{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
			{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
		},
		ExcludedDNSDomains:      nil,
		ExcludedIPRanges:        nil,
		PermittedEmailAddresses: nil,
		ExcludedEmailAddresses:  nil,
		PermittedURIDomains:     nil,
		ExcludedURIDomains:      nil,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create egress CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal egress CA key: %w", err)
	}
	return map[string][]byte{
		egressCACertKey: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		egressCAKeyKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func (r *AgentRunReconciler) reconcileEgressdPod(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	pod := &corev1.Pod{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdPodName(agentRun.Name)}
	if err := r.Get(ctx, key, pod); err == nil {
		if !metav1.IsControlledBy(pod, agentRun) {
			return fmt.Errorf("egressd Pod %s/%s exists but is not controlled by AgentRun %s", pod.Namespace, pod.Name, agentRun.Name)
		}
		if err := r.repairOwnedPodLabels(ctx, pod, enforcementLabels(agentRun.Name, roleLabelEgressd)); err != nil {
			return err
		}
		return nil
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("get egressd Pod: %w", err)
	}
	desired, err := DesiredEgressdPod(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	if err := r.Create(ctx, desired); err != nil {
		return fmt.Errorf("create egressd Pod: %w", err)
	}
	return nil
}

func (r *AgentRunReconciler) reconcileEgressdService(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	service := &corev1.Service{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressdServiceName(agentRun.Name)}
	desired, err := DesiredEgressdService(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	if err := r.Get(ctx, key, service); err == nil {
		if !metav1.IsControlledBy(service, agentRun) {
			return fmt.Errorf("egressd Service %s/%s exists but is not controlled by AgentRun %s", service.Namespace, service.Name, agentRun.Name)
		}
		if reflect.DeepEqual(service.Labels, desired.Labels) &&
			reflect.DeepEqual(service.OwnerReferences, desired.OwnerReferences) &&
			reflect.DeepEqual(service.Spec.Selector, desired.Spec.Selector) &&
			reflect.DeepEqual(service.Spec.Ports, desired.Spec.Ports) {
			return nil
		}
		service.Labels = desired.Labels
		service.OwnerReferences = desired.OwnerReferences
		service.Spec.Selector = desired.Spec.Selector
		service.Spec.Ports = desired.Spec.Ports
		if err := r.Update(ctx, service); err != nil {
			return fmt.Errorf("update egressd Service: %w", err)
		}
		return nil
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("get egressd Service: %w", err)
	}
	if err := r.Create(ctx, desired); err != nil {
		return fmt.Errorf("create egressd Service: %w", err)
	}
	return nil
}

// DesiredEgressdPod renders the own-Pod egressd for an enforcement run. It
// carries the same config/token/broker-CA wiring as the same-Pod sidecar,
// plus a readiness probe on the CA endpoint so EgressdReady is observable.
func DesiredEgressdPod(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Pod, error) {
	if err := ValidateBrokerTLSConfig(); err != nil {
		return nil, err
	}
	volumes := []corev1.Volume{{
		Name: egressdConfigName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: EgressdConfigMapName(agentRun.Name)},
				Items: []corev1.KeyToPath{
					{Key: egressdConfigKey, Path: egressdConfigKey},
				},
			},
		},
	}}
	volumeMounts := []corev1.VolumeMount{
		{Name: egressdConfigName, MountPath: egressdConfigPath, SubPath: egressdConfigKey, ReadOnly: true},
	}
	if AgentRunEgressEnforced(agentRun) {
		volumes = append(volumes, corev1.Volume{
			Name: egressCASecretVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: EgressCASecretName(agentRun.Name),
					Items: []corev1.KeyToPath{
						{Key: egressCACertKey, Path: egressCACertKey},
						{Key: egressCAKeyKey, Path: egressCAKeyKey},
					},
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      egressCASecretVolume,
			MountPath: egressCASecretMount,
			ReadOnly:  true,
		})
	}
	if brokerCADistributed() {
		volumes = append(volumes, corev1.Volume{
			Name: brokerCAVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: BrokerCASecretName(),
					Items: []corev1.KeyToPath{
						{Key: brokerCAKey, Path: brokerCAKey},
					},
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      brokerCAVolumeName,
			MountPath: egressdBrokerCAMount,
			ReadOnly:  true,
		})
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressdPodName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    enforcementLabels(agentRun.Name, roleLabelEgressd),
		},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: ptrTo(false),
			RestartPolicy:                corev1.RestartPolicyAlways,
			Containers: []corev1.Container{{
				Name:            "egressd",
				Image:           EgressdImage(),
				ImagePullPolicy: corev1.PullIfNotPresent,
				Env: []corev1.EnvVar{
					{Name: "NVT_EGRESSD_CONFIG", Value: egressdConfigPath},
					{
						Name: "NVT_BROKER_TOKEN",
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: EgressTokenSecretName(agentRun.Name)},
								Key:                  egressTokenKey,
							},
						},
					},
				},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path: "/healthz",
							Port: intstr.FromInt32(egressCAPort),
						},
					},
					PeriodSeconds: 2,
				},
				VolumeMounts: volumeMounts,
			}},
			Volumes: volumes,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, pod, scheme); err != nil {
		return nil, fmt.Errorf("set egressd Pod owner: %w", err)
	}
	return pod, nil
}

// AgentNetworkPolicyName returns the per-run agent egress policy name.
func AgentNetworkPolicyName(agentRunName string) string {
	return agentRunName + "-agent"
}

// EgressdNetworkPolicyName returns the per-run egressd policy name.
func EgressdNetworkPolicyName(agentRunName string) string {
	return agentRunName + "-egressd"
}

func (r *AgentRunReconciler) reconcileNetworkPolicies(ctx context.Context, agentRun *nvtv1alpha1.AgentRun) error {
	agentPolicy, err := DesiredAgentNetworkPolicy(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	egressdPolicy, err := DesiredEgressdNetworkPolicy(agentRun, r.Scheme)
	if err != nil {
		return err
	}
	for _, desired := range []*networkingv1.NetworkPolicy{agentPolicy, egressdPolicy} {
		policy := &networkingv1.NetworkPolicy{}
		err := r.Get(ctx, client.ObjectKeyFromObject(desired), policy)
		if err == nil {
			if !metav1.IsControlledBy(policy, agentRun) {
				return fmt.Errorf("NetworkPolicy %s/%s exists but is not controlled by AgentRun %s", policy.Namespace, policy.Name, agentRun.Name)
			}
			if reflect.DeepEqual(policy.Labels, desired.Labels) &&
				reflect.DeepEqual(policy.OwnerReferences, desired.OwnerReferences) &&
				reflect.DeepEqual(policy.Spec, desired.Spec) {
				continue
			}
			policy.Labels = desired.Labels
			policy.OwnerReferences = desired.OwnerReferences
			policy.Spec = desired.Spec
			if err := r.Update(ctx, policy); err != nil {
				return fmt.Errorf("update NetworkPolicy %s: %w", desired.Name, err)
			}
			continue
		}
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get NetworkPolicy %s: %w", desired.Name, err)
		}
		if createErr := r.Create(ctx, desired); createErr != nil {
			return fmt.Errorf("create NetworkPolicy %s: %w", desired.Name, createErr)
		}
	}
	return nil
}

func protocolPtr(protocol corev1.Protocol) *corev1.Protocol {
	return &protocol
}

func policyPort(protocol corev1.Protocol, port int) networkingv1.NetworkPolicyPort {
	value := intstr.FromInt32(int32(port))
	return networkingv1.NetworkPolicyPort{Protocol: protocolPtr(protocol), Port: &value}
}

func dnsPolicyEgressRule() networkingv1.NetworkPolicyEgressRule {
	return networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
			},
		}},
		Ports: []networkingv1.NetworkPolicyPort{
			policyPort(corev1.ProtocolUDP, 53),
			policyPort(corev1.ProtocolTCP, 53),
		},
	}
}

func brokerPolicyEgressRule() networkingv1.NetworkPolicyEgressRule {
	return networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/name": "nvt-broker"},
			},
		}},
		Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, 7347)},
	}
}

// egressdPolicyPorts are the CA endpoint plus every route port (and the
// forward-proxy port in forward-proxy mode). Feeds both the agent→egressd
// egress rule and the egressd ingress rule.
func egressdPolicyPorts(agentRun *nvtv1alpha1.AgentRun) []networkingv1.NetworkPolicyPort {
	ports := []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, egressCAPort)}
	for index := range headerInjectGrants(agentRun) {
		ports = append(ports, policyPort(corev1.ProtocolTCP, egressRouteBasePort+index))
	}
	if AgentRunEgressForwardProxy(agentRun) {
		ports = append(ports, policyPort(corev1.ProtocolTCP, egressForwardProxyPort))
	}
	return ports
}

// DesiredAgentNetworkPolicy is the enforcement fence around the agent Pod:
// default-deny egress plus kube-dns and the paired egressd. Literal zero-secret
// runs have no direct broker or callback path. No internet CIDR at all — including traffic from
// dind-spawned containers, which still exits the Pod and hits the CNI.
// Ingress is left unrestricted this PR (gateway/code-server unaffected).
func DesiredAgentNetworkPolicy(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*networkingv1.NetworkPolicy, error) {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentNetworkPolicyName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    enforcementLabels(agentRun.Name, roleLabelAgent),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					agentRunLabelKey: agentRun.Name,
					roleLabelKey:     roleLabelAgent,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				dnsPolicyEgressRule(),
				{
					// Paired egressd only: the run label pins the pair, so
					// agent A can never reach egressd B.
					To: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								agentRunLabelKey: agentRun.Name,
								roleLabelKey:     roleLabelEgressd,
							},
						},
					}},
					Ports: egressdPolicyPorts(agentRun),
				},
			},
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, policy, scheme); err != nil {
		return nil, fmt.Errorf("set agent NetworkPolicy owner: %w", err)
	}
	return policy, nil
}

// DesiredEgressdNetworkPolicy fences the own-Pod egressd: ingress only from
// the paired agent; egress to DNS, the broker, and configured external TCP
// ports (HTTP/HTTPS by default).
//
// The public-CIDR/port egress is a deliberately coarse fence: vanilla
// NetworkPolicy selects by CIDR/port, not hostname. The semantic per-host
// allowlist lives in egressd itself (pinned route upstreams, capability
// injection-hosts, fail-closed CONNECT allowlist) — do not read the public
// CIDR rules as host-scoped. Cluster CIDRs remain excluded; a test/dev-only
// allowInsecureUpstream can instead select an explicitly labelled fixture.
func DesiredEgressdNetworkPolicy(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*networkingv1.NetworkPolicy, error) {
	denyCIDRs, err := DeploymentDenyCIDRs()
	if err != nil {
		return nil, err
	}
	externalPorts, err := ExternalTCPPorts()
	if err != nil {
		return nil, err
	}
	var ipv4Except, ipv6Except []string
	for _, cidr := range denyCIDRs {
		if strings.Contains(cidr, ":") {
			ipv6Except = append(ipv6Except, cidr)
		} else {
			ipv4Except = append(ipv4Except, cidr)
		}
	}
	egressRules := []networkingv1.NetworkPolicyEgressRule{dnsPolicyEgressRule(), brokerPolicyEgressRule()}
	// Test/dev-only explicitly configured in-cluster upstreams get a narrow
	// Pod-selector exception. External-looking fixture names must opt in by
	// carrying the hash label; blind tunnels never receive this exception.
	for _, grant := range AgentRunBrokerGrants(agentRun.Spec.Broker) {
		if !grant.AllowInsecureUpstream {
			continue
		}
		for _, upstream := range grant.EgressHosts {
			host, portText, err := net.SplitHostPort(upstream)
			if err != nil {
				continue
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				continue
			}
			labels := map[string]string{"nvt.dev/egress-host": egressHostLabel(host)}
			if strings.HasSuffix(host, ".svc.cluster.local") {
				labels = map[string]string{"app.kubernetes.io/name": strings.Split(host, ".")[0]}
			}
			egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{
				To:    []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: labels}}},
				Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, port)},
			})
		}
	}
	externalPolicyPorts := make([]networkingv1.NetworkPolicyPort, 0, len(externalPorts))
	for _, port := range externalPorts {
		externalPolicyPorts = append(externalPolicyPorts, policyPort(corev1.ProtocolTCP, port))
	}
	egressRules = append(egressRules,
		networkingv1.NetworkPolicyEgressRule{
			To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: ipv4Except}}},
			Ports: externalPolicyPorts,
		},
		networkingv1.NetworkPolicyEgressRule{
			To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "::/0", Except: ipv6Except}}},
			Ports: externalPolicyPorts,
		},
	)
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressdNetworkPolicyName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    enforcementLabels(agentRun.Name, roleLabelEgressd),
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					agentRunLabelKey: agentRun.Name,
					roleLabelKey:     roleLabelEgressd,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								agentRunLabelKey: agentRun.Name,
								roleLabelKey:     roleLabelAgent,
							},
						},
					}},
					Ports: egressdPolicyPorts(agentRun),
				},
				{
					// Operator probes may read the public CA endpoint across
					// the CNI. CA port only — never the route ports.
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app.kubernetes.io/name": "nvt-operator"},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{policyPort(corev1.ProtocolTCP, egressCAPort)},
				},
			},
			Egress: egressRules,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, policy, scheme); err != nil {
		return nil, fmt.Errorf("set egressd NetworkPolicy owner: %w", err)
	}
	return policy, nil
}

func egressHostLabel(host string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSuffix(host, "."))))
	return hex.EncodeToString(digest[:16])
}

// DesiredEgressdService exposes the CA endpoint and every route port under
// the per-run Service name the agent's base-urls point at.
func DesiredEgressdService(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.Service, error) {
	ports := []corev1.ServicePort{{Name: "ca", Port: egressCAPort}}
	for index := range headerInjectGrants(agentRun) {
		ports = append(ports, corev1.ServicePort{
			Name: fmt.Sprintf("route-%d", index),
			Port: int32(egressRouteBasePort + index),
		})
	}
	if AgentRunEgressForwardProxy(agentRun) {
		ports = append(ports, corev1.ServicePort{Name: "forward-proxy", Port: int32(egressForwardProxyPort)})
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressdServiceName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    enforcementLabels(agentRun.Name, roleLabelEgressd),
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				agentRunLabelKey: agentRun.Name,
				roleLabelKey:     roleLabelEgressd,
			},
			Ports: ports,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, service, scheme); err != nil {
		return nil, fmt.Errorf("set egressd Service owner: %w", err)
	}
	return service, nil
}

// DesiredTokenSecret returns an owned token Secret, preserving an existing token when present.
func DesiredTokenSecret(
	agentRun *nvtv1alpha1.AgentRun,
	scheme *runtime.Scheme,
	name string,
	key string,
	existingToken []byte,
) (*corev1.Secret, error) {
	token := existingToken
	if len(token) == 0 {
		generated, err := GenerateToken(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate AgentRun token Secret %s token: %w", name, err)
		}
		token = []byte(generated)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			key: append([]byte(nil), token...),
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, secret, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun token Secret owner: %w", err)
	}

	return secret, nil
}

// DesiredAgentConfigMap renders the AgentRun agent config into its owned ConfigMap.
func DesiredAgentConfigMap(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.ConfigMap, error) {
	if err := ValidateAgentRunWorkspaceInstructions(agentRun); err != nil {
		return nil, err
	}
	if err := ValidateAgentRunRuntimeCapabilities(agentRun); err != nil {
		return nil, err
	}
	rendered, err := RenderAgentConfigYAML(agentRun)
	if err != nil {
		return nil, err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      AgentConfigMapName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Data: map[string]string{
			agentConfigKey: rendered,
		},
	}
	if agentRun.Spec.Agent.WorkspaceInstructions != "" {
		configMap.Data[profileWorkspaceInstructionsKey] = agentRun.Spec.Agent.WorkspaceInstructions
	}
	if agentRun.Spec.Agent.WorkflowInstructions != "" {
		configMap.Data[workflowWorkspaceInstructionsKey] = agentRun.Spec.Agent.WorkflowInstructions
	}
	if err := controllerutil.SetControllerReference(agentRun, configMap, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun config ConfigMap owner: %w", err)
	}

	return configMap, nil
}

// DesiredEgressdConfigMap renders the mediated egressd config for an AgentRun.
func DesiredEgressdConfigMap(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme) (*corev1.ConfigMap, error) {
	rendered, err := RenderEgressdConfigJSON(agentRun)
	if err != nil {
		return nil, err
	}
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EgressdConfigMapName(agentRun.Name),
			Namespace: agentRun.Namespace,
			Labels:    agentRunLabels(agentRun.Name),
		},
		Data: map[string]string{
			egressdConfigKey: rendered,
		},
	}
	if err := controllerutil.SetControllerReference(agentRun, configMap, scheme); err != nil {
		return nil, fmt.Errorf("set AgentRun egressd config ConfigMap owner: %w", err)
	}
	return configMap, nil
}

func RenderEgressdConfigJSON(agentRun *nvtv1alpha1.AgentRun) (string, error) {
	type egressdRoute struct {
		Listen                string `json:"listen"`
		Capability            string `json:"capability"`
		Upstream              string `json:"upstream"`
		AllowInsecureUpstream bool   `json:"allow_insecure_upstream"`
		ListenTLS             string `json:"listen_tls,omitempty"`
		MaxRequests           int    `json:"max_requests,omitempty"`
	}
	type egressdCA struct {
		PublishDir   string   `json:"publish_dir,omitempty"`
		LeafDNSNames []string `json:"leaf_dns_names,omitempty"`
		ServeAddr    string   `json:"serve_addr,omitempty"`
		CertFile     string   `json:"cert_file,omitempty"`
		KeyFile      string   `json:"key_file,omitempty"`
	}
	type egressdForwardProxyRoute struct {
		Host                  string `json:"host"`
		Capability            string `json:"capability"`
		Upstream              string `json:"upstream"`
		AllowInsecureUpstream bool   `json:"allow_insecure_upstream,omitempty"`
		MaxRequests           int    `json:"max_requests,omitempty"`
		RequireCapabilityHint bool   `json:"require_capability_hint,omitempty"`
	}
	type egressdForwardProxy struct {
		Listen               string                     `json:"listen"`
		TransparentMode      bool                       `json:"transparent_mode,omitempty"`
		AllowUnmatchedHosts  bool                       `json:"allow_unmatched_hosts"`
		AllowPorts           []int                      `json:"allow_ports"`
		MaxConcurrentTunnels int32                      `json:"max_concurrent_tunnels,omitempty"`
		DenyCIDRs            []string                   `json:"deny_cidrs,omitempty"`
		InjectRoutes         []egressdForwardProxyRoute `json:"inject_routes"`
	}
	type egressdConfig struct {
		BrokerURL           string               `json:"broker_url"`
		AllowInsecureBroker bool                 `json:"allow_insecure_broker"`
		BrokerCAFile        string               `json:"broker_ca_file,omitempty"`
		Routes              []egressdRoute       `json:"routes"`
		ForwardProxy        *egressdForwardProxy `json:"forward_proxy,omitempty"`
		CA                  *egressdCA           `json:"ca,omitempty"`
	}
	if err := ValidateBrokerTLSConfig(); err != nil {
		return "", err
	}
	grants := AgentRunBrokerGrants(agentRun.Spec.Broker)
	routes := make([]egressdRoute, 0, len(grants))
	enforced := AgentRunEgressEnforced(agentRun)
	forwardProxy := AgentRunEgressForwardProxy(agentRun)
	routeIndex := 0
	needCA := false
	for _, grant := range grants {
		// In forward-proxy mode injectable grants are routed by the MITM proxy,
		// not per-route redirect base URLs, so no redirect routes are rendered.
		if forwardProxy || AgentRunGrantMaterialization(grant) != nvtv1alpha1.AgentRunGrantHeaderInject {
			continue
		}
		if len(grant.EgressHosts) == 0 {
			return "", fmt.Errorf("broker grant %s egressHosts is required for mediated egress", grant.Provider)
		}
		route := egressdRoute{
			Listen:                fmt.Sprintf("127.0.0.1:%d", egressRouteBasePort+routeIndex),
			Capability:            grant.Provider,
			Upstream:              grant.EgressHosts[0],
			AllowInsecureUpstream: grant.AllowInsecureUpstream,
		}
		if grant.Quota != nil {
			route.MaxRequests = grant.Quota.Requests
		}
		if enforced {
			// Own-Pod: the hop leaves localhost, so every route listens on
			// the Pod network and terminates TLS under the per-agent CA.
			route.Listen = fmt.Sprintf("0.0.0.0:%d", egressRouteBasePort+routeIndex)
			route.ListenTLS = "ca"
			needCA = true
		} else if grant.Git {
			// git clients require an https base URL; the route terminates
			// TLS with a leaf signed by the boot-generated per-agent CA.
			route.ListenTLS = "ca"
			needCA = true
		}
		routes = append(routes, route)
		routeIndex++
	}
	config := egressdConfig{
		BrokerURL:           BrokerURL(),
		AllowInsecureBroker: agentRun.Spec.EgressAllowInsecureBroker,
		Routes:              routes,
	}
	if forwardProxy {
		denyCIDRs, err := DeploymentDenyCIDRs()
		if err != nil {
			return "", err
		}
		externalPorts, err := ExternalTCPPorts()
		if err != nil {
			return "", err
		}
		injects := forwardProxyInjects(agentRun)
		if len(injects) == 0 {
			return "", fmt.Errorf("forward-proxy egress requires at least one injectable grant with egressHosts")
		}
		fpRoutes := make([]egressdForwardProxyRoute, 0, len(injects))
		for _, inject := range injects {
			fpRoutes = append(fpRoutes, egressdForwardProxyRoute{
				Host:                  inject.Host,
				Capability:            inject.Capability,
				Upstream:              inject.Upstream,
				AllowInsecureUpstream: inject.AllowInsecureUpstream,
				MaxRequests:           inject.MaxRequests,
				RequireCapabilityHint: inject.RequireCapabilityHint,
			})
		}
		config.ForwardProxy = &egressdForwardProxy{
			Listen:               fmt.Sprintf("0.0.0.0:%d", egressForwardProxyPort),
			TransparentMode:      AgentRunEgressTransparent(agentRun),
			AllowUnmatchedHosts:  true,
			AllowPorts:           externalPorts,
			MaxConcurrentTunnels: agentRun.Spec.EgressMaxConcurrentTunnels,
			DenyCIDRs:            denyCIDRs,
			InjectRoutes:         fpRoutes,
		}
	}
	if brokerCADistributed() {
		// TLS broker leg: pin the CA so egressd verifies the broker instead
		// of relying on the insecure flag.
		config.BrokerCAFile = egressdBrokerCAFile
		config.AllowInsecureBroker = false
	}
	if enforced {
		// The CA keypair is generated once by the operator and mounted only
		// into egressd; the agent receives only ca.crt via ConfigMap.
		config.CA = &egressdCA{
			LeafDNSNames: egressdLeafDNSNames(agentRun),
			ServeAddr:    fmt.Sprintf("0.0.0.0:%d", egressCAPort),
			CertFile:     egressCASecretCert,
			KeyFile:      egressCASecretKeyFile,
		}
	} else if needCA {
		config.CA = &egressdCA{PublishDir: egressCAMountPath}
	}
	rendered, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("render egressd config: %w", err)
	}
	return string(rendered) + "\n", nil
}
