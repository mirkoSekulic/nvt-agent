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
	"encoding/pem"
	stderrors "errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

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
	if err := validateCAKeyPairPEMAt(certPEM, secret.Data[egressCAKeyKey], r.now().Time); err != nil {
		return false, fmt.Errorf("egress CA Secret contains invalid keypair: %w", err)
	}
	configMap := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: agentRun.Namespace, Name: EgressCAConfigMapName(agentRun.Name)}
	err := r.Get(ctx, key, configMap)
	if err == nil {
		if !metav1.IsControlledBy(configMap, agentRun) {
			return false, fmt.Errorf("egress CA ConfigMap %s/%s exists but is not controlled by AgentRun %s", key.Namespace, key.Name, agentRun.Name)
		}
		desiredAnnotations := caGenerationAnnotations(certPEM, secret.Annotations[egressCAGenerationAnnotation])
		if configMap.Data[egressCACertKey] == string(certPEM) &&
			reflect.DeepEqual(configMap.Labels, agentRunLabels(agentRun.Name)) &&
			reflect.DeepEqual(configMap.Annotations, desiredAnnotations) {
			return true, nil
		}
		configMap.Labels = agentRunLabels(agentRun.Name)
		configMap.Annotations = desiredAnnotations
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
	desired.Annotations = caGenerationAnnotations(certPEM, secret.Annotations[egressCAGenerationAnnotation])
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
	return validateCAKeyPairPEMAt(certPEM, keyPEM, time.Now())
}

// DesiredEgressCAConfigMap wraps the public CA certificate for the agent Pod
// to mount read-only at the managed egress CA path.
func DesiredEgressCAConfigMap(agentRun *nvtv1alpha1.AgentRun, scheme *runtime.Scheme, certPEM []byte) (*corev1.ConfigMap, error) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        EgressCAConfigMapName(agentRun.Name),
			Namespace:   agentRun.Namespace,
			Labels:      agentRunLabels(agentRun.Name),
			Annotations: caGenerationAnnotations(certPEM, "1"),
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
		if err := validateCAKeyPairPEMAt(secret.Data[egressCACertKey], secret.Data[egressCAKeyKey], r.now().Time); err != nil {
			if !stderrors.Is(err, errEgressCAValidity) {
				return fmt.Errorf("egress CA Secret %s/%s has invalid keypair: %w", secret.Namespace, secret.Name, err)
			}
			if !egressCARotationIntent(agentRun) {
				r.setRunCondition(agentRun, ConditionEgressCAPublished, metav1.ConditionFalse, "EgressCARotating", "rotating egress CA and recreating trust consumers")
				if statusErr := r.Status().Update(ctx, agentRun); statusErr != nil {
					return fmt.Errorf("persist egress CA rotation intent: %w", statusErr)
				}
				return errEgressCARotationInProgress
			}
			for _, podName := range []string{AgentPodName(agentRun.Name), EgressdPodName(agentRun.Name)} {
				pod := &corev1.Pod{}
				if getErr := r.Get(ctx, client.ObjectKey{Namespace: agentRun.Namespace, Name: podName}, pod); getErr == nil {
					if !metav1.IsControlledBy(pod, agentRun) {
						return fmt.Errorf("refusing CA rotation: Pod %s is not controlled by AgentRun", podName)
					}
					if !pod.DeletionTimestamp.IsZero() {
						return errEgressCARotationInProgress
					}
					if deleteErr := r.Delete(ctx, pod); deleteErr != nil {
						return fmt.Errorf("delete stale CA consumer Pod %s: %w", podName, deleteErr)
					}
					return errEgressCARotationInProgress
				} else if !errors.IsNotFound(getErr) {
					return getErr
				}
			}
			generation, _ := strconv.ParseUint(secret.Annotations[egressCAGenerationAnnotation], 10, 64)
			data, generateErr := generateEgressCASecretDataAt(append(egressdLeafDNSNames(agentRun), forwardProxyUpstreamHosts(agentRun)...), r.now().Time)
			if generateErr != nil {
				return generateErr
			}
			secret.Data = data
			secret.Annotations = caGenerationAnnotations(data[egressCACertKey], strconv.FormatUint(generation+1, 10))
			if updateErr := r.Update(ctx, secret); updateErr != nil {
				return fmt.Errorf("rotate egress CA Secret: %w", updateErr)
			}
			return errEgressCARotationInProgress
		}
		generation := secret.Annotations[egressCAGenerationAnnotation]
		if generation == "" {
			generation = "1"
		}
		desiredAnnotations := caGenerationAnnotations(secret.Data[egressCACertKey], generation)
		if !reflect.DeepEqual(secret.Annotations, desiredAnnotations) {
			secret.Annotations = desiredAnnotations
			if err := r.Update(ctx, secret); err != nil {
				return fmt.Errorf("repair egress CA generation metadata: %w", err)
			}
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
	data, err := generateEgressCASecretDataAt(leafNames, r.now().Time)
	if err != nil {
		return err
	}
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        EgressCASecretName(agentRun.Name),
			Namespace:   agentRun.Namespace,
			Labels:      agentRunLabels(agentRun.Name),
			Annotations: caGenerationAnnotations(data[egressCACertKey], "1"),
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
	return generateEgressCASecretDataAt(leafDNSNames, time.Now())
}

func egressCARotationIntent(agentRun *nvtv1alpha1.AgentRun) bool {
	condition := meta.FindStatusCondition(agentRun.Status.Conditions, ConditionEgressCAPublished)
	return condition != nil && condition.Status == metav1.ConditionFalse && condition.Reason == "EgressCARotating"
}

func validateCAKeyPairPEMAt(certPEM, keyPEM []byte, now time.Time) error {
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
	if now.Before(certs[0].NotBefore) {
		return fmt.Errorf("%w: certificate is not valid before %s", errEgressCAValidity, certs[0].NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Add(egressCARenewalMargin).Before(certs[0].NotAfter) {
		return fmt.Errorf("%w: certificate expires at %s inside the %s renewal window", errEgressCAValidity, certs[0].NotAfter.UTC().Format(time.RFC3339), egressCARenewalMargin)
	}
	return nil
}

func generateEgressCASecretDataAt(leafDNSNames []string, now time.Time) (map[string][]byte, error) {
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
		NotBefore:                   now.Add(-5 * time.Minute),
		NotAfter:                    now.Add(egressCAValidity),
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

func caGenerationAnnotations(certPEM []byte, generation string) map[string]string {
	digest := sha256.Sum256(certPEM)
	return map[string]string{egressCAGenerationAnnotation: generation, egressCADigestAnnotation: hex.EncodeToString(digest[:])}
}

func (r *AgentRunReconciler) applyEgressCAGeneration(ctx context.Context, run *nvtv1alpha1.AgentRun, pod *corev1.Pod) error {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: run.Namespace, Name: EgressCASecretName(run.Name)}, secret); err != nil {
		return fmt.Errorf("get egress CA generation: %w", err)
	}
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	for _, key := range []string{egressCAGenerationAnnotation, egressCADigestAnnotation} {
		pod.Annotations[key] = secret.Annotations[key]
	}
	return nil
}

func (r *AgentRunReconciler) egressCARenewalRequeue(ctx context.Context, run *nvtv1alpha1.AgentRun) (ctrl.Result, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: run.Namespace, Name: EgressCASecretName(run.Name)}, secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("get egress CA renewal deadline: %w", err)
	}
	certs, err := parseCACertificatesPEM(secret.Data[egressCACertKey])
	if err != nil || len(certs) == 0 {
		return ctrl.Result{}, fmt.Errorf("read egress CA renewal deadline: %w", err)
	}
	delay := certs[0].NotAfter.Add(-egressCARenewalMargin).Sub(r.now().Time)
	if delay <= 0 {
		delay = time.Second
	}
	return ctrl.Result{RequeueAfter: delay}, nil
}
