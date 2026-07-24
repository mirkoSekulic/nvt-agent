package controller

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
)

// linuxCapabilityNames is the Linux UAPI capability registry through
// CAP_CHECKPOINT_RESTORE. This is input validation, not an nvt security
// policy: Kubernetes admission and the selected container runtime remain
// authoritative about which valid capabilities a workload may receive.
var linuxCapabilityNames = map[corev1.Capability]struct{}{
	"CHOWN": {}, "DAC_OVERRIDE": {}, "DAC_READ_SEARCH": {}, "FOWNER": {},
	"FSETID": {}, "KILL": {}, "SETGID": {}, "SETUID": {}, "SETPCAP": {},
	"LINUX_IMMUTABLE": {}, "NET_BIND_SERVICE": {}, "NET_BROADCAST": {},
	"NET_ADMIN": {}, "NET_RAW": {}, "IPC_LOCK": {}, "IPC_OWNER": {},
	"SYS_MODULE": {}, "SYS_RAWIO": {}, "SYS_CHROOT": {}, "SYS_PTRACE": {},
	"SYS_PACCT": {}, "SYS_ADMIN": {}, "SYS_BOOT": {}, "SYS_NICE": {},
	"SYS_RESOURCE": {}, "SYS_TIME": {}, "SYS_TTY_CONFIG": {}, "MKNOD": {},
	"LEASE": {}, "AUDIT_WRITE": {}, "AUDIT_CONTROL": {}, "SETFCAP": {},
	"MAC_OVERRIDE": {}, "MAC_ADMIN": {}, "SYSLOG": {}, "WAKE_ALARM": {},
	"BLOCK_SUSPEND": {}, "AUDIT_READ": {}, "PERFMON": {}, "BPF": {},
	"CHECKPOINT_RESTORE": {},
}

// ValidateAgentRunRuntimeCapabilities validates the narrow container process
// contract before an agent Pod is created.
func ValidateAgentRunRuntimeCapabilities(agentRun *nvtv1alpha1.AgentRun) error {
	return validateRuntimeCapabilities(agentRun.Spec.Runtime)
}

func validateRuntimeCapabilities(runtime nvtv1alpha1.AgentRunRuntime) error {
	if runtime.Container == nil || runtime.Container.Capabilities == nil {
		return nil
	}
	seen := make(map[corev1.Capability]struct{}, len(runtime.Container.Capabilities.Add))
	for _, capability := range runtime.Container.Capabilities.Add {
		if _, valid := linuxCapabilityNames[capability]; !valid {
			return fmt.Errorf("spec.runtime.container.capabilities.add contains unknown Linux capability %q", capability)
		}
		if _, duplicate := seen[capability]; duplicate {
			return fmt.Errorf("spec.runtime.container.capabilities.add contains duplicate capability %q", capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func agentRuntimeCapabilities(agentRun *nvtv1alpha1.AgentRun) []corev1.Capability {
	if agentRun.Spec.Runtime.Container == nil || agentRun.Spec.Runtime.Container.Capabilities == nil {
		return nil
	}
	return append([]corev1.Capability(nil), agentRun.Spec.Runtime.Container.Capabilities.Add...)
}
