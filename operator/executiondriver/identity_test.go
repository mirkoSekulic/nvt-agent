package executiondriver

import "testing"

func TestAgentRunExecutionIDIsStableAndOpaque(t *testing.T) {
	first, err := AgentRunExecutionID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	second, err := AgentRunExecutionID("11111111-1111-1111-1111-111111111111")
	if err != nil || first != second || len(first) != len("nvt-agentrun-")+64 {
		t.Fatalf("execution identity first=%q second=%q error=%v", first, second, err)
	}
	other, err := AgentRunExecutionID("22222222-2222-2222-2222-222222222222")
	if err != nil || other == first {
		t.Fatalf("distinct UID identity=%q error=%v", other, err)
	}
	if _, err := AgentRunExecutionID(""); err == nil {
		t.Fatal("empty AgentRun UID accepted")
	}
}
