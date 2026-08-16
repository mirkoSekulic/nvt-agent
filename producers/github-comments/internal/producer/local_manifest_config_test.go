package producer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	localmanifest "github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	localproducer "github.com/mirkoSekulic/nvt-agent/localplatform/producer"
)

func TestGeneratedLocalManifestConfigurationLoadsWithRealValidator(t *testing.T) {
	const raw = `apiVersion: nvt.dev/local/v1
secrets:
  github-key: {file: ./.nvt-local/secrets/github/key.pem}
accounts:
  github:
    preset: github-app
    appId: "123"
    privateKeySecret: github-key
    installations: {acme: "456"}
profiles:
  development:
    runtime: {preset: shell, autonomy: read-only}
    accounts: [github]
repositories:
  widget: {github: acme/widget, account: github}
workflows:
  development: {profile: development, repository: widget, retention: disposable}
producers:
  - name: github
    preset: github-comments
    account: github
    repository: widget
    prefix: /nvtagent
    allowedAuthors: [owner]
    workflow: development
`
	decoded, err := localmanifest.Decode(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("decode local manifest: %v", err)
	}
	compiled, err := localmanifest.Compile(decoded)
	if err != nil {
		t.Fatalf("compile local manifest: %v", err)
	}
	files, err := localproducer.Configurations(compiled)
	if err != nil || len(files) != 1 {
		t.Fatalf("render generated configuration: files=%d err=%v", len(files), err)
	}
	path := filepath.Join(t.TempDir(), "github.json")
	if err := os.WriteFile(path, files[0].Data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("real producer rejected generated configuration: %v", err)
	}
	if config.Submission.Backend != SubmissionBackendLocal || config.Submission.AdmissionMode != AdmissionModeProfiled ||
		config.Submission.ScheduleNamespace != "unused" || config.Submission.ScheduleName != "github" || config.Submission.Workflow != "development" {
		t.Fatalf("generated submission contract changed: %#v", config.Submission)
	}
}
