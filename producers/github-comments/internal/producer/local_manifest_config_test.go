package producer

import (
	"os"
	"path/filepath"
	"testing"

	localmanifest "github.com/mirkoSekulic/nvt-agent/localplatform/manifest"
	localproducer "github.com/mirkoSekulic/nvt-agent/localplatform/producer"
)

func TestGeneratedLocalManifestConfigurationLoadsWithRealValidator(t *testing.T) {
	compiled := localmanifest.Compiled{
		Version: localmanifest.APIVersion,
		Producers: []localmanifest.ProducerIntent{{
			Owner: "producer:github", Name: "github", Kind: "github-comments",
			RuntimeIdentity: localmanifest.RuntimeIdentityIntent{UID: 65532, GID: 65532},
			Workflow:        "development", AdmissionCredential: "producer-admission:github",
			GitHub: &localmanifest.GitHubProducerIntent{
				AppID: 123, InstallationID: 456, PrivateKeySecret: "github-key",
				RepositoryOwner: "acme", RepositoryName: "widget", Prefix: "/nvtagent", AllowedAuthors: []string{"owner"},
			},
		}},
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
