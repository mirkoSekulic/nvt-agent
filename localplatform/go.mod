module github.com/mirkoSekulic/nvt-agent/localplatform

go 1.25.0

require (
	github.com/distribution/reference v0.6.0
	github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/opencontainers/go-digest v1.0.0 // indirect

replace github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun => ../protocol/resolvedrun
