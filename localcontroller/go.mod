module github.com/mirkoSekulic/nvt-agent/localcontroller

go 1.25.0

require (
	github.com/mirkoSekulic/nvt-agent/localplatform v0.0.0
	github.com/mirkoSekulic/nvt-agent/protocol/localroutes v0.0.0
	github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun v0.0.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.53.0
)

require (
	github.com/distribution/reference v0.6.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.44.0 // indirect
	modernc.org/libc v1.73.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/mirkoSekulic/nvt-agent/protocol/resolvedrun => ../protocol/resolvedrun

replace github.com/mirkoSekulic/nvt-agent/protocol/localroutes => ../protocol/localroutes

replace github.com/mirkoSekulic/nvt-agent/localplatform => ../localplatform
