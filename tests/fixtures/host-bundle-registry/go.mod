module github.com/mirkoSekulic/nvt-agent/tests/fixtures/host-bundle-registry

go 1.24.0

require github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment v0.0.0

replace github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment => ../../../protocol/guestenrollment
