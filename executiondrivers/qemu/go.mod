module github.com/mirkoSekulic/nvt-agent/executiondrivers/qemu

go 1.24.0

require (
	github.com/mirkoSekulic/nvt-agent/operator v0.0.0
	github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment v0.0.0
)

replace github.com/mirkoSekulic/nvt-agent/operator => ../../operator

replace github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment => ../../protocol/guestenrollment
