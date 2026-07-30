module github.com/mirkoSekulic/nvt-agent/nativeegressrelay

go 1.25.0

require github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment v0.0.0

require github.com/hashicorp/yamux v0.1.2 // indirect

replace github.com/mirkoSekulic/nvt-agent/protocol/guestenrollment => ../protocol/guestenrollment
