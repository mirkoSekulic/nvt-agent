TYPE ?= codex

.PHONY: infra-up infra-down agent-init

infra-up:
	./scripts/infra-up.sh

infra-down:
	./scripts/infra-down.sh

agent-init:
	@test -n "$(NAME)" || (echo "usage: make agent-init NAME=<name> [TYPE=codex|claude]"; exit 1)
	./scripts/agent-init.sh --name "$(NAME)" --type "$(TYPE)"
