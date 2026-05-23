TYPE ?= codex

.PHONY: infra-up infra-down agent-init agent-up

infra-up:
	./scripts/infra-up.sh

infra-down:
	./scripts/infra-down.sh

agent-init:
	@test -n "$(NAME)" || (echo "usage: make agent-init NAME=<name> [TYPE=codex|claude]"; exit 1)
	./scripts/agent-init.sh --name "$(NAME)" --type "$(TYPE)"

agent-up:
	@test -n "$(NAME)" || (echo "usage: make agent-up NAME=<name>"; exit 1)
	./scripts/agent-up.sh --name "$(NAME)"
