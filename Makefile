TYPE ?= codex

.PHONY: runtime-build infra-up infra-down agent-init agent-up agent-logs agent-shell agent-ps agent-down agent-rm

runtime-build:
	bash scripts/runtime-build.sh $(if $(NO_CACHE),--no-cache)

infra-up:
	bash scripts/infra-up.sh

infra-down:
	bash scripts/infra-down.sh

agent-init:
	@test -n "$(NAME)" || (echo "usage: make agent-init NAME=<name> [TYPE=codex|claude]"; exit 1)
	bash scripts/agent-init.sh --name "$(NAME)" --type "$(TYPE)"

agent-up:
	@test -n "$(NAME)" || (echo "usage: make agent-up NAME=<name>"; exit 1)
	bash scripts/agent-up.sh --name "$(NAME)"

agent-logs:
	@test -n "$(NAME)" || (echo "usage: make agent-logs NAME=<name>"; exit 1)
	bash scripts/agent-logs.sh --name "$(NAME)"

agent-shell:
	@test -n "$(NAME)" || (echo "usage: make agent-shell NAME=<name>"; exit 1)
	bash scripts/agent-shell.sh --name "$(NAME)"

agent-ps:
	bash scripts/agent-ps.sh

agent-down:
	@test -n "$(NAME)" || (echo "usage: make agent-down NAME=<name>"; exit 1)
	bash scripts/agent-down.sh --name "$(NAME)"

agent-rm:
	@test -n "$(NAME)" || (echo "usage: make agent-rm NAME=<name> [FORCE=1]"; exit 1)
	bash scripts/agent-rm.sh --name "$(NAME)" $(if $(FORCE),--force)
