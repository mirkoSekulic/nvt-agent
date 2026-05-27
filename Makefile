TYPE ?= codex
DIR ?= runtime/plugins

.PHONY: runtime-build broker-build infra-up infra-down infra-network-rm agent-init agent-grant agent-up agent-logs agent-shell agent-doctor agent-ps agent-down agent-down-all agent-rm agent-rm-all plugin-init down-all clean nuke

runtime-build:
	bash scripts/runtime-build.sh $(if $(NO_CACHE),--no-cache)

broker-build:
	bash scripts/broker-build.sh

infra-up:
	bash scripts/infra-up.sh

infra-down:
	bash scripts/infra-down.sh

infra-network-rm:
	bash scripts/infra-network-rm.sh

agent-init:
	@test -n "$(NAME)" || (echo "usage: make agent-init NAME=<name> [TYPE=codex|claude]"; exit 1)
	bash scripts/agent-init.sh --name "$(NAME)" --type "$(TYPE)"

agent-grant:
	@test -n "$(NAME)" || (echo "usage: make agent-grant NAME=<name> PROVIDER=<provider> REPO=<owner/repo>"; exit 1)
	@test -n "$(PROVIDER)" || (echo "usage: make agent-grant NAME=<name> PROVIDER=<provider> REPO=<owner/repo>"; exit 1)
	@test -n "$(REPO)" || (echo "usage: make agent-grant NAME=<name> PROVIDER=<provider> REPO=<owner/repo>"; exit 1)
	bash scripts/agent-grant.sh --name "$(NAME)" --provider "$(PROVIDER)" --repo "$(REPO)"

agent-up:
	@test -n "$(NAME)" || (echo "usage: make agent-up NAME=<name>"; exit 1)
	bash scripts/agent-up.sh --name "$(NAME)"

agent-logs:
	@test -n "$(NAME)" || (echo "usage: make agent-logs NAME=<name>"; exit 1)
	bash scripts/agent-logs.sh --name "$(NAME)"

agent-shell:
	@test -n "$(NAME)" || (echo "usage: make agent-shell NAME=<name>"; exit 1)
	bash scripts/agent-shell.sh --name "$(NAME)"

agent-doctor:
	@test -n "$(NAME)" || (echo "usage: make agent-doctor NAME=<name> [PLUGIN=<plugin>]"; exit 1)
	bash scripts/agent-doctor.sh --name "$(NAME)" $(if $(PLUGIN),--plugin "$(PLUGIN)")

agent-ps:
	bash scripts/agent-ps.sh

agent-down:
	@test -n "$(NAME)" || (echo "usage: make agent-down NAME=<name>"; exit 1)
	bash scripts/agent-down.sh --name "$(NAME)"

agent-down-all:
	bash scripts/agent-down-all.sh

agent-rm:
	@test -n "$(NAME)" || (echo "usage: make agent-rm NAME=<name> [FORCE=1]"; exit 1)
	bash scripts/agent-rm.sh --name "$(NAME)" $(if $(FORCE),--force)

agent-rm-all:
	bash scripts/agent-rm-all.sh $(if $(FORCE),--force)

plugin-init:
	@test -n "$(NAME)" || (echo "usage: make plugin-init NAME=<name> [DIR=runtime/plugins]"; exit 1)
	bash scripts/plugin-init.sh --name "$(NAME)" --dir "$(DIR)"

down-all:
	bash scripts/down-all.sh

clean:
	bash scripts/clean.sh

nuke:
	bash scripts/nuke.sh $(if $(FORCE),--force)
