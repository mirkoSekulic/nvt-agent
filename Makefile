TYPE ?= codex
AUTONOMY ?= trusted-local
DIR ?= runtime/plugins
CLUSTER ?= nvt-smoke
NAMESPACE ?= nvt
SOURCE ?= $(HOME)/.codex
SECRET ?= codex-auth
CODEX_AUTH_SOURCE ?= $(SOURCE)
CODEX_AUTH_SECRET ?= $(SECRET)
GITHUB_APP_PRIVATE_KEY_FILE ?=
PRODUCER_GITHUB_APP_SECRET ?= nvt-github-app
PRODUCER_GITHUB_APP_KEY ?= private-key.pem
BROKER_ENV_FILE ?= .broker/env
BROKER_ENV_SECRET ?= nvt-broker-env
PRODUCER_IMAGE ?= nvt-github-comments-producer:latest
GATEWAY_IMAGE ?= nvt-agent-gateway:latest
PRODUCER_VALUES ?= values.github-comments.yaml
PRODUCER_RELEASE ?= nvt-github-comments-producer
PRODUCER_CHART ?= charts/nvt-github-comments-producer
CREATE_CLUSTER ?= 1
ROLLOUT_TIMEOUT ?= 180s
KUBECTL_CONTEXT ?= kind-$(CLUSTER)
OPERATOR_KIND_HELM_ARGS ?=
OPERATOR_KIND_GATEWAY ?= 0

ifeq ($(OPERATOR_KIND_GATEWAY),1)
OPERATOR_KIND_EXTRA_IMAGE_TARGETS := gateway-kind-load
OPERATOR_KIND_GATEWAY_HELM_ARGS := --set gateway.enabled=true --set gateway.image=$(GATEWAY_IMAGE)
endif

.PHONY: runtime-build broker-build operator-build producer-build gateway-build operator-helm-test operator-kind-cluster operator-kind-images operator-kind-install operator-kind-setup operator-kind-delete operator-kind-smoke operator-kind-smoke-render gateway-kind-load producer-kind-load producer-kind-install producer-kind-setup operator-codex-auth-secret github-comments-producer-secret broker-env-secret operator-smoke-schedule infra-up infra-down infra-network-rm agent-init agent-copy agent-cp agent-grant agent-up agent-logs agent-shell agent-doctor agent-ps agent-forward forward agent-down agent-down-all agent-rm agent-rm-all plugin-init down-all clean nuke

runtime-build:
	bash scripts/runtime-build.sh $(if $(NO_CACHE),--no-cache)

broker-build:
	bash scripts/broker-build.sh

operator-build:
	bash scripts/operator-build.sh $(if $(NO_CACHE),--no-cache)

producer-build:
	docker build -f producers/github-comments/Dockerfile -t "$(PRODUCER_IMAGE)" .

gateway-build:
	docker build -f gateway/Dockerfile -t "$(GATEWAY_IMAGE)" .

operator-helm-test:
	bash tests/operator/helm/test.sh

operator-kind-cluster:
	@if kind get clusters | grep -Fxq "$(CLUSTER)"; then \
		printf '[operator-kind-setup] using existing kind cluster %s\n' "$(CLUSTER)"; \
	elif [ "$(CREATE_CLUSTER)" = "1" ]; then \
		printf '[operator-kind-setup] creating kind cluster %s\n' "$(CLUSTER)"; \
		kind create cluster --name "$(CLUSTER)"; \
	else \
		printf '[operator-kind-setup] ERROR: kind cluster %s does not exist and CREATE_CLUSTER is not 1\n' "$(CLUSTER)" >&2; \
		exit 1; \
	fi

operator-kind-images: operator-kind-cluster runtime-build broker-build operator-build
	@printf '[operator-kind-setup] loading local images into kind cluster %s\n' "$(CLUSTER)"
	kind load docker-image nvt-agent-runtime:latest --name "$(CLUSTER)"
	kind load docker-image nvt-broker:latest --name "$(CLUSTER)"
	kind load docker-image nvt-operator:latest --name "$(CLUSTER)"

operator-kind-install: operator-kind-images $(OPERATOR_KIND_EXTRA_IMAGE_TARGETS)
	@printf '[operator-kind-setup] installing chart into namespace %s\n' "$(NAMESPACE)"
	helm upgrade --install nvt charts/nvt \
		--kube-context "$(KUBECTL_CONTEXT)" \
		-n "$(NAMESPACE)" \
		--create-namespace \
		--wait \
		--timeout "$(ROLLOUT_TIMEOUT)" \
		$(OPERATOR_KIND_GATEWAY_HELM_ARGS) \
		$(OPERATOR_KIND_HELM_ARGS)
	kubectl --context "$(KUBECTL_CONTEXT)" rollout status deployment/nvt-broker -n "$(NAMESPACE)" --timeout="$(ROLLOUT_TIMEOUT)"
	kubectl --context "$(KUBECTL_CONTEXT)" rollout status deployment/nvt-operator -n "$(NAMESPACE)" --timeout="$(ROLLOUT_TIMEOUT)"
	@if [ "$(OPERATOR_KIND_GATEWAY)" = "1" ]; then \
		kubectl --context "$(KUBECTL_CONTEXT)" rollout status deployment/nvt-agent-gateway -n "$(NAMESPACE)" --timeout="$(ROLLOUT_TIMEOUT)"; \
	fi

operator-kind-setup: operator-kind-install

operator-kind-delete:
	kind delete cluster --name "$(CLUSTER)"

operator-kind-smoke:
	bash tests/operator/kind/smoke.sh

operator-kind-smoke-render:
	KIND_SMOKE_MODE=render bash tests/operator/kind/smoke.sh

gateway-kind-load: operator-kind-cluster gateway-build
	@printf '[operator-kind-setup] loading gateway image %s into kind cluster %s\n' "$(GATEWAY_IMAGE)" "$(CLUSTER)"
	kind load docker-image "$(GATEWAY_IMAGE)" --name "$(CLUSTER)"

producer-kind-load: operator-kind-cluster producer-build
	@printf '[producer-kind-setup] loading producer image %s into kind cluster %s\n' "$(PRODUCER_IMAGE)" "$(CLUSTER)"
	kind load docker-image "$(PRODUCER_IMAGE)" --name "$(CLUSTER)"

producer-kind-install:
	@test -f "$(PRODUCER_VALUES)" || (echo "[producer-kind-setup] ERROR: PRODUCER_VALUES file does not exist: $(PRODUCER_VALUES). Create a local values file, for example values.github-comments.yaml, or pass PRODUCER_VALUES=<path>." >&2; exit 1)
	@printf '[producer-kind-setup] installing producer chart %s into namespace %s using %s\n' "$(PRODUCER_RELEASE)" "$(NAMESPACE)" "$(PRODUCER_VALUES)"
	helm upgrade --install "$(PRODUCER_RELEASE)" "$(PRODUCER_CHART)" \
		--kube-context "$(KUBECTL_CONTEXT)" \
		-n "$(NAMESPACE)" \
		--create-namespace \
		-f "$(PRODUCER_VALUES)" \
		--wait \
		--timeout "$(ROLLOUT_TIMEOUT)"

producer-kind-setup: producer-kind-load producer-kind-install

operator-codex-auth-secret:
	CODEX_AUTH_SOURCE="$(CODEX_AUTH_SOURCE)" CODEX_AUTH_SECRET="$(CODEX_AUTH_SECRET)" SOURCE="$(SOURCE)" SECRET="$(SECRET)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" bash scripts/operator-codex-auth-secret.sh

github-comments-producer-secret:
	GITHUB_APP_PRIVATE_KEY_FILE="$(GITHUB_APP_PRIVATE_KEY_FILE)" PRODUCER_GITHUB_APP_SECRET="$(PRODUCER_GITHUB_APP_SECRET)" PRODUCER_GITHUB_APP_KEY="$(PRODUCER_GITHUB_APP_KEY)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" bash scripts/github-comments-producer-secret.sh

broker-env-secret:
	BROKER_ENV_FILE="$(BROKER_ENV_FILE)" BROKER_ENV_SECRET="$(BROKER_ENV_SECRET)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" bash scripts/broker-env-secret.sh

operator-smoke-schedule:
	@test -n "$(NAME)" || (echo "usage: make operator-smoke-schedule NAME=<name> [CLUSTER=nvt-smoke] [NAMESPACE=nvt]"; exit 1)
	NAME="$(NAME)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" ACTIVE_DEADLINE_SECONDS="$(ACTIVE_DEADLINE_SECONDS)" COMPLETED_TTL_SECONDS="$(COMPLETED_TTL_SECONDS)" SMOKE_DELAY_SECONDS="$(SMOKE_DELAY_SECONDS)" bash tests/operator/kind/smoke-scheduler-job.sh apply

infra-up:
	bash scripts/infra-up.sh

infra-down:
	bash scripts/infra-down.sh

infra-network-rm:
	bash scripts/infra-network-rm.sh

agent-init:
	@test -n "$(NAME)" || (echo "usage: make agent-init NAME=<name> [TYPE=codex|claude] [AUTONOMY=trusted-local|interactive]"; exit 1)
	bash scripts/agent-init.sh --name "$(NAME)" --type "$(TYPE)" --autonomy "$(AUTONOMY)"

agent-copy agent-cp:
	@test -n "$(FROM)" || (echo "usage: make $@ FROM=<source> TO=<target> [COPY_GRANTS=0] [COPY_WORKSPACE=1] [COPY_AUTH=1] [FORCE=1]"; exit 1)
	@test -n "$(TO)" || (echo "usage: make $@ FROM=<source> TO=<target> [COPY_GRANTS=0] [COPY_WORKSPACE=1] [COPY_AUTH=1] [FORCE=1]"; exit 1)
	bash scripts/agent-copy.sh --from "$(FROM)" --to "$(TO)" $(if $(FORCE),--force) $(if $(filter 0 false no,$(COPY_GRANTS)),--no-copy-grants) $(if $(filter 1 true yes,$(COPY_WORKSPACE)),--copy-workspace) $(if $(filter 1 true yes,$(COPY_AUTH)),--copy-auth) $(if $(filter 0 false no,$(COPY_AUTH)),--no-copy-auth)

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

agent-forward forward:
	@test -n "$(NAME)" || (echo "usage: make forward NAME=<name> PORT=<remote-port> [LOCAL=<local-port>]"; exit 1)
	@test -n "$(PORT)" || (echo "usage: make forward NAME=<name> PORT=<remote-port> [LOCAL=<local-port>]"; exit 1)
	bash scripts/agent-forward.sh --name "$(NAME)" --port "$(PORT)" $(if $(LOCAL),--local "$(LOCAL)")

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
