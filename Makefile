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
BROKER_ENV_FILE ?= .nvt-local/secrets/broker-env
BROKER_ENV_SECRET ?= nvt-broker-env
PRODUCER_IMAGE ?= nvt-github-comments-producer:latest
GATEWAY_IMAGE ?= nvt-agent-gateway:latest
CREDENTIAL_PORTAL_IMAGE ?= nvt-credential-portal:latest
EGRESSD_IMAGE ?= nvt-egressd:latest
CAPTURED_IMAGE ?= nvt-captured:latest
NATIVE_EGRESS_RELAY_IMAGE ?= nvt-native-egress-relay:latest
DIND_IMAGE ?= nvt-dind:latest
ECHO_IMAGE ?= nvt-smoke-echo:latest
PRODUCER_VALUES ?= values.nvt-local.yaml
PRODUCER_RELEASE ?= nvt
PRODUCER_CHART ?= charts/nvt
CREATE_CLUSTER ?= 1
ROLLOUT_TIMEOUT ?= 180s
KUBECTL_CONTEXT ?= kind-$(CLUSTER)
KIND_CLUSTER_CONFIG ?=
CALICO_VERSION ?= v3.28.2
CALICO_MANIFEST ?= https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests/calico.yaml
OPERATOR_KIND_HELM_ARGS ?=
OPERATOR_KIND_LOCAL_IMAGE_ARGS := --set runtime.image.repository=nvt-agent-runtime --set runtime.image.tag=latest --set dind.image.repository=$(word 1,$(subst :, ,$(DIND_IMAGE))) --set dind.image.tag=$(word 2,$(subst :, ,$(DIND_IMAGE))) --set broker.image.repository=nvt-broker --set broker.image.tag=latest --set egress.egressd.image.repository=$(word 1,$(subst :, ,$(EGRESSD_IMAGE))) --set egress.egressd.image.tag=$(word 2,$(subst :, ,$(EGRESSD_IMAGE))) --set egress.captured.image.repository=$(word 1,$(subst :, ,$(CAPTURED_IMAGE))) --set egress.captured.image.tag=$(word 2,$(subst :, ,$(CAPTURED_IMAGE))) --set operator.image.repository=nvt-operator --set operator.image.tag=latest
OPERATOR_KIND_GATEWAY ?= 0
LOCAL_MANIFEST ?= nvt.local.yaml

ifeq ($(OPERATOR_KIND_GATEWAY),1)
OPERATOR_KIND_EXTRA_IMAGE_TARGETS := gateway-kind-load
OPERATOR_KIND_GATEWAY_HELM_ARGS := --set gateway.enabled=true --set gateway.image.repository=$(word 1,$(subst :, ,$(GATEWAY_IMAGE))) --set gateway.image.tag=$(word 2,$(subst :, ,$(GATEWAY_IMAGE)))
endif

.PHONY: runtime-build dind-build broker-build local-controller-build egressd-build captured-build native-egress-relay-build transparent-compose-smoke echo-build echo-kind-load operator-build execution-driver-host-build qemu-execution-driver-build qemu-execution-driver-test azure-execution-driver-build azure-execution-driver-test host-bundle-build host-bundle-test eligibility-test guest-enrollment-test producer-build gateway-build credential-portal-build operator-helm-test operator-kind-cluster operator-kind-cluster-enforced operator-kind-images operator-kind-install operator-kind-setup operator-kind-delete operator-kind-smoke operator-kind-smoke-render gateway-kind-load producer-kind-load producer-kind-install producer-kind-setup operator-codex-auth-secret codex-mediated-proof github-comments-producer-secret broker-env-secret operator-smoke-schedule local-images local-init local-up local-status local-down local-reset plugin-init

runtime-build:
	bash scripts/runtime-build.sh $(if $(NO_CACHE),--no-cache)

dind-build:
	docker build -f dind/Dockerfile -t "$(DIND_IMAGE)" .

broker-build:
	bash scripts/broker-build.sh

local-controller-build:
	bash scripts/local-controller-build.sh

egressd-build:
	docker build -f egressd/Dockerfile -t "$(EGRESSD_IMAGE)" .

captured-build:
	docker build -f captured/Dockerfile -t "$(CAPTURED_IMAGE)" .

native-egress-relay-build:
	docker build -f nativeegressrelay/Dockerfile -t "$(NATIVE_EGRESS_RELAY_IMAGE)" .

transparent-compose-smoke:
	bash tests/runtime/compose-transparent-smoke.sh

operator-build:
	bash scripts/operator-build.sh $(if $(NO_CACHE),--no-cache)

execution-driver-host-build:
	docker build -f operator/executiondriver/host-image/Dockerfile -t nvt-execution-driver-host:latest .

qemu-execution-driver-build:
	docker build -f executiondrivers/qemu/Dockerfile -t nvt-qemu-execution-driver:latest .

qemu-execution-driver-test:
	cd executiondrivers/qemu && go vet ./... && go test -race -count=1 ./...

azure-execution-driver-build:
	docker build -f executiondrivers/azure/Dockerfile -t nvt-azure-execution-driver:latest .

azure-execution-driver-test:
	cd executiondrivers/azure && go vet ./... && go test -race -count=1 ./...
	BICEP=$${BICEP:-/tmp/bicep} bash executiondrivers/azure/bicep-check.sh

host-bundle-build:
	bash hostbundle/build.sh "$${NVT_HOST_BUNDLE_VERSION:?set NVT_HOST_BUNDLE_VERSION}" "$${NVT_HOST_BUNDLE_REVISION:?set NVT_HOST_BUNDLE_REVISION}"

host-bundle-test:
	cd hostbundle && go vet ./... && go test -race -count=1 ./...
	bash hostbundle/build-test.sh

eligibility-test:
	cd protocol/eligibility && go vet ./... && go test -race -count=1 ./...

resolved-run-test:
	cd protocol/resolvedrun && go vet ./... && go test -race -count=1 ./...

guest-enrollment-test:
	cd protocol/guestenrollment && go vet ./... && go test -race -count=1 ./...

producer-build:
	docker build -f producers/github-comments/Dockerfile -t "$(PRODUCER_IMAGE)" .

gateway-build:
	docker build -f gateway/Dockerfile -t "$(GATEWAY_IMAGE)" .

credential-portal-build:
	docker build -f credentialportal/Dockerfile -t "$(CREDENTIAL_PORTAL_IMAGE)" .

echo-build:
	docker build -f tests/fixtures/echo/Dockerfile -t "$(ECHO_IMAGE)" .

# Hermetic upstream fixture for the kind egress smokes (quota, revocation,
# enforced-egress). Loaded into the active $(CLUSTER) after it exists; the
# smoke case creates the cluster first, so this does not depend on
# operator-kind-cluster.
echo-kind-load: echo-build
	@printf '[operator-kind-setup] loading echo fixture image %s into kind cluster %s\n' "$(ECHO_IMAGE)" "$(CLUSTER)"
	kind load docker-image "$(ECHO_IMAGE)" --name "$(CLUSTER)"

operator-helm-test:
	bash tests/operator/helm/test.sh

operator-kind-cluster:
	@if kind get clusters | grep -Fxq "$(CLUSTER)"; then \
		printf '[operator-kind-setup] using existing kind cluster %s\n' "$(CLUSTER)"; \
	elif [ "$(CREATE_CLUSTER)" = "1" ]; then \
		printf '[operator-kind-setup] creating kind cluster %s\n' "$(CLUSTER)"; \
		tests/operator/kind/kind-command.sh kind create cluster --name "$(CLUSTER)" $(if $(KIND_CLUSTER_CONFIG),--config "$(KIND_CLUSTER_CONFIG)"); \
	else \
		printf '[operator-kind-setup] ERROR: kind cluster %s does not exist and CREATE_CLUSTER is not 1\n' "$(CLUSTER)" >&2; \
		exit 1; \
	fi

# Enforcement smokes need a NetworkPolicy-enforcing CNI: kindnet does not
# enforce policies, so this target creates the cluster without a default CNI
# and installs a pinned Calico.
operator-kind-cluster-enforced:
	$(MAKE) CLUSTER="$(CLUSTER)" CREATE_CLUSTER="$(CREATE_CLUSTER)" KIND_CLUSTER_CONFIG=tests/operator/kind/kind-calico.yaml operator-kind-cluster
	@if ! kubectl --context "$(KUBECTL_CONTEXT)" get daemonset calico-node -n kube-system >/dev/null 2>&1; then \
		printf '[operator-kind-setup] installing Calico %s\n' "$(CALICO_VERSION)"; \
		kubectl --context "$(KUBECTL_CONTEXT)" apply -f "$(CALICO_MANIFEST)"; \
	fi
	kubectl --context "$(KUBECTL_CONTEXT)" rollout status daemonset/calico-node -n kube-system --timeout="$(ROLLOUT_TIMEOUT)"

operator-kind-images: operator-kind-cluster runtime-build dind-build broker-build egressd-build captured-build operator-build
	@printf '[operator-kind-setup] loading local images into kind cluster %s\n' "$(CLUSTER)"
	kind load docker-image nvt-agent-runtime:latest --name "$(CLUSTER)"
	kind load docker-image "$(DIND_IMAGE)" --name "$(CLUSTER)"
	kind load docker-image nvt-broker:latest --name "$(CLUSTER)"
	kind load docker-image "$(EGRESSD_IMAGE)" --name "$(CLUSTER)"
	kind load docker-image "$(CAPTURED_IMAGE)" --name "$(CLUSTER)"
	kind load docker-image nvt-operator:latest --name "$(CLUSTER)"

operator-kind-install: operator-kind-images $(OPERATOR_KIND_EXTRA_IMAGE_TARGETS)
	@printf '[operator-kind-setup] installing chart into namespace %s\n' "$(NAMESPACE)"
	helm upgrade --install nvt charts/nvt \
		--kube-context "$(KUBECTL_CONTEXT)" \
		-n "$(NAMESPACE)" \
		--create-namespace \
		--wait \
		--timeout "$(ROLLOUT_TIMEOUT)" \
		$(OPERATOR_KIND_LOCAL_IMAGE_ARGS) \
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
	@test -f "$(PRODUCER_VALUES)" || (echo "[producer-kind-setup] ERROR: complete consolidated chart values file does not exist: $(PRODUCER_VALUES). Create values.nvt-local.yaml as documented, or pass PRODUCER_VALUES=<path-to-complete-nvt-values>." >&2; exit 1)
	@printf '[producer-kind-setup] installing producer chart %s into namespace %s using %s\n' "$(PRODUCER_RELEASE)" "$(NAMESPACE)" "$(PRODUCER_VALUES)"
	helm upgrade --install "$(PRODUCER_RELEASE)" "$(PRODUCER_CHART)" \
		--kube-context "$(KUBECTL_CONTEXT)" \
		-n "$(NAMESPACE)" \
		--create-namespace \
		--reset-values \
		$(OPERATOR_KIND_LOCAL_IMAGE_ARGS) \
		--set producer.image.repository=$(word 1,$(subst :, ,$(PRODUCER_IMAGE))) \
		--set producer.image.tag=$(word 2,$(subst :, ,$(PRODUCER_IMAGE))) \
		--set producer.enabled=true \
		-f "$(PRODUCER_VALUES)" \
		--wait \
		--timeout "$(ROLLOUT_TIMEOUT)"

producer-kind-setup: producer-kind-load producer-kind-install

operator-codex-auth-secret:
	CODEX_AUTH_SOURCE="$(CODEX_AUTH_SOURCE)" CODEX_AUTH_SECRET="$(CODEX_AUTH_SECRET)" SOURCE="$(SOURCE)" SECRET="$(SECRET)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" bash scripts/operator-codex-auth-secret.sh

# Manual, opt-in real-Codex mediated-auth proof (docs/codex-auth.md).
# NOT run in CI: needs real host Codex auth. Writes evidence to .proof-out/codex/.
codex-mediated-proof:
	CODEX_AUTH_SOURCE="$(CODEX_AUTH_SOURCE)" CODEX_AUTH_SECRET="$(CODEX_AUTH_SECRET)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" ROLLOUT_TIMEOUT="$(ROLLOUT_TIMEOUT)" bash scripts/codex-mediated-proof.sh

github-comments-producer-secret:
	GITHUB_APP_PRIVATE_KEY_FILE="$(GITHUB_APP_PRIVATE_KEY_FILE)" PRODUCER_GITHUB_APP_SECRET="$(PRODUCER_GITHUB_APP_SECRET)" PRODUCER_GITHUB_APP_KEY="$(PRODUCER_GITHUB_APP_KEY)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" bash scripts/github-comments-producer-secret.sh

broker-env-secret:
	BROKER_ENV_FILE="$(BROKER_ENV_FILE)" BROKER_ENV_SECRET="$(BROKER_ENV_SECRET)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" bash scripts/broker-env-secret.sh

operator-smoke-schedule:
	@test -n "$(NAME)" || (echo "usage: make operator-smoke-schedule NAME=<name> [CLUSTER=nvt-smoke] [NAMESPACE=nvt]"; exit 1)
	NAME="$(NAME)" NAMESPACE="$(NAMESPACE)" CLUSTER="$(CLUSTER)" KUBECTL_CONTEXT="$(KUBECTL_CONTEXT)" ACTIVE_DEADLINE_SECONDS="$(ACTIVE_DEADLINE_SECONDS)" COMPLETED_TTL_SECONDS="$(COMPLETED_TTL_SECONDS)" SMOKE_DELAY_SECONDS="$(SMOKE_DELAY_SECONDS)" bash tests/operator/kind/smoke-scheduler-job.sh apply

local-images: runtime-build dind-build broker-build local-controller-build gateway-build credential-portal-build egressd-build captured-build producer-build

local-init:
	cd localplatform && NVT_LOCAL_MANIFEST="../$(LOCAL_MANIFEST)" go run ./cmd/nvt-local init

local-up:
	cd localplatform && NVT_LOCAL_MANIFEST="../$(LOCAL_MANIFEST)" go run ./cmd/nvt-local up

local-status:
	cd localplatform && go run ./cmd/nvt-local status

local-down:
	cd localplatform && go run ./cmd/nvt-local down

local-reset:
	cd localplatform && go run ./cmd/nvt-local reset

plugin-init:
	@test -n "$(NAME)" || (echo "usage: make plugin-init NAME=<name> [DIR=runtime/plugins]"; exit 1)
	bash scripts/plugin-init.sh --name "$(NAME)" --dir "$(DIR)"
