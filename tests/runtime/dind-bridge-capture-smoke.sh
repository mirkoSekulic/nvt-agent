#!/usr/bin/env bash
set -euo pipefail

IMAGE="${NVT_DIND_TEST_IMAGE:-nvt-dind:latest}"
DAEMON="nvt-dind-bridge-capture-${RANDOM}"

cleanup() {
  docker rm -f "${DAEMON}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --privileged --name "${DAEMON}" "${IMAGE}" --tls=false >/dev/null
for _ in $(seq 1 30); do
  if docker exec "${DAEMON}" docker info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${DAEMON}" docker info >/dev/null
docker exec "${DAEMON}" docker pull busybox:1.36 >/dev/null

start_fixture() {
  local network="$1"
  local server="$2"
  docker exec "${DAEMON}" docker network create "${network}" >/dev/null
  docker exec "${DAEMON}" docker run -d --name "${server}" --network "${network}" busybox:1.36 \
    sh -ec 'mkdir -p /tmp/www; echo bridge-ok >/tmp/www/index.html; exec httpd -f -p 8080 -h /tmp/www' >/dev/null
  for _ in $(seq 1 20); do
    if [[ "$(docker exec "${DAEMON}" docker run --rm --network "${network}" busybox:1.36 \
      wget -q -T 1 -O- "http://${server}:8080/" 2>/dev/null || true)" == "bridge-ok" ]]; then
      return
    fi
    sleep 1
  done
  echo "same-bridge fixture did not become ready" >&2
  exit 1
}

bridge_request() {
  local network="$1"
  local server="$2"
  docker exec "${DAEMON}" docker run --rm --network "${network}" busybox:1.36 \
    wget -q -T 3 -O- "http://${server}:8080/"
}

rule_packets() {
  local pattern="$1"
  docker exec "${DAEMON}" nft list chain ip nat NVT_DIND | awk -v pattern="${pattern}" '
    index($0, pattern) {
      for (i = 1; i <= NF; i++) {
        if ($i == "packets") { print $(i + 1); exit }
      }
    }
  '
}

# Prove the baseline before installing capture rules.
start_fixture nvt_before nvt_before_server
[[ "$(bridge_request nvt_before nvt_before_server)" == "bridge-ok" ]]
docker exec "${DAEMON}" docker run --rm --network nvt_before busybox:1.36 \
  wget -q -T 10 -O /dev/null http://example.com/

# This is the production rule order. FIB output-interface classification is
# available in nat PREROUTING even though physdev bridge metadata is not.
docker exec "${DAEMON}" sh -ec '
  sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
  iptables -t nat -N NVT_DIND
  nft add rule ip nat NVT_DIND iifname "docker0" fib daddr oifname "docker0" counter return
  nft add rule ip nat NVT_DIND iifname "br-*" fib daddr oifname "br-*" counter return
  iptables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
  iptables -t nat -A NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
  iptables -t nat -I PREROUTING 1 -j NVT_DIND
'

# Existing and post-init dynamic bridges both retain local service traffic.
[[ "$(bridge_request nvt_before nvt_before_server)" == "bridge-ok" ]]
start_fixture nvt_after nvt_after_server
[[ "$(bridge_request nvt_after nvt_after_server)" == "bridge-ok" ]]
local_packets="$(rule_packets 'fib daddr oifname "br-*"')"
[[ "${local_packets:-0}" -gt 0 ]]

# Routed traffic from the exact post-init bridge must hit the redirect. There
# is intentionally no listener on 15001 in this isolated proof, so both calls
# fail closed and increment the capture rule counter.
redirect_before="$(rule_packets 'iifname "br-*" ip protocol tcp')"
if docker exec "${DAEMON}" docker run --rm --network nvt_after busybox:1.36 \
  wget -q -T 3 -O /dev/null http://example.com/; then
  echo "dynamic-bridge external traffic bypassed capture" >&2
  exit 1
fi
redirect_external="$(rule_packets 'iifname "br-*" ip protocol tcp')"
[[ "${redirect_external:-0}" -gt "${redirect_before:-0}" ]]

if docker exec "${DAEMON}" docker run --rm --network nvt_after busybox:1.36 \
  wget -q -T 3 -O /dev/null http://169.254.169.254/; then
  echo "dynamic-bridge metadata traffic bypassed capture" >&2
  exit 1
fi
redirect_metadata="$(rule_packets 'iifname "br-*" ip protocol tcp')"
[[ "${redirect_metadata:-0}" -gt "${redirect_external:-0}" ]]

printf 'DinD bridge capture smoke passed (local=%s external=%s metadata=%s)\n' \
  "${local_packets}" "${redirect_external}" "${redirect_metadata}"
