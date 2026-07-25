#!/usr/bin/env bash
set -euo pipefail

IMAGE="${NVT_DIND_TEST_IMAGE:-nvt-dind:latest}"
DAEMON="nvt-dind-bridge-capture-${RANDOM}"

cleanup() {
  docker rm -f "${DAEMON}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --privileged --name "${DAEMON}" \
  -e NVT_DIND_TRANSPARENT=true \
  -v /lib/modules:/lib/modules:ro "${IMAGE}" --tls=false >/dev/null
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

routed_bridge_request() {
  local network="$1"
  local server="$2"
  local nested_address="$3"
  local server_address
  server_address="$(docker exec "${DAEMON}" docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${server}")"
  docker exec "${DAEMON}" docker run --rm --privileged --network "${network}" \
    -e NVT_PEER_ADDRESS="${server_address}" -e NVT_NESTED_ADDRESS="${nested_address}" busybox:1.36 \
    sh -ec 'ip route add "${NVT_NESTED_ADDRESS}/32" via "${NVT_PEER_ADDRESS}"; wget -q -T 3 -O- "http://${NVT_NESTED_ADDRESS}:8080/"'
}

routed_bridge_request_v6() {
  local network="$1"
  local server="$2"
  local nested_address="$3"
  local server_address
  server_address="$(docker exec "${DAEMON}" docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "${server}")"
  docker exec "${DAEMON}" docker run --rm --privileged --network "${network}" \
    -e NVT_PEER_ADDRESS="${server_address}" -e NVT_NESTED_ADDRESS="${nested_address}" busybox:1.36 \
    sh -ec 'ip -6 route add "${NVT_NESTED_ADDRESS}/128" via "${NVT_PEER_ADDRESS}"; wget -q -T 3 -O- "http://[${NVT_NESTED_ADDRESS}]:8080/"'
}

rule_packets() {
  docker exec "${DAEMON}" iptables -t nat -L NVT_DIND -v -n | awk '/REDIRECT.*15001/ {sum += $1} END {print sum + 0}'
}

rule_packets_v6() {
  docker exec "${DAEMON}" ip6tables -t nat -L NVT_DIND -v -n | awk '/REDIRECT.*15001/ {sum += $1} END {print sum + 0}'
}

# Prove the baseline before installing capture rules.
start_fixture nvt_before nvt_before_server
[[ "$(bridge_request nvt_before nvt_before_server)" == "bridge-ok" ]]
docker exec "${DAEMON}" docker run --rm --network nvt_before busybox:1.36 \
  wget -q -T 10 -O /dev/null http://example.com/

# Exercise the production sysctl semantics before installing normal
# bridge-originated PREROUTING redirects.
docker exec "${DAEMON}" sh -ec '
  if [ ! -e /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    modprobe br_netfilter
  fi
  test -e /proc/sys/net/bridge/bridge-nf-call-iptables
  test -e /proc/sys/net/bridge/bridge-nf-call-ip6tables
  sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
  sysctl -w net.bridge.bridge-nf-call-ip6tables=1 >/dev/null
  /usr/local/bin/nvt-disable-bridge-netfilter
  test "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = 0
  test "$(cat /proc/sys/net/bridge/bridge-nf-call-ip6tables)" = 0
  iptables -t nat -N NVT_DIND
  iptables -t nat -A NVT_DIND -d 172.30.0.0/15 -m comment --comment nvt-local-docker -j RETURN
  iptables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
  iptables -t nat -A NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
  iptables -t nat -I PREROUTING 1 -j NVT_DIND
  ip6tables -t nat -N NVT_DIND
  ip6tables -t nat -A NVT_DIND -i docker0 -p tcp -j REDIRECT --to-ports 15001
  ip6tables -t nat -A NVT_DIND -i br-+ -p tcp -j REDIRECT --to-ports 15001
  ip6tables -t nat -I PREROUTING 1 -j NVT_DIND
'

# Existing and post-init dynamic bridges both retain local service traffic.
[[ "$(bridge_request nvt_before nvt_before_server)" == "bridge-ok" ]]
start_fixture nvt_after nvt_after_server
[[ "$(bridge_request nvt_after nvt_after_server)" == "bridge-ok" ]]
docker exec "${DAEMON}" iptables -t nat -C NVT_DIND -d 172.30.0.0/15 -m comment --comment nvt-local-docker -j RETURN

# Model two nested-system nodes on a managed Docker bridge. The destination is
# a separately routed workload address, so the managed-pool destination return
# cannot preserve it; disabling bridge-to-inet hooks keeps it at L2.
docker exec "${DAEMON}" docker network create nvt_routed >/dev/null
docker exec "${DAEMON}" docker run -d --privileged --name nvt_routed_server --network nvt_routed \
  busybox:1.36 sh -ec 'ip addr add 192.0.2.154/32 dev lo; mkdir -p /tmp/www; echo routed-bridge-ok >/tmp/www/index.html; exec httpd -f -p 8080 -h /tmp/www' >/dev/null
for _ in $(seq 1 20); do
  if [[ "$(routed_bridge_request nvt_routed nvt_routed_server 192.0.2.154 2>/dev/null || true)" == "routed-bridge-ok" ]]; then
    break
  fi
  sleep 1
done
[[ "$(routed_bridge_request nvt_routed nvt_routed_server 192.0.2.154)" == "routed-bridge-ok" ]]

# The same bridge classification is consumed by IPv6 PREROUTING without a
# destination-range exception.
docker exec "${DAEMON}" docker network create --ipv6 --subnet fd00:31::/64 nvt_routed_v6 >/dev/null
docker exec "${DAEMON}" docker run -d --privileged --name nvt_routed_server_v6 --network nvt_routed_v6 \
  busybox:1.36 sh -ec 'ip -6 addr add 2001:db8:154::2/128 dev lo; mkdir -p /tmp/www; echo routed-v6-ok >/tmp/www/index.html; exec httpd -f -p 8080 -h /tmp/www' >/dev/null
for _ in $(seq 1 20); do
  if [[ "$(routed_bridge_request_v6 nvt_routed_v6 nvt_routed_server_v6 2001:db8:154::2 2>/dev/null || true)" == "routed-v6-ok" ]]; then
    break
  fi
  sleep 1
done
[[ "$(routed_bridge_request_v6 nvt_routed_v6 nvt_routed_server_v6 2001:db8:154::2)" == "routed-v6-ok" ]]

# Host-directed IPv6 traffic on that exact bridge remains routed and must hit
# the normal ip6tables PREROUTING redirect.
docker exec "${DAEMON}" docker run -d --name nvt_routed_client_v6 --privileged --network nvt_routed_v6 busybox:1.36 sleep 300 >/dev/null
gateway_v6="$(docker exec "${DAEMON}" docker exec nvt_routed_client_v6 sh -ec 'ip -6 route show default | awk "{print \$3; exit}"')"
[[ -n "${gateway_v6}" ]]
docker exec "${DAEMON}" docker exec nvt_routed_client_v6 \
  ip -6 route replace 2001:db8:ffff::1/128 via "${gateway_v6}"
redirect_v6_before="$(rule_packets_v6)"
if docker exec "${DAEMON}" docker exec nvt_routed_client_v6 \
  wget -q -T 3 -O /dev/null 'http://[2001:db8:ffff::1]/'; then
  echo "IPv6 external traffic bypassed capture" >&2
  exit 1
fi
redirect_v6_external="$(rule_packets_v6)"
[[ "${redirect_v6_external:-0}" -gt "${redirect_v6_before:-0}" ]]

docker exec "${DAEMON}" docker exec nvt_routed_client_v6 \
  ip -6 route replace fd00:ec2::254/128 via "${gateway_v6}"
if docker exec "${DAEMON}" docker exec nvt_routed_client_v6 \
  wget -q -T 3 -O /dev/null 'http://[fd00:ec2::254]/'; then
  echo "IPv6 protected traffic bypassed capture" >&2
  exit 1
fi
redirect_v6_protected="$(rule_packets_v6)"
[[ "${redirect_v6_protected:-0}" -gt "${redirect_v6_external:-0}" ]]
docker exec "${DAEMON}" docker rm -f nvt_routed_client_v6 >/dev/null

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

if docker exec "${DAEMON}" docker run --rm --network nvt_after busybox:1.36 \
  wget -q -T 3 -O /dev/null http://10.0.0.1/; then
  echo "dynamic-bridge private traffic bypassed capture" >&2
  exit 1
fi
redirect_private="$(rule_packets 'iifname "br-*" ip protocol tcp')"
[[ "${redirect_private:-0}" -gt "${redirect_metadata:-0}" ]]

printf 'DinD bridge capture smoke passed (routed-v4=ok routed-v6=ok external-v6=%s protected-v6=%s external=%s metadata=%s private=%s)\n' \
  "${redirect_v6_external}" "${redirect_v6_protected}" \
  "${redirect_external}" "${redirect_metadata}" "${redirect_private}"
