FROM docker:27-dind

# Kata commonly exposes the container root filesystem through virtiofs. The
# sidecar prepares an ext4 loopback filesystem before dockerd starts, so bake
# the filesystem/loop tooling into the coordinated image instead of fetching
# packages during every AgentRun startup.
RUN apk add --no-cache coreutils e2fsprogs nftables util-linux

COPY dind/nvt-dind-entrypoint.sh /usr/local/bin/nvt-dind-entrypoint
COPY dind/nvt-dind-ready.sh /usr/local/bin/nvt-dind-ready

RUN chmod 0755 /usr/local/bin/nvt-dind-entrypoint /usr/local/bin/nvt-dind-ready

ENTRYPOINT ["/usr/local/bin/nvt-dind-entrypoint"]
