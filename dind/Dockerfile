FROM docker:27-dind

# Kata commonly exposes the container root filesystem through virtiofs. The
# sidecar prepares an ext4 loopback filesystem before dockerd starts, so bake
# the filesystem/loop tooling into the coordinated image instead of fetching
# packages during every AgentRun startup.
RUN apk add --no-cache coreutils e2fsprogs python3 util-linux

# nvt-dind-entrypoint hands startup back to the base image's Docker entrypoint
# so the upstream cgroup-v2 nesting setup still runs. Fail the build instead of
# reimplementing that setup if the base image ever stops shipping it.
RUN test -x /usr/local/bin/dockerd-entrypoint.sh \
 && test -x /usr/local/bin/dind

COPY dind/nvt-dind-entrypoint.sh /usr/local/bin/nvt-dind-entrypoint
COPY dind/nvt-dind-ready.sh /usr/local/bin/nvt-dind-ready
COPY dind/validate-managed-cidrs.sh /usr/local/bin/nvt-validate-managed-cidrs

RUN chmod 0755 /usr/local/bin/nvt-dind-entrypoint /usr/local/bin/nvt-dind-ready /usr/local/bin/nvt-validate-managed-cidrs

ENTRYPOINT ["/usr/local/bin/nvt-dind-entrypoint"]
