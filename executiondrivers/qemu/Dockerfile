# syntax=docker/dockerfile:1

ARG GUEST_PLATFORM=linux/amd64

FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS builder

ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY protocol/guestenrollment/go.mod protocol/guestenrollment/go.mod
COPY operator/go.mod operator/go.sum operator/
COPY executiondrivers/qemu/go.mod executiondrivers/qemu/
COPY hostbundle/go.mod hostbundle/go.mod
RUN cd /src/executiondrivers/qemu && go mod download
COPY protocol/guestenrollment/ protocol/guestenrollment/
COPY operator/executiondriver/ operator/executiondriver/
COPY executiondrivers/qemu/ executiondrivers/qemu/
COPY hostbundle/ hostbundle/
RUN cd /src/executiondrivers/qemu && CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/nvt-qemu-driver ./cmd/nvt-qemu-driver && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/nvt-qemu-guest-init ./cmd/nvt-qemu-guest-init && \
    cd /src/hostbundle && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o /out/nvt-host-bootstrap ./cmd/nvt-host-bootstrap

FROM --platform=${GUEST_PLATFORM} alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS guest-image
RUN apk add --no-cache \
      busybox ca-certificates e2fsprogs linux-virt python3 qemu-img tmux && \
    addgroup -g 65532 -S nvt-agent && \
    adduser -u 65532 -S -D -H -G nvt-agent nvt-agent
COPY --from=builder /out/nvt-qemu-guest-init /sbin/nvt-qemu-guest-init
COPY --from=builder /out/nvt-host-bootstrap /usr/local/bin/nvt-host-bootstrap
RUN rm -f /sbin/init && ln -s /sbin/nvt-qemu-guest-init /sbin/init && \
    mkdir -p /guest-root /out /workspace /run/nvt-agent /var/lib/nvt-agent /var/lib/nvt-enrollment && \
    chown 65532:65532 /workspace /run/nvt-agent /var/lib/nvt-agent && \
    chmod 0700 /var/lib/nvt-enrollment && \
    cp -a /bin /etc /lib /sbin /usr /var /guest-root/ && \
    mkdir -p /guest-root/dev /guest-root/proc /guest-root/sys /guest-root/run/nvt-agent /guest-root/workspace /guest-root/opt/nvt && \
    chown 65532:65532 /guest-root/run/nvt-agent /guest-root/workspace /guest-root/var/lib/nvt-agent && \
    truncate -s 768M /out/root.raw && \
    mke2fs -q -F -t ext4 -L nvt-guest -U 64b1e27d-2f2f-47ae-94e8-e474c1f135fb -d /guest-root /out/root.raw && \
    qemu-img convert -f raw -O qcow2 -c /out/root.raw /out/root.qcow2 && rm /out/root.raw && \
    cp "$(readlink -f /boot/vmlinuz-virt)" /out/vmlinuz && \
    cp "$(readlink -f /boot/initramfs-virt)" /out/initramfs && \
    chmod 0644 /out/vmlinuz /out/initramfs /out/root.qcow2 && \
    { for artifact in /out/vmlinuz /out/initramfs /out/root.qcow2; do printf '%s:' "$(stat -c %s "${artifact}")"; cat "${artifact}"; done; } \
      | sha256sum | awk '{print "sha256:" $1}' > /out/digest

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN apk add --no-cache qemu-img qemu-system-x86_64 && \
    addgroup -g 65532 -S nvt-driver && \
    adduser -u 65532 -S -D -H -G nvt-driver nvt-driver
COPY --from=builder /out/nvt-qemu-driver /usr/local/bin/nvt-qemu-driver
COPY --from=guest-image /out/vmlinuz /opt/nvt-qemu/guest/vmlinuz
COPY --from=guest-image /out/initramfs /opt/nvt-qemu/guest/initramfs
COPY --from=guest-image /out/root.qcow2 /opt/nvt-qemu/guest/root.qcow2
COPY --from=guest-image /out/digest /opt/nvt-qemu/guest/digest
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/nvt-qemu-driver"]
