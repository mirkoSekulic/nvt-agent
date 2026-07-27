# Execution-driver host image

`nvt-execution-driver-host` is a coordinated static transport binary. The
chart runs this image only as an init container and atomically copies the
binary into a private `emptyDir`. The main container uses the administrator's
complete, digest-pinned provider image and starts the copied host as PID 1.
The host then executes the provider image's explicit absolute driver command
through the `nvt.execution-driver/v1` JSONL supervisor.

Provider images may use any implementation language, but must:

- include the complete runtime, libraries, and executable in the image;
- run as non-root with a read-only root filesystem and a writable `/tmp`;
- implement the frozen execution-driver protocol on stdin/stdout; and
- need no clone, build, package installation, hook, or source acquisition at
  startup.

The host's HTTPS API uses a per-registration TLS CA and bearer token. Those are
transport credentials, not provider credentials. Provider infrastructure
credentials are projected only into the matching main container and are
copied into the driver child environment only when explicitly allowlisted.
