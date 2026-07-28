#!/usr/bin/env python3
"""Extract one regular file from a single-platform OCI image archive."""

import io
import json
import pathlib
import sys
import tarfile


def fail(message):
    raise SystemExit(f"extract-oci-file: {message}")


if len(sys.argv) != 4:
    fail("usage: extract-oci-file.py <archive> <absolute-image-path> <output>")

archive_path, image_path, output_path = sys.argv[1:]
if not image_path.startswith("/") or ".." in pathlib.PurePosixPath(image_path).parts:
    fail("image path is invalid")
normalized = image_path.lstrip("/")

with tarfile.open(archive_path, "r:*") as archive:
    def read(name):
        member = archive.getmember(name)
        if not member.isfile():
            fail("OCI member is not a regular file")
        handle = archive.extractfile(member)
        if handle is None:
            fail("OCI member is unavailable")
        return handle.read()

    index = json.loads(read("index.json"))
    descriptors = index.get("manifests", [])
    if len(descriptors) != 1:
        fail("OCI root is ambiguous")
    descriptor = descriptors[0]
    while True:
        digest = descriptor.get("digest", "")
        if not digest.startswith("sha256:"):
            fail("OCI descriptor digest is invalid")
        document = json.loads(read("blobs/sha256/" + digest.removeprefix("sha256:")))
        if "layers" in document:
            layers = document["layers"]
            break
        manifests = document.get("manifests", [])
        if len(manifests) != 1:
            fail("OCI platform is ambiguous")
        descriptor = manifests[0]

    result = None
    for layer in layers:
        digest = layer.get("digest", "")
        if not digest.startswith("sha256:"):
            fail("OCI layer digest is invalid")
        layer_bytes = read("blobs/sha256/" + digest.removeprefix("sha256:"))
        with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer_archive:
            for member in layer_archive:
                name = member.name.removeprefix("./")
                if name == normalized:
                    if not member.isfile():
                        fail("selected image path is not a regular file")
                    handle = layer_archive.extractfile(member)
                    if handle is None:
                        fail("selected image path is unavailable")
                    result = handle.read()
                if pathlib.PurePosixPath(name).name == ".wh." + pathlib.PurePosixPath(normalized).name and pathlib.PurePosixPath(name).parent == pathlib.PurePosixPath(normalized).parent:
                    result = None

if result is None:
    fail("selected image path is absent")
pathlib.Path(output_path).write_bytes(result)
