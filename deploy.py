#!/usr/bin/env python3
"""Builds the erratas image and (re)creates erratas-pod with podman.

Standalone on purpose: it doesn't touch dewey-pod or deploy.py.
"""

import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
POD = "erratas-pod"
IMAGE = "erratas"
PORT = "9000"


def podman(*args):
    subprocess.run(["podman", *args], check=True)


def main():
    podman("build", "-t", IMAGE, "-f", str(HERE / "Containerfile"), str(HERE))

    # Drop any previous copy of the pod (and its container) before recreating.
    subprocess.run(["podman", "pod", "rm", "-f", POD], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    podman("pod", "create", "--name", POD, "-p", f"{PORT}:{PORT}")

    # Read-only root fs with a tmpfs /app-writable area would break uploads
    # (they land in the working dir), so only lock down what's safe.
    # --log-driver=journald sends stdout/stderr to the system journal, so logs
    # survive container removal (the `pod rm -f` above) and redeploys. Read
    # them with: journalctl CONTAINER_NAME=erratas
    podman("run", "-d", "--name", "erratas", "--pod", POD,
           "--cap-drop=ALL", "--security-opt=no-new-privileges",
           "--log-driver=journald",
           IMAGE)

    print(f"{POD} is up; Erratas is listening on port {PORT}")


if __name__ == "__main__":
    main()
