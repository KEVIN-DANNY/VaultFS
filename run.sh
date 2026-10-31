#!/usr/bin/env bash
# Universal Runner for VaultFS (macOS / Linux)

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [ "$(uname -s)" = "Darwin" ]; then
    # Ensure Docker Desktop is active
    if ! docker info >/dev/null 2>&1; then
        echo "Starting Docker Desktop..."
        open -a Docker
        while ! docker info >/dev/null 2>&1; do
            sleep 1
        done
    fi

    # Build container image if needed
    if ! docker image inspect vaultfs >/dev/null 2>&1; then
        echo "Building VaultFS Docker container (first run only)..."
        docker build -t vaultfs .
    fi

    if [ $# -eq 0 ] || [ "$1" = "test" ] || [ "$1" = "demo" ]; then
        exec docker run --privileged --device /dev/fuse --cap-add SYS_ADMIN --rm -it -v "$DIR:/workspace/VaultFS" -w /workspace/VaultFS vaultfs bash test_demos.sh
    elif [ "$1" = "ransomware" ] || [ "$1" = "heal" ]; then
        exec docker run --privileged --device /dev/fuse --cap-add SYS_ADMIN --rm -it -v "$DIR:/workspace/VaultFS" -w /workspace/VaultFS vaultfs bash test_ransomware.sh
    elif [ "$1" = "research" ] || [ "$1" = "eval" ] || [ "$1" = "bench" ]; then
        exec docker run --privileged --device /dev/fuse --cap-add SYS_ADMIN --rm -it -v "$DIR:/workspace/VaultFS" -w /workspace/VaultFS vaultfs bash test_research.sh
    elif [ "$1" = "shell" ] || [ "$1" = "bash" ]; then
        exec docker run --privileged --device /dev/fuse --cap-add SYS_ADMIN --rm -it -v "$DIR:/workspace/VaultFS" -w /workspace/VaultFS vaultfs bash
    else
        exec docker run --privileged --device /dev/fuse --cap-add SYS_ADMIN --rm -it -v "$DIR:/workspace/VaultFS" -w /workspace/VaultFS vaultfs "$@"
    fi
else
    # Linux Native
    if [ ! -f ./vaultfs ]; then
        make
    fi
    if [ $# -eq 0 ] || [ "$1" = "test" ] || [ "$1" = "demo" ]; then
        exec bash test_demos.sh
    elif [ "$1" = "ransomware" ] || [ "$1" = "heal" ]; then
        exec bash test_ransomware.sh
    elif [ "$1" = "research" ] || [ "$1" = "eval" ] || [ "$1" = "bench" ]; then
        exec bash test_research.sh
    else
        exec "$@"
    fi
fi
