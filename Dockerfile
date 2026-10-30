FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    pkg-config \
    libfuse3-dev \
    libssl-dev \
    fuse3 \
    curl \
    python3 \
    procps \
    tree \
    util-linux \
    sqlite3 \
    libsqlite3-dev \
    zip \
    unzip \
    bc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/VaultFS

COPY . /workspace/VaultFS

RUN make clean && make

CMD ["bash", "test_demos.sh"]
