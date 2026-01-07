# =============================================================================
# EdgeLink Dockerfile - Multi-stage build with Alpine
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build environment
# -----------------------------------------------------------------------------
FROM alpine:3.20 AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    git \
    pkgconfig \
    linux-headers \
    boost-dev \
    openssl-dev \
    sqlite-dev \
    spdlog-dev \
    fmt-dev \
    nlohmann-json \
    libsodium-dev

WORKDIR /build
COPY . .

# Build (dynamic linking)
RUN cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_CONTROLLER=ON \
    -DBUILD_SERVER=ON \
    -DBUILD_CLIENT=ON \
    -DBUILD_TESTS=OFF \
    && cmake --build build --config Release -j$(nproc) \
    && strip build/edgelink-controller build/edgelink-server build/edgelink-client

# -----------------------------------------------------------------------------
# Stage 2: Controller
# -----------------------------------------------------------------------------
FROM alpine:3.20 AS controller

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    libstdc++ \
    boost1.84-json \
    openssl \
    sqlite-libs \
    spdlog \
    fmt \
    libsodium

WORKDIR /app

COPY --from=builder /build/build/edgelink-controller /app/
COPY --from=builder /build/config/controller.example.json /app/config/controller.json

EXPOSE 8080 8443

VOLUME ["/app/data", "/app/config"]

ENTRYPOINT ["/app/edgelink-controller"]
CMD ["-c", "/app/config/controller.json"]

# -----------------------------------------------------------------------------
# Stage 3: Server (Relay/STUN)
# -----------------------------------------------------------------------------
FROM alpine:3.20 AS server

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    libstdc++ \
    boost1.84-json \
    openssl \
    spdlog \
    fmt \
    libsodium

WORKDIR /app

COPY --from=builder /build/build/edgelink-server /app/
COPY --from=builder /build/config/server.example.json /app/config/server.json

EXPOSE 9443 3478/udp

VOLUME ["/app/config"]

ENTRYPOINT ["/app/edgelink-server"]
CMD ["-c", "/app/config/server.json"]

# -----------------------------------------------------------------------------
# Stage 4: Client
# -----------------------------------------------------------------------------
FROM alpine:3.20 AS client

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    libstdc++ \
    boost1.84-json \
    openssl \
    spdlog \
    fmt \
    libsodium \
    iproute2 \
    iptables

WORKDIR /app

COPY --from=builder /build/build/edgelink-client /app/
COPY --from=builder /build/config/client.example.json /app/config/client.json

VOLUME ["/app/config"]

ENTRYPOINT ["/app/edgelink-client"]
CMD ["-c", "/app/config/client.json"]
