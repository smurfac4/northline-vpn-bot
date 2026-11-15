FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openvpn iproute2 curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["python3"]
