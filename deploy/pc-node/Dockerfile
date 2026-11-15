FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools wireguard-go openssh-server iptables python3 iproute2 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY node_control.py /app/node_control.py
COPY pc-node/entrypoint.py /app/entrypoint.py
COPY pc-node/ssh-control.sh /app/ssh-control.sh
RUN chmod 755 /app/ssh-control.sh && mkdir -p /run/sshd /root/.ssh \
    && chmod 700 /root/.ssh
EXPOSE 51820/udp
ENTRYPOINT ["python3", "/app/entrypoint.py"]
