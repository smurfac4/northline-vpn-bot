FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git python3 python3-cryptography python3-pycryptodome ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/alexbers/mtprotoproxy.git /opt/mtprotoproxy \
    && cd /opt/mtprotoproxy && git checkout bd5b03cd998eee5e916c5fcea8519d6d2c331d4d
COPY mtproxy/entrypoint.py /app/entrypoint.py
COPY mtproxy/run_proxy.py /app/run_proxy.py
COPY mtproxy/metrics.py /app/metrics.py
ENTRYPOINT ["python3", "/app/entrypoint.py"]
