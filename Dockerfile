FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends wget unzip ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/selfray-ui
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
RUN mkdir -p data xray && \
    ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in amd64) X="64";; arm64) X="arm64-v8a";; armhf) X="arm32-v7a";; *) X="64";; esac && \
    wget -q "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${X}.zip" -O /tmp/xray.zip && \
    unzip -o /tmp/xray.zip -d xray && chmod +x xray/xray && rm -f /tmp/xray.zip
EXPOSE 8443
VOLUME ["/opt/selfray-ui/data"]
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8443"]
