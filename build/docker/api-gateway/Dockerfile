FROM alpine:latest

WORKDIR /opt/api-gateway

RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
      echo "Asia/Shanghai" > /etc/timezone && \
      mkdir -p /var/log/api-gateway

COPY api-gateway /opt/api-gateway/bin/
COPY api-gateway.yaml /etc/api-gateway/

ENTRYPOINT ["/opt/api-gateway/bin/api-gateway"]
CMD ["-c", "/etc/api-gateway/api-gateway.yaml"]

# docker build -f build/docker/api-gateway/Dockerfile -t go-api-gateway:v1 _output/platforms/linux/amd64/