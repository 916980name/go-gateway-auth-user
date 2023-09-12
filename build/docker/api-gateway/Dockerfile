FROM BASE_IMAGE

WORKDIR /opt/api-gateway

RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
      echo "Asia/Shanghai" > /etc/timezone && \
      mkdir -p /var/log/api-gateway

COPY api-gateway /opt/api-gateway/bin/

ENTRYPOINT ["/opt/api-gateway/bin/api-gateway"]
CMD ["-c", "/etc/api-gateway/api-gateway.yaml"]
