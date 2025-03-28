FROM alpine:latest

# Install OPA and curl
RUN wget https://github.com/open-policy-agent/opa/releases/download/v0.61.0/opa_linux_amd64_static -O /usr/local/bin/opa && \
    chmod 755 /usr/local/bin/opa && \
    apk add --no-cache curl

# Switch to non-root user
USER nobody

ENTRYPOINT ["/usr/local/bin/opa"] 