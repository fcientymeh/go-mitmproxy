FROM scratch
COPY mime* /
ADD certs /certs
COPY aisecproxy.json /
COPY app /
ADD dummy /suricata

ENTRYPOINT ["/app"]