#!/bin/bash
CGO_ENABLED=0 go build
docker build -t b3repo.aiseclab.com:5000/ais/proxy/aisecproxy:2.0.1 .
docker push b3repo.aiseclab.com:5000/ais/proxy/aisecproxy:2.0.1