#!/bin/sh
set -e
cd /src
go mod init p0 >/dev/null 2>&1 || true
go get golang.org/x/net@v0.30.0 >/dev/null 2>&1
go build -cover -coverpkg=all -o /tmp/p0 . 
mkdir -p /tmp/cov && GOCOVERDIR=/tmp/cov /tmp/p0 &
sleep 1
wget -qO- "http://127.0.0.1:8099/parse?q=%3Cp%3Ehi%3C/p%3E"
wget -qO- http://127.0.0.1:8099/quit >/dev/null 2>&1 || true
sleep 1
go tool covdata textfmt -i=/tmp/cov -o /src/cov.txt
go version
