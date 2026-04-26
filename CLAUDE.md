# DPI Detector

Detects Russian ISP DPI blocking (TLS injection, HTTP redirect, TCP 16-20KB blocks).

## Tech Stack

Python 3.10+, httpx, rich (CLI), aiodns. Distributed as Docker image, .exe, or source.

## Features

- TLS 1.2/1.3 validation, MITM detection, SNI blocking
- HTTP injection detection (redirect to ISP block pages)
- TCP 16-20KB window block detection
- Error classification: TCP Reset, Connection Abort, Handshake Timeout, TLS alerts, SNI block, HTTP 451

## Config

- `domains.txt` — target domains
- `tcp_16_20_targets.json` — TCP window targets
- `config.py` — concurrency, timeouts, block markers
