x2kafka CHANGELOG
===============

## 2.0.1
  - Nils Verschaeve
    - [668d975] Bug #27307: Trim NUL padding before checking NetFlow/IPFIX string fields
    - [4e74b13] Bug #27307: Add tests for NUL padded NetFlow/IPFIX string fields
  - David Vanhoucke
    - [4b067d4] Add redborder flow-agent information (ja4, tls_version, os)

## 1.1.0

  - David Vanhoucke
    - [7a52f28] Improvement #27165: Implement OpenTelemetry (OTLP) protocol listeners (otlp_http, otlp_https, otlp_grpc, otlp) with kv/CEF extraction, schema standardization and sensor enrichment
    - [26d9652] Improvement #27165: Implement OpenTelemetry (OTLP) protocol listeners, follow-up

## 1.0.3

  - David Vanhoucke
    - [a8197e0] Add application_id info for flow data

## 1.0.2

  - David Vanhoucke
    - [6b08b5a] Add netflow and sflow

## 1.0.1 and earlier

  - David Vanhoucke
    - [e4053f2] Describe best practices
    - [4409177] Update README
    - [d28eeff] Add kafka2x
    - [ec64fde] Fix github workflow
    - [d38f86f] First commit
