FROM mirror.gcr.io/library/ubuntu:latest as builder
ARG BUILDKIT_SBOM_SCAN_STAGE=true

RUN apt update -qqq && apt install openssl -y


FROM mirror.gcr.io/library/ubuntu:latest
ARG BUILDKIT_SBOM_SCAN_CONTEXT=true

COPY --from=builder /usr/bin/openssl /usr/bin/openssl