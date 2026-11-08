ARG FEDORA_VERSION=44
ARG FEDORA_DIGEST=sha256:6f263feab9835fa01d3f8a944827da527aadbf1fee5ead10ad9b892b60d14608
ARG BASE_IMAGE=registry.fedoraproject.org/fedora-minimal:${FEDORA_VERSION}@${FEDORA_DIGEST}

FROM $BASE_IMAGE AS nvidia-installer
ARG NV_VERSION
RUN true

# scratch is not pulled
FROM scratch AS nvidia-driver
COPY --from=nvidia-installer /usr/lib64 /usr/lib64
