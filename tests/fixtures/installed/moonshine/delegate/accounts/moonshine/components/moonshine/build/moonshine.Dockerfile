ARG FEDORA_VERSION=44
ARG FEDORA_DIGEST=sha256:6f263feab9835fa01d3f8a944827da527aadbf1fee5ead10ad9b892b60d14608
ARG BASE_IMAGE=registry.fedoraproject.org/fedora-minimal:${FEDORA_VERSION}@${FEDORA_DIGEST}
ARG MOONSHINE_REPO=https://github.com/skewballfox/moonshine.git
ARG MOONSHINE_REF=patches

FROM $BASE_IMAGE AS builder
ARG MOONSHINE_COMMIT
RUN true

# An earlier stage, not an image: not pulled
FROM $BASE_IMAGE AS runner
COPY --from=builder /usr/local/bin /usr/local/bin
