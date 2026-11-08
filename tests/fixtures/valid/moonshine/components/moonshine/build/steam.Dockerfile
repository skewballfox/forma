ARG FEDORA_VERSION=44
ARG FEDORA_DIGEST=sha256:6f263feab9835fa01d3f8a944827da527aadbf1fee5ead10ad9b892b60d14608
ARG BASE_IMAGE=registry.fedoraproject.org/fedora-minimal:${FEDORA_VERSION}@${FEDORA_DIGEST}
# A forma image in the builder's storage: not pulled, never treated as remote
ARG MOONSHINE_IMAGE=localhost/moonshine/moonshine:patches

FROM $MOONSHINE_IMAGE AS moonshine

FROM $BASE_IMAGE
COPY --from=moonshine /usr/lib64/libVkLayer_moonshine.so /usr/lib64/
