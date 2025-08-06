# Stage 1: Build the IAM Roles Anywhere Credential Helper from source
# Version pinned to most recent stable release
FROM --platform=$TARGETPLATFORM public.ecr.aws/amazonlinux/amazonlinux:2023.8.20250721.2 AS builder

# Add build arguments
ARG TARGETARCH
ARG VERSION

# Install build dependencies
RUN dnf install -y \
    golang-1.24.5-1.amzn2023.0.1 \
    make \
    && dnf clean all

# Set up working directory
WORKDIR /build/rolesanywhere-credential-helper

# Set GOARCH for cross-compilation
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=${TARGETARCH}

COPY .. .

# Build with architecture-specific settings
RUN make release

# Stage 2: Create a minimal runtime image
# Version pinned to most recent stable release
FROM --platform=$TARGETPLATFORM public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-glibc:2025-06-11-1749625329.2023

# Add build argument for version in final stage
ARG VERSION

# Copy the credential helper from the builder stage
COPY --from=builder /build/rolesanywhere-credential-helper/build/bin/aws_signing_helper /usr/local/bin/

USER 65532:65532

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/aws_signing_helper"]

# Add labels
LABEL maintainer="AWS IAM Roles Anywhere" \
      version="${VERSION}" \
      description="AWS IAM Roles Anywhere Credential Helper Docker Image"
