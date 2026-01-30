FROM public.ecr.aws/amazonlinux/amazonlinux:2023

SHELL ["/bin/bash", "-c"]

# Install build dependencies
RUN yum -y install \
    git \
    gcc \
    make \
    golang \
    tar \
    gzip \
    && yum clean all

# Set up Go environment
ENV GOPATH=/root/go \
    PATH=/root/go/bin:$PATH \
    HOME=/root \
    CGO_ENABLED=1

# Copy go.mod to the container
COPY go.mod /tmp/go.mod

# Install Go
RUN mkdir -p /root/go/bin && \
    GO_VERSION=$(grep '^toolchain' /tmp/go.mod | awk '{print $2}' | sed 's/go//') && \
    go install golang.org/dl/go${GO_VERSION}@latest && \
    go${GO_VERSION} download && \
    rm -rf /usr/local/go && \
    ln -s /root/sdk/go${GO_VERSION} /usr/local/go

# Update PATH with new Go installation
ENV GOROOT=/usr/local/go \
    PATH=/usr/local/go/bin:/root/go/bin:$PATH \
    GOOS=linux \
    GOARCH=arm64 \
    GOPROXY=direct

WORKDIR /workspace

CMD ["/bin/bash"]
