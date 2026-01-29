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

# Install specific Go version
RUN mkdir -p /root/go/bin && \
    go install golang.org/dl/go1.24.11@latest && \
    go1.24.11 download && \
    rm -rf /usr/local/go && \
    ln -s /root/sdk/go1.24.11 /usr/local/go

# Update PATH with new Go installation
ENV GOROOT=/usr/local/go \
    PATH=/usr/local/go/bin:/root/go/bin:$PATH \
    GOOS=linux \
    GOARCH=amd64 \
    GOPROXY=direct

WORKDIR /workspace

CMD ["/bin/bash"]
