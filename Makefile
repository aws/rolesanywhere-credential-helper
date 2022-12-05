VERSION=1.0.3

release:
	go build -buildmode=pie -ldflags "-X 'main.Version=${VERSION}' -linkmode=external -w -s" -trimpath -o build/bin/aws_signing_helper cmd/aws_signing_helper/main.go
