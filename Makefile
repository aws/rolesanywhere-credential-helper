VERSION=1.0.5

GO_BUILD := go build -buildmode=pie -ldflags "-X 'github.com/aws/rolesanywhere-credential-helper/cmd.Version=$(VERSION)' -linkmode=external -w -s" -trimpath

release:
	$(GO_BUILD) -o build/bin/aws_signing_helper main.go
