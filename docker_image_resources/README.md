# Docker Image Resources for AWS IAM Roles Anywhere Credential Helper

This directory contains resources for building and testing a Docker image of the AWS IAM Roles Anywhere Credential Helper. The Docker image provides a containerized version of the credential helper that can be used in container environments like Kubernetes.

## Getting Started

Follow these steps to build and test the Docker image:

1. **Set up environment variables**:
   ```bash
   # Copy the template file
   cp .env.template myEnvironmentVariables.env
   
   # Edit the .env file with your values
   vim myEnvironmentVariables.env
   
   # Load the environment variables
   source myEnvironmentVariables.env
   ```

2. **Build the Docker image**:
   ```bash
   ./build.sh
   ```
   This script will install Docker if necessary and build the image for your platform.

3. **Run the test suite** (optional):
   ```bash
   ./tests/run-tests.sh
   ```
   This will set up a Kind cluster, load the image, and run all tests.

4. **Run individual tests** (optional):
   ```bash
   ./tests/scripts/run-test.sh <test-case-name>
   ```
   Available test cases: `serve`, `update`, `update-credentials-file`

## Environment Variables

The following environment variables can be configured in your `.env` file:

### Image Properties (Optional)
These have default values if not specified:
- `VERSION` - Image version tag (default: `latest`)
- `REGISTRY` - Docker registry (default: `local`)
- `IMAGE_NAME` - Image name (default: `iamra-credential-helper`)

### AWS Resource ARNs (Required)
These must be specified and do not have defaults:
- `TRUST_ANCHOR_ARN` - Format: `arn:aws:rolesanywhere:region:account:trust-anchor/id`
- `PROFILE_ARN` - Format: `arn:aws:rolesanywhere:region:account:profile/id`
- `ROLE_ARN` - Format: `arn:aws:iam::account:role/role-name`

### PKI Resource Paths (Required)
These have default values pointing to the test certificates:
- `CERTIFICATE_PATH` - Path to your certificate (default: `tests/certs/certificate.pem`)
- `PRIVATE_KEY_PATH` - Path to your private key (default: `tests/certs/private_key.pem`)

## Directory Structure

- `Dockerfile` - Multi-stage Dockerfile that builds the credential helper from source and creates a minimal runtime image
- `build.sh` - Script to build the Docker image with configurable parameters and automatic Docker installation if not found
- `.env.template` - Template for environment variables needed for building and testing
- `tests/` - Directory containing test resources
  - `run-tests.sh` - Script to run all tests for the Docker image
  - `setup.sh` - Sets up the test environment (Kind cluster) with automatic installation of required tools
  - `kind-config.yaml` - Configuration for the Kind cluster
  - `certs/` - Test certificates used for authentication
  - `pod_configurations/` - Kubernetes pod configurations for different test scenarios
  - `scripts/` - Test scripts for validation and execution
    - `run-test.sh` - Script to run individual tests
    - `evaluate-caller-identity.sh` - Script to validate credentials using AWS STS (used by test-client in test cases)

## Building the Docker Image

The `build.sh` script builds the Docker image with configurable parameters:

```bash
# Build for the current architecture (amd64 or arm64 auto-detected)
./build.sh
```

The script will:
1. Check if Docker is installed and install it if necessary
2. Detect your platform architecture (amd64 or arm64)
3. Build the Docker image using `docker buildx`
4. Create two tags:
   - `${REGISTRY}/${IMAGE_NAME}:${VERSION}-${PLATFORM}` (platform-specific)
   - `${REGISTRY}/${IMAGE_NAME}:${VERSION}` (default)

## Testing the Docker Image

### Running the Full Test Suite

The `run-tests.sh` script runs all tests to verify the functionality of the Docker image:

```bash
./tests/run-tests.sh
```

This script will:
1. Set up the test environment using `setup.sh`
2. Run all three test cases sequentially
3. Provide a summary of test results

### Running Individual Tests

You can run individual tests using the `run-test.sh` script:

```bash
./tests/scripts/run-test.sh <test-case-name> [timeout]
```

Where:
- `<test-case-name>` is one of: `serve`, `update`, or `update-credentials-file`
- `[timeout]` is an optional parameter specifying how long to wait for the pod to be ready (default: 30 seconds)

### Test Environment Setup

The `setup.sh` script prepares the test environment:

1. Installs `kubectl` and `kind` if not already installed
2. Creates a Kind cluster or uses an existing one
3. Loads the Docker image into the Kind cluster
4. Creates ConfigMaps for test certificates and test resources

### Test Modes

The Docker image is tested in three different modes:

1. **Serve Mode** - Tests the credential helper in serve mode, which vends temporary credentials through a local endpoint
   - Configuration: `tests/pod_configurations/serve.yaml`
   - Test validates credentials using the AWS STS get-caller-identity API

2. **Update Mode** - Tests the credential helper in update mode, which updates temporary credentials in the AWS credentials file
   - Configuration: `tests/pod_configurations/update.yaml`
   - Runs with root privileges to write to the default AWS credentials location
   - Test validates credentials using the AWS STS get-caller-identity API

3. **Update Mode (using AWS_SHARED_CREDENTIALS_FILE)** - Tests the credential helper in update mode without root privileges
   - Configuration: `tests/pod_configurations/update-credentials-file.yaml`
   - Uses environment variables to specify a custom credentials file location
   - Test validates credentials using the AWS STS get-caller-identity API

## Docker Image Details

The Docker image is built using a multi-stage build process:

1. **Build Stage**:
   - Uses Amazon Linux 2023 as the base image
   - Installs build dependencies (golang and make)
   - Builds the credential helper from source

2. **Runtime Stage**:
   - Uses a minimal base image (eks-distro-minimal-base-glibc)
   - Copies only the built binary from the build stage
   - Runs as a non-root user (UID 65532)
   - Sets the entrypoint to the credential helper binary

## Usage Examples

### Running in Serve Mode

```yaml
containers:
- name: credential-helper
  image: local/iamra-credential-helper:latest
  args:
  - "serve"
  - "--certificate"
  - "/certs/certificate.pem"
  - "--private-key"
  - "/certs/private_key.pem"
  - "--trust-anchor-arn"
  - "arn:aws:rolesanywhere:region:account:trust-anchor/id"
  - "--profile-arn"
  - "arn:aws:rolesanywhere:region:account:profile/id"
  - "--role-arn"
  - "arn:aws:iam::account:role/role-name"
  volumeMounts:
  - name: certs-volume
    mountPath: /certs
    readOnly: true
```

### Running in Update Mode

```yaml
containers:
- name: credential-helper
  image: local/iamra-credential-helper:latest
  securityContext:
      runAsUser: 0 #Necessary for write to root directory
  args:
  - "update"
  - "--certificate"
  - "/certs/certificate.pem"
  - "--private-key"
  - "/certs/private_key.pem"
  - "--trust-anchor-arn"
  - "arn:aws:rolesanywhere:region:account:trust-anchor/id"
  - "--profile-arn"
  - "arn:aws:rolesanywhere:region:account:profile/id"
  - "--role-arn"
  - "arn:aws:iam::account:role/role-name"
  - "--profile"
  - "default"
  volumeMounts:
  - name: certs-volume
    mountPath: /certs
    readOnly: true
  - name: aws-credentials
    mountPath: /root/.aws
```

### Running in Update Mode (using AWS_SHARED_CREDENTIALS_FILE)

```yaml
containers:
- name: credential-helper
  image: local/iamra-credential-helper:latest
  env:
  - name: AWS_SHARED_CREDENTIALS_FILE
    value: "/tmp/.aws/credentials"
  args:
  - "update"
  - "--certificate"
  - "/certs/certificate.pem"
  - "--private-key"
  - "/certs/private_key.pem"
  - "--trust-anchor-arn"
  - "arn:aws:rolesanywhere:region:account:trust-anchor/id"
  - "--profile-arn"
  - "arn:aws:rolesanywhere:region:account:profile/id"
  - "--role-arn"
  - "arn:aws:iam::account:role/role-name"
  - "--profile"
  - "default"
  volumeMounts:
  - name: certs-volume
    mountPath: /certs
    readOnly: true
  - name: aws-credentials
    mountPath: /tmp/.aws
```

## License

This project is licensed under the Apache-2.0 License. See the LICENSE file in the root directory for details.
