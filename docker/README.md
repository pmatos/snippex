# Snippex Docker Testing Environments

This directory contains Docker configurations for reproducible testing environments, enabling cross-architecture validation between native x86_64 execution and FEX-Emu on ARM64.

## Overview

Snippex's testing methodology requires comparing:
- **Native x86_64 execution** (ground truth)
- **FEX-Emu emulation on ARM64** (testing target)

The Docker setup provides:
- `x86-native`: Native x86_64 environment for ground truth
- `arm64-fex`: ARM64 environment with FEX-Emu for emulation testing
- `ssh-server`: SSH-accessible ARM64 container for remote execution testing

## Quick Start

### Prerequisites

- Docker 20.10+ with Compose V2
- For cross-platform builds: Docker BuildX (`docker buildx install`)

### Building Images

```bash
# Build all images
./scripts/docker-build.sh

# Build specific architecture
./scripts/docker-build.sh x86     # x86_64 only
./scripts/docker-build.sh arm64   # aarch64 only

# Build multi-arch images and push to registry
./scripts/docker-build.sh --multiarch
```

### Running Containers

```bash
# Start all services
cd docker
docker-compose up -d

# Run interactive x86 container
docker-compose run x86-native

# Run interactive ARM64 container
docker-compose run arm64-fex

# Stop all services
docker-compose down
```

## Testing Workflow

### 1. Extract and Simulate on x86 (Ground Truth)

```bash
# Enter x86 container
docker-compose run x86-native

# Extract blocks from a binary
snippex extract /samples/test-binary --count 10

# Simulate blocks natively
snippex simulate --database /data/snippex.db

# Export results for comparison
snippex export json --output /data/native-results.json
```

### 2. Compare on ARM64 with FEX-Emu

```bash
# Enter ARM64 container
docker-compose run arm64-fex

# Import native results
snippex import json --input /data/native-results.json

# Simulate same blocks through FEX-Emu
snippex simulate --emulator fex --database /data/snippex.db

# Compare results
snippex compare --native /data/native-results.json \
    --emulated /data/fex-results.json
```

### 3. Remote Execution Testing

For testing SSH remote execution:

```bash
# Start SSH server
docker-compose up -d ssh-server

# From x86 container, test remote execution
snippex validate --remote ssh://snippex-ssh:22
```

## Container Details

### x86-native (x86_64)

Base image: Ubuntu 22.04 (amd64)

Includes:
- Rust toolchain
- NASM assembler
- GCC/G++ compilers
- binutils
- snippex (release build)

### arm64-fex (aarch64)

Base image: Ubuntu 22.04 (arm64)

Includes:
- Rust toolchain (native aarch64)
- FEX-Emu from official PPA
- x86_64 RootFS for FEX-Emu
- snippex (release build)

Environment variables:
- `FEX_ROOTFS=/root/.fex-emu/RootFS`

### Shared Volumes

| Volume | Purpose | Mount Point |
|--------|---------|-------------|
| `snippex-data` | Database and export files | `/data` |
| `snippex-samples` | Sample binaries for testing | `/samples` |

## Configuration

### Environment Variables

The build scripts support these environment variables:

```bash
DOCKER_REGISTRY=ghcr.io       # Container registry
DOCKER_REPO=snippex/snippex   # Repository name
DOCKER_TAG=latest             # Image tag
```

### Custom Registry

```bash
# Build for custom registry
./scripts/docker-build.sh --registry my-registry.io --repo my-org/snippex

# Push to custom registry
./scripts/docker-push.sh --registry my-registry.io --repo my-org/snippex
```

## Troubleshooting

### Image Build Fails

**Cross-platform build on x86 for ARM64:**
```bash
# Ensure buildx is installed
docker buildx version

# Create and use builder
docker buildx create --name snippex-builder --use
docker buildx inspect --bootstrap
```

**FEX-Emu RootFS download fails:**

The aarch64 image downloads the x86_64 RootFS during build. If this fails:
1. Check network connectivity
2. Verify FEX-Emu PPA is accessible
3. Try building with `--no-cache`

### Container Won't Start

**ARM64 container on x86 host:**

Cross-architecture containers require QEMU:
```bash
# Install QEMU user-mode emulation
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

### FEX-Emu Issues

**Check FEX-Emu version:**
```bash
docker-compose run arm64-fex FEXInterpreter --version
```

**Test FEX-Emu directly:**
```bash
docker-compose run arm64-fex FEXInterpreter /bin/ls
```

### Database Sharing Issues

Ensure the data volume is properly mounted:
```bash
docker-compose run x86-native ls -la /data
```

## Development

### Mounting Local Source

For development, uncomment the source mount in `docker-compose.yml`:

```yaml
volumes:
  - ..:/snippex:ro  # Mount local source
```

Then rebuild inside the container:
```bash
docker-compose run x86-native bash
cd /snippex
cargo build --release
```

### Adding Sample Binaries

Place test binaries in the `snippex-samples` volume:
```bash
docker cp ./my-test-binary snippex-x86-native:/samples/
```

## CI/CD Integration

See `.github/workflows/` for CI workflow examples using these containers.

### GitHub Actions Example

```yaml
jobs:
  test-x86:
    runs-on: ubuntu-latest
    container: ghcr.io/snippex/snippex:x86_64-latest
    steps:
      - uses: actions/checkout@v4
      - run: snippex --version
      - run: cargo test

  test-arm64:
    runs-on: ubuntu-latest
    container: ghcr.io/snippex/snippex:aarch64-latest
    steps:
      - uses: actions/checkout@v4
      - run: snippex --version
```
