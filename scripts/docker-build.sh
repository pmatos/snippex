#!/bin/bash
# Build Docker images for snippex testing environments
#
# Usage:
#   ./scripts/docker-build.sh              # Build all images
#   ./scripts/docker-build.sh x86          # Build only x86_64 image
#   ./scripts/docker-build.sh arm64        # Build only aarch64 image
#   ./scripts/docker-build.sh --multiarch  # Build multi-architecture images

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REGISTRY="${DOCKER_REGISTRY:-ghcr.io}"
REPO="${DOCKER_REPO:-snippex/snippex}"
TAG="${DOCKER_TAG:-latest}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

build_x86_64() {
    log_info "Building x86_64 image..."
    docker build \
        -t "snippex:x86_64" \
        -t "${REGISTRY}/${REPO}:x86_64-${TAG}" \
        -f "${PROJECT_ROOT}/docker/Dockerfile.x86_64" \
        "${PROJECT_ROOT}"
    log_info "x86_64 image built successfully"
}

build_aarch64() {
    log_info "Building aarch64 image..."

    # Check if we need to use buildx for cross-platform build
    CURRENT_ARCH=$(uname -m)
    if [[ "$CURRENT_ARCH" != "aarch64" && "$CURRENT_ARCH" != "arm64" ]]; then
        log_warn "Building aarch64 image on ${CURRENT_ARCH} - using buildx"

        # Ensure buildx is available
        if ! docker buildx version &>/dev/null; then
            log_error "Docker buildx is required for cross-platform builds"
            log_error "Install with: docker buildx install"
            exit 1
        fi

        # Create builder if it doesn't exist
        if ! docker buildx inspect snippex-builder &>/dev/null; then
            log_info "Creating buildx builder..."
            docker buildx create --name snippex-builder --use
        fi

        docker buildx build \
            --platform linux/arm64 \
            -t "snippex:aarch64" \
            -t "${REGISTRY}/${REPO}:aarch64-${TAG}" \
            -f "${PROJECT_ROOT}/docker/Dockerfile.aarch64" \
            --load \
            "${PROJECT_ROOT}"
    else
        docker build \
            -t "snippex:aarch64" \
            -t "${REGISTRY}/${REPO}:aarch64-${TAG}" \
            -f "${PROJECT_ROOT}/docker/Dockerfile.aarch64" \
            "${PROJECT_ROOT}"
    fi

    log_info "aarch64 image built successfully"
}

build_multiarch() {
    log_info "Building multi-architecture images..."

    # Ensure buildx is available
    if ! docker buildx version &>/dev/null; then
        log_error "Docker buildx is required for multi-architecture builds"
        log_error "Install with: docker buildx install"
        exit 1
    fi

    # Create builder if it doesn't exist
    if ! docker buildx inspect snippex-builder &>/dev/null; then
        log_info "Creating buildx builder..."
        docker buildx create --name snippex-builder --use --bootstrap
    else
        docker buildx use snippex-builder
    fi

    # Build x86_64 image
    log_info "Building x86_64 multi-arch image..."
    docker buildx build \
        --platform linux/amd64 \
        -t "${REGISTRY}/${REPO}:x86_64-${TAG}" \
        -f "${PROJECT_ROOT}/docker/Dockerfile.x86_64" \
        --push \
        "${PROJECT_ROOT}"

    # Build aarch64 image
    log_info "Building aarch64 multi-arch image..."
    docker buildx build \
        --platform linux/arm64 \
        -t "${REGISTRY}/${REPO}:aarch64-${TAG}" \
        -f "${PROJECT_ROOT}/docker/Dockerfile.aarch64" \
        --push \
        "${PROJECT_ROOT}"

    log_info "Multi-architecture images built and pushed successfully"
}

show_usage() {
    echo "Usage: $0 [OPTIONS] [TARGET]"
    echo ""
    echo "Targets:"
    echo "  x86, x86_64     Build only x86_64 image"
    echo "  arm64, aarch64  Build only aarch64 image"
    echo "  all             Build all images (default)"
    echo ""
    echo "Options:"
    echo "  --multiarch     Build and push multi-architecture images"
    echo "  --tag TAG       Set image tag (default: latest)"
    echo "  --registry REG  Set registry (default: ghcr.io)"
    echo "  --repo REPO     Set repository name (default: snippex/snippex)"
    echo "  --help          Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  DOCKER_REGISTRY  Docker registry (default: ghcr.io)"
    echo "  DOCKER_REPO      Repository name (default: snippex/snippex)"
    echo "  DOCKER_TAG       Image tag (default: latest)"
}

# Parse arguments
MULTIARCH=false
TARGET="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        --multiarch)
            MULTIARCH=true
            shift
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        --registry)
            REGISTRY="$2"
            shift 2
            ;;
        --repo)
            REPO="$2"
            shift 2
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        x86|x86_64)
            TARGET="x86_64"
            shift
            ;;
        arm64|aarch64)
            TARGET="aarch64"
            shift
            ;;
        all)
            TARGET="all"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
cd "${PROJECT_ROOT}"

log_info "Building snippex Docker images"
log_info "Registry: ${REGISTRY}"
log_info "Repository: ${REPO}"
log_info "Tag: ${TAG}"
echo ""

if $MULTIARCH; then
    build_multiarch
else
    case $TARGET in
        x86_64)
            build_x86_64
            ;;
        aarch64)
            build_aarch64
            ;;
        all)
            build_x86_64
            build_aarch64
            ;;
    esac
fi

echo ""
log_info "Build complete!"
log_info "Images available:"
docker images | grep snippex | head -10
