#!/bin/bash
# Push Docker images to registry
#
# Usage:
#   ./scripts/docker-push.sh              # Push all images
#   ./scripts/docker-push.sh x86          # Push only x86_64 image
#   ./scripts/docker-push.sh arm64        # Push only aarch64 image
#   ./scripts/docker-push.sh --latest     # Also tag and push as 'latest'
#
# Prerequisites:
#   - Docker login to registry (e.g., `docker login ghcr.io`)
#   - Images must be built first (./scripts/docker-build.sh)

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

check_login() {
    # Try to verify we're logged in
    if ! docker info 2>/dev/null | grep -q "Username"; then
        log_warn "Docker may not be logged in to registry"
        log_warn "Run: docker login ${REGISTRY}"
    fi
}

push_x86_64() {
    local image="${REGISTRY}/${REPO}:x86_64-${TAG}"

    # Check if image exists
    if ! docker image inspect "snippex:x86_64" &>/dev/null; then
        log_error "Image snippex:x86_64 not found. Run docker-build.sh first."
        exit 1
    fi

    log_info "Pushing x86_64 image to ${image}..."
    docker push "${image}"

    if $PUSH_LATEST; then
        local latest_image="${REGISTRY}/${REPO}:x86_64-latest"
        log_info "Tagging and pushing as latest..."
        docker tag "snippex:x86_64" "${latest_image}"
        docker push "${latest_image}"
    fi

    log_info "x86_64 image pushed successfully"
}

push_aarch64() {
    local image="${REGISTRY}/${REPO}:aarch64-${TAG}"

    # Check if image exists
    if ! docker image inspect "snippex:aarch64" &>/dev/null; then
        log_error "Image snippex:aarch64 not found. Run docker-build.sh first."
        exit 1
    fi

    log_info "Pushing aarch64 image to ${image}..."
    docker push "${image}"

    if $PUSH_LATEST; then
        local latest_image="${REGISTRY}/${REPO}:aarch64-latest"
        log_info "Tagging and pushing as latest..."
        docker tag "snippex:aarch64" "${latest_image}"
        docker push "${latest_image}"
    fi

    log_info "aarch64 image pushed successfully"
}

create_manifest() {
    log_info "Creating multi-architecture manifest..."

    local manifest="${REGISTRY}/${REPO}:${TAG}"
    local x86_image="${REGISTRY}/${REPO}:x86_64-${TAG}"
    local arm_image="${REGISTRY}/${REPO}:aarch64-${TAG}"

    # Remove existing manifest if present
    docker manifest rm "${manifest}" 2>/dev/null || true

    # Create manifest
    docker manifest create "${manifest}" \
        "${x86_image}" \
        "${arm_image}"

    # Annotate with architecture info
    docker manifest annotate "${manifest}" "${x86_image}" \
        --os linux --arch amd64
    docker manifest annotate "${manifest}" "${arm_image}" \
        --os linux --arch arm64

    # Push manifest
    docker manifest push "${manifest}"

    if $PUSH_LATEST && [[ "${TAG}" != "latest" ]]; then
        local latest_manifest="${REGISTRY}/${REPO}:latest"
        docker manifest rm "${latest_manifest}" 2>/dev/null || true
        docker manifest create "${latest_manifest}" \
            "${x86_image}" \
            "${arm_image}"
        docker manifest annotate "${latest_manifest}" "${x86_image}" \
            --os linux --arch amd64
        docker manifest annotate "${latest_manifest}" "${arm_image}" \
            --os linux --arch arm64
        docker manifest push "${latest_manifest}"
    fi

    log_info "Multi-architecture manifest created and pushed"
}

show_usage() {
    echo "Usage: $0 [OPTIONS] [TARGET]"
    echo ""
    echo "Targets:"
    echo "  x86, x86_64     Push only x86_64 image"
    echo "  arm64, aarch64  Push only aarch64 image"
    echo "  all             Push all images (default)"
    echo ""
    echo "Options:"
    echo "  --latest        Also tag and push as 'latest'"
    echo "  --manifest      Create and push multi-arch manifest"
    echo "  --tag TAG       Set image tag (default: latest)"
    echo "  --registry REG  Set registry (default: ghcr.io)"
    echo "  --repo REPO     Set repository name (default: snippex/snippex)"
    echo "  --help          Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  DOCKER_REGISTRY  Docker registry (default: ghcr.io)"
    echo "  DOCKER_REPO      Repository name (default: snippex/snippex)"
    echo "  DOCKER_TAG       Image tag (default: latest)"
    echo ""
    echo "Examples:"
    echo "  $0                           # Push all images with current tag"
    echo "  $0 --tag v1.0.0 --latest     # Push with version tag and latest"
    echo "  $0 --manifest --tag v1.0.0   # Push with multi-arch manifest"
}

# Parse arguments
PUSH_LATEST=false
CREATE_MANIFEST=false
TARGET="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        --latest)
            PUSH_LATEST=true
            shift
            ;;
        --manifest)
            CREATE_MANIFEST=true
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

log_info "Pushing snippex Docker images"
log_info "Registry: ${REGISTRY}"
log_info "Repository: ${REPO}"
log_info "Tag: ${TAG}"
echo ""

check_login

case $TARGET in
    x86_64)
        push_x86_64
        ;;
    aarch64)
        push_aarch64
        ;;
    all)
        push_x86_64
        push_aarch64
        if $CREATE_MANIFEST; then
            create_manifest
        fi
        ;;
esac

echo ""
log_info "Push complete!"
