# Required variables — all must be non-empty in the shell before running make.
# Source them first:  . ./setenv && make
#
# Architecture is selected with DEMO_ARCH (arm | intel). If unset, make
# auto-detects from `uname -m`. See README.md.

REQUIRED_VARS := \
	WATSONX_PROJECT_ID \
	WATSONX_API_KEY \
	WATSONX_API_URL \
	GENERIC_CLIENT_ID \
	GENERIC_CLIENT_SECRET \
	KEYCLOAK_CLIENT_SECRET

HOST_ARCH := $(shell uname -m)
DEMO_ARCH_RAW := $(shell printf '%s' "$(DEMO_ARCH)" | tr '[:upper:]' '[:lower:]')

ifeq ($(strip $(DEMO_ARCH_RAW)),)
  ifeq ($(HOST_ARCH),arm64)
    DEMO_ARCH_RAW := arm
  endif
endif
ifeq ($(strip $(DEMO_ARCH_RAW)),)
  ifeq ($(HOST_ARCH),aarch64)
    DEMO_ARCH_RAW := arm
  endif
endif
ifeq ($(strip $(DEMO_ARCH_RAW)),)
  DEMO_ARCH_RAW := intel
endif

ifeq ($(DEMO_ARCH_RAW),$(filter $(DEMO_ARCH_RAW),arm arm64 aarch64))
  DEMO_ARCH := arm
  DOCKER_PLATFORM := linux/arm64
  SPIRE_ARCH := arm64
endif
ifeq ($(DEMO_ARCH_RAW),$(filter $(DEMO_ARCH_RAW),intel amd64 x86_64 x64))
  DEMO_ARCH := intel
  DOCKER_PLATFORM := linux/amd64
  SPIRE_ARCH := x86_64
endif
ifeq ($(DOCKER_PLATFORM),)
  $(error DEMO_ARCH must be arm or intel (got '$(DEMO_ARCH_RAW)'). Example: DEMO_ARCH=arm make)
endif

export DEMO_ARCH
export DOCKER_PLATFORM
export SPIRE_ARCH
DOCKER_DEFAULT_PLATFORM := $(DOCKER_PLATFORM)
export DOCKER_DEFAULT_PLATFORM

all: check-env .env clear build
	docker compose up -d --force-recreate

help:
	@echo "Architecture  host=$(HOST_ARCH)  DEMO_ARCH=$(DEMO_ARCH)  DOCKER_PLATFORM=$(DOCKER_PLATFORM)  SPIRE_ARCH=$(SPIRE_ARCH)"
	@echo "  DEMO_ARCH=arm    Apple Silicon / ARM servers   -> linux/arm64"
	@echo "  DEMO_ARCH=intel  Intel/AMD PCs and Intel Macs  -> linux/amd64"
	@echo ""
	@echo "Commands (from docker-compose/, after . ./setenv)"
	@echo "  make             Full reset, build, and start for the selected arch"
	@echo "  make build       Build local images for DOCKER_PLATFORM"
	@echo "  make clear       Stop stack and delete volumes"
	@echo "  make prove-rar   Mint a Keycloak RAR token and hit Vault with it"
	@echo "  make help        Show this message"

# check-env validates that every required variable is set and non-empty.
check-env:
	@missing=0; \
	for var in $(REQUIRED_VARS); do \
		val=$$(eval echo \$${$$var}); \
		if [ -z "$$val" ]; then \
			echo "ERROR: $$var is not set. Source setenv first:  . ./setenv"; \
			missing=1; \
		fi; \
	done; \
	if [ "$$missing" = "1" ]; then \
		echo ""; \
		echo "Run:  . ./setenv && make"; \
		exit 1; \
	fi
	@echo "All required environment variables are set."
	@echo "Architecture: DEMO_ARCH=$(DEMO_ARCH)  DOCKER_PLATFORM=$(DOCKER_PLATFORM)  SPIRE_ARCH=$(SPIRE_ARCH)  (host=$(HOST_ARCH))"

# Generate a Compose-compatible .env from setenv (strips 'export ' prefixes)
# and write the resolved arch so Compose interpolates platform/SPIRE_ARCH.
.env: setenv
	sed 's/^export //' setenv | grep -v -E '^(DEMO_ARCH|DOCKER_PLATFORM|SPIRE_ARCH)=' > .env
	printf 'DEMO_ARCH=%s\nDOCKER_PLATFORM=%s\nSPIRE_ARCH=%s\n' "$(DEMO_ARCH)" "$(DOCKER_PLATFORM)" "$(SPIRE_ARCH)" >> .env

clear:
	docker compose down -v

build:
	docker compose build

prove-rar:
	bash ./scripts/prove-keycloak-rar.sh

.PHONY: all help check-env clear build prove-rar
