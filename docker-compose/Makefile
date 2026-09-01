# Required variables — all must be non-empty in the shell before running make.
# They are sourced from setenv via `. ./setenv && make`.
REQUIRED_VARS := \
	WATSONX_PROJECT_ID \
	WATSONX_API_KEY \
	WATSONX_API_URL \
	GENERIC_CLIENT_ID \
	GENERIC_CLIENT_SECRET \
	KEYCLOAK_CLIENT_SECRET

# check-env validates that every required variable is set and non-empty.
# It prints a clear message for each missing variable then exits non-zero.
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

# Generate a Compose-compatible .env from setenv (strips 'export ' prefixes)
# so that variable references in env_file templates are expanded by Compose.
.env: setenv
	sed 's/^export //' setenv > .env

all: check-env .env clear build
	docker compose up -d --force-recreate

clear:
	docker compose down -v

build:
	docker compose build

.PHONY: all check-env clear build