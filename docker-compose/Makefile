# Generate a Compose-compatible .env from setenv (strips 'export ' prefixes)
# so that variable references in env_file templates are expanded by Compose.
.env: setenv
	sed 's/^export //' setenv > .env

all: .env clear build
	docker compose up -d --force-recreate

clear:
	docker compose down -v

build:
	docker compose build

.PHONY: all clear build