all: clear build
	docker compose up --force-recreate

clear:
	docker compose down -v

build:
	docker compose build

.PHONY: all clear