SHELL := /bin/bash

.PHONY: bootstrap up down logs validate test backup restore
bootstrap:
	./scripts/bootstrap.sh
up:
	./scripts/dev-up.sh
down:
	docker compose down
logs:
	docker compose logs -f --tail=200
validate:
	./scripts/validate.sh
test:
	docker compose run --rm api pytest -q
backup:
	./scripts/backup.sh
restore:
	./scripts/restore.sh
