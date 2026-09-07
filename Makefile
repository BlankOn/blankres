# Common tasks. `make` on its own lists them.

IMAGE ?= herpiko/blankres-ingest
TAG   ?= $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

# The end-to-end suites need a database; without this they skip rather than fail.
TEST_DATABASE_URL ?= postgres://blankres:blankres@127.0.0.1:55432/blankres

.PHONY: help build test check fmt clippy deb build-docker push-docker up down logs clean

help:
	@echo "build         build every binary in release mode"
	@echo "test          run the test suite (set TEST_DATABASE_URL for the end-to-end suites)"
	@echo "check         fmt --check, clippy -D warnings, and the tests"
	@echo "fmt           format the workspace"
	@echo "clippy        lint the workspace, warnings are errors"
	@echo "deb           build the client Debian package"
	@echo "build-docker  build the ingest server image as $(IMAGE):$(TAG)"
	@echo "push-docker   push that image and its latest tag"
	@echo "up            start the ingest server and its database with docker compose"
	@echo "down          stop them (add KEEP=0 to delete the stored crash data too)"
	@echo "logs          follow the ingest server's logs"
	@echo "clean         remove build artefacts"

build:
	cargo build --release

test:
	BLANKRES_TEST_DATABASE_URL=$(TEST_DATABASE_URL) cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

check: clippy test
	cargo fmt --all --check

# -d skips the build-dependency check, which fails when cargo and rustc come from rustup rather
# than from the Debian packages.
deb:
	dpkg-buildpackage -us -uc -b -d

build-docker:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

push-docker: build-docker
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest

# Local deployment. See docker-compose.yaml for what it starts and what it deliberately does not.
up:
	docker compose up -d --build
	@echo "ingest server on http://127.0.0.1:$${BLANKRES_PORT:-8080} (token: dev-fleet-token)"

# Volumes survive by default: `down` should not be a way to lose a fleet's crash reports by
# accident. KEEP=0 removes them.
down:
	docker compose down $(if $(filter 0,$(KEEP)),--volumes,)

logs:
	docker compose logs -f ingest

clean:
	cargo clean
	rm -rf debian/cargo debian/blankres debian/.debhelper debian/files debian/*.substvars
