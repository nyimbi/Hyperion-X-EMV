CARGO ?= cargo
HYPERION ?= $(CARGO) run --quiet --bin hyperion --

.PHONY: verify coverage bundle workspace freeze schemas header cli-smoke

verify:
	$(CARGO) fmt --check
	$(CARGO) test
	$(CARGO) test --examples
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	git diff --check

coverage:
	scripts/coverage_100.sh

bundle:
	$(HYPERION) bundle init --out target/hyperion-certification-wizard

workspace:
	$(HYPERION) report workspace --out target/hyperion-report-workspace

freeze:
	$(HYPERION) release freeze --artifacts target/hyperion-cert-artifact-import --out target/hyperion-submission-pack --allow-incomplete

schemas:
	$(HYPERION) schemas write --out docs/schemas

header:
	$(HYPERION) c-header write --out include/hyperion_emv.h

cli-smoke:
	$(HYPERION) commands --markdown
	$(HYPERION) certify check > target/hyperion-prelab-quality-gates.json
