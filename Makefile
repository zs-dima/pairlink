SHELL := /bin/bash -e -o pipefail

.DEFAULT_GOAL := all
.PHONY: all
all: format check test ## format, check, test

.PHONY: help
help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: get
get: ## resolve dependencies
	@dart pub get

.PHONY: format
format: ## format sources
	@dart format .

.PHONY: fix
fix: ## apply analyzer fixes
	@dart fix --apply

.PHONY: analyze
analyze: get ## format check and analyzer, infos and warnings fatal
	@git ls-files '*.dart' | grep -vE '\.(g|freezed|gen)\.dart$$' | xargs -r dart format --set-exit-if-changed -o none
	@dart analyze --fatal-infos --fatal-warnings

.PHONY: dcm
dcm: ## DCM with the lints_tool rule set
	@dcm analyze .

.PHONY: test
test: get ## run the tests
	@dart test

.PHONY: publish-check
publish-check: ## pub.dev dry run
	@dart pub publish --dry-run

.PHONY: check
check: analyze publish-check ## everything CI runs except the tests

.PHONY: outdated
outdated: get ## outdated dependencies
	@dart pub outdated

.PHONY: publish
publish: check test ## publish to pub.dev
	@dart pub publish

.PHONY: clean
clean: ## remove build output
	@rm -rf .dart_tool build coverage reports
