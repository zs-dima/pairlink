# pairlink recipes, from dev_tool templates/dart-package/justfile @1.0.0
# Needs `sh` on PATH (Windows: Git for Windows' `Git\bin`); tools: `mise install`.

# `flutter` for a package that needs the Flutter SDK.
TOOL := 'dart'

default:
    @just --list

[group('gate')]
check: format-check analyze test publish-check

[group('gate')]
format-check:
    dart format --output=none --set-exit-if-changed .

[group('gate')]
analyze:
    {{ TOOL }} analyze --fatal-infos --fatal-warnings

[group('gate')]
test *args:
    {{ TOOL }} test {{ args }}

[group('gate')]
publish-check:
    {{ TOOL }} pub publish --dry-run

# Local only: the DCM licence is a secret a fork's CI cannot see.
[group('gate')]
dcm:
    dcm analyze .

[group('dev')]
get:
    {{ TOOL }} pub get

[group('dev')]
format:
    dart format .

[group('dev')]
fix:
    dart fix --apply

[group('dev')]
outdated:
    {{ TOOL }} pub outdated

[group('dev')]
clean:
    rm -rf .dart_tool build coverage reports

# Operator only: gate, bump, commit, tag vX.Y.Z, push (deploy.yml publishes the tag).
[group('operator')]
[script]
release version:
    [ -t 0 ] || { echo "release is an operator command: run it from a terminal"; exit 2; }
    case "{{ version }}" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "usage: just release 1.2.3"; exit 2 ;; esac
    [ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "commit or stash first: the tree is dirty"; exit 1; }
    grep -q "^## \[{{ version }}\]" CHANGELOG.md || { echo "CHANGELOG.md has no section for {{ version }}"; exit 1; }
    just check
    sed "s/^version: .*/version: {{ version }}/" pubspec.yaml > pubspec.yaml.tmp && mv pubspec.yaml.tmp pubspec.yaml
    git add pubspec.yaml
    git diff --cached --quiet || git commit --quiet -m "chore: release {{ version }}"
    git tag "v{{ version }}"
    git push --quiet origin HEAD "v{{ version }}"
    echo "pushed v{{ version }}"

# Format, then the full gate.
[group('dev')]
all: format check

# Operator only: by hand; a pushed tag publishes through deploy.yml.
[group('operator')]
publish: check
    {{ TOOL }} pub publish
