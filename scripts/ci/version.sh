#!/usr/bin/env bash
# Decide the version string for a release-pipeline run and write it to $GITHUB_OUTPUT.
#
#   tag push vX.Y.Z  → version=X.Y.Z (must equal the workspace version in Cargo.toml,
#                      so a release can never be labelled with the wrong version)
#   anything else    → version=<cargo version>-nightly.<YYYYMMDD>.<short sha>
#
# Outputs: version, kind (release|nightly), build_number (numeric, for Info.plist).
set -euo pipefail
: "${GITHUB_OUTPUT:?}" "${GITHUB_SHA:?}" "${GITHUB_RUN_NUMBER:?}"

cargo_version="$(cargo metadata --no-deps --format-version 1 \
  | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"

if [[ "${GITHUB_REF_TYPE:-}" == "tag" && "${GITHUB_REF_NAME:-}" == v* ]]; then
  version="${GITHUB_REF_NAME#v}"
  if [[ "$version" != "$cargo_version" ]]; then
    echo "::error::Tag $GITHUB_REF_NAME does not match workspace version $cargo_version in Cargo.toml"
    exit 1
  fi
  kind=release
else
  version="$cargo_version-nightly.$(date -u +%Y%m%d).${GITHUB_SHA:0:7}"
  kind=nightly
fi

{
  echo "version=$version"
  echo "kind=$kind"
  echo "build_number=$GITHUB_RUN_NUMBER"
} >> "$GITHUB_OUTPUT"
echo "Version: $version ($kind), build $GITHUB_RUN_NUMBER"
