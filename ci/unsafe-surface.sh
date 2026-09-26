#!/usr/bin/env bash
# Prints the first-party unsafe surface as canonical JSON.
#
# `cargo geiger --invert` emits the whole dependency tree, which changes on every
# dependency bump and would make a diff useless: the signal this project needs is
# "did *our* unsafe grow", not "did a transitive dependency change". So each
# member is measured on its own (geiger requires a real package, not the virtual
# manifest) and reduced to the workspace crates' own `used` counts.
#
# `forbids_unsafe` is in the output on purpose: it is the machine-readable form of
# the rule that every crate outside r3s-store, r3s-runtime and r3s-net carries
# `#![forbid(unsafe_code)]`, and it is the one field a reviewer can trust at a
# glance.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
members=()
while IFS= read -r line; do
  members+=("$line")
done < <(cd "$root" && cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[].manifest_path' | sort)

out='{"crates":['
first=1
for manifest in "${members[@]}"; do
  dir="$(dirname "$manifest")"
  name="$(basename "$dir")"
  row="$(cd "$dir" && cargo geiger --invert --output-format Json 2>/dev/null | jq -c --arg name "$name" '
    (.packages // [])
    | map(select(.package.id.name == $name))
    | first
    | .unsafety
    | {
        unsafe_functions:  (.used.functions.unsafe_ // 0),
        unsafe_exprs:      (.used.exprs.unsafe_ // 0),
        unsafe_methods:    (.used.methods.unsafe_ // 0),
        unsafe_item_impls: (.used.item_impls.unsafe_ // 0),
        unsafe_traits:     (.used.item_traits.unsafe_ // 0),
        forbids_unsafe:    (.forbids_unsafe // false)
      }')"
  if [ -z "$row" ] || [ "$row" = "null" ]; then
    echo "geiger produced nothing for $name" >&2
    exit 1
  fi
  [ "$first" -eq 1 ] || out+=','
  first=0
  out+="{\"crate\":\"$name\",\"unsafety\":$row}"
done
out+=']}'

printf '%s' "$out" | jq -S .
