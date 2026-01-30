#!/usr/bin/env bash
set -e

ROOT="solana-security-cookbook"

echo "Creating Solana Security Cookbook structure (examples updated only)..."

# ----------------------
# Cookbook root (UNCHANGED)
# ----------------------
mkdir -p "$ROOT"
cd "$ROOT"

# Jekyll / blog (kept exactly)
mkdir -p _posts _includes _layouts assets tests

touch \
  Gemfile \
  _config.yml \
  index.md \
  security-guide.md \
  README.md \
  package.json

# Blog posts (kept)
touch \
  _posts/2025-01-27-missing-signer-check.md \
  _posts/2025-01-27-incorrect-pda-validation.md \
  _posts/2025-01-27-arithmetic-overflow.md \
  _posts/2025-01-27-reentrancy-risk.md \
  _posts/2025-01-27-unsafe-account-closure.md

# ----------------------
# Examples (UPDATED CANONICAL LAYOUT)
# ----------------------
mkdir -p examples

declare -a EXAMPLES=(
  "01-missing-signer-check"
  "02-incorrect-pda-validation"
  "03-arithmetic-overflow"
  "04-reentrancy-risk"
  "05-unsafe-account-closure"
)

for ex in "${EXAMPLES[@]}"; do
  # Base
  mkdir -p "examples/$ex"
  touch "examples/$ex/README.md"

  # Anchor
  mkdir -p \
    "examples/$ex/anchor/vulnerable/src" \
    "examples/$ex/anchor/secure/src"

  touch \
    "examples/$ex/anchor/vulnerable/Cargo.toml" \
    "examples/$ex/anchor/vulnerable/src/lib.rs" \
    "examples/$ex/anchor/secure/Cargo.toml" \
    "examples/$ex/anchor/secure/src/lib.rs"

  # Pinocchio
  mkdir -p \
    "examples/$ex/pinocchio/vulnerable/src" \
    "examples/$ex/pinocchio/secure/src"

  touch \
    "examples/$ex/pinocchio/vulnerable/Cargo.toml" \
    "examples/$ex/pinocchio/vulnerable/src/lib.rs" \
    "examples/$ex/pinocchio/secure/Cargo.toml" \
    "examples/$ex/pinocchio/secure/src/lib.rs"

  # Tests
  mkdir -p "examples/$ex/tests"
  touch \
    "examples/$ex/tests/exploit.ts" \
    "examples/$ex/tests/verify.ts"
done

echo "✅ Done. Blog/Jekyll preserved. Examples upgraded."
