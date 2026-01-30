# Solana Security Cookbook - Anchor Programs

All Anchor programs follow the same structure for clarity and ease of testing.

## Structure

Each vulnerability has two separate Anchor projects:

```
vulnerability-name/
├── vulnerable/
│   ├── Anchor.toml
│   ├── Cargo.toml
│   └── programs/vulnerable/
│       ├── Cargo.toml
│       └── src/lib.rs
└── secure/
    ├── Anchor.toml
    ├── Cargo.toml
    └── programs/secure/
        ├── Cargo.toml
        └── src/lib.rs
```

## Building

Each project builds independently:

```bash
# Build vulnerable version
cd vulnerable
anchor build

# Build secure version
cd ../secure
anchor build
```

## Testing

Tests are in the parent `tests/` directory and can target either program.

## Vulnerabilities Covered

1. **Missing Signer Check** - Using `AccountInfo` instead of `Signer`
2. **Incorrect PDA Validation** - Missing `seeds` and `bump` constraints
3. **Arithmetic Overflow** - Not using `checked_*` methods
4. **Reentrancy Risk** - Updating state after CPI calls
5. **Unsafe Account Closure** - Not properly closing accounts

Each demonstrates the vulnerability and its fix in working code.
