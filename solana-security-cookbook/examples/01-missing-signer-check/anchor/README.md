# Missing Signer Check - Anchor Examples

This example demonstrates the missing signer check vulnerability in Anchor.

## Structure

```
anchor/
├── vulnerable/     # Missing signer check
└── secure/         # Proper signer validation
```

## Vulnerable Version

**The Bug:** Uses `AccountInfo<'info>` instead of `Signer<'info>` in the withdraw function.

```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: AccountInfo<'info>,  // ❌ No signature check!
    // ...
}
```

**Attack:** Anyone can call withdraw with any user's public key and drain their vault.

## Secure Version

**The Fix:** Uses `Signer<'info>` to enforce signature verification.

```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,  // ✅ Signature required!
    // ...
}
```

## Building

```bash
# Vulnerable version
cd vulnerable
anchor build

# Secure version
cd secure
anchor build
```

## Testing

See `../../tests/test.ts` for exploit demonstration.

## Key Difference

The only difference is **one word**: `AccountInfo` vs `Signer`.

That one word protects millions of dollars.
