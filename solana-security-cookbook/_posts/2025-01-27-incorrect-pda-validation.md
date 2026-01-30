---
layout: post
title: "Incorrect PDA Validation: The Fake ID Problem"
date: 2025-01-27
categories: vulnerabilities
---

# Incorrect PDA Validation: The Fake ID Problem

Look, PDAs (Program Derived Addresses) are weird. They're addresses that programs control instead of users. No private key, no signature - just math.

And that's exactly why they're dangerous when you mess them up.

## What's a PDA Anyway?

Think of a PDA like a safety deposit box at a bank. The bank (your program) controls it, not you. You can't just walk in with a key - the bank has to open it for you.

In Solana terms:
- **Regular address**: You have the private key, you control it
- **PDA**: The program has "control" through deterministic derivation

PDAs are created from:
1. Some seeds (like "vault", user pubkey, etc.)
2. A program ID
3. A bump seed (to make sure it's not a regular keypair)

```rust
// This creates a PDA
let (pda, bump) = Pubkey::find_program_address(
    &[b"vault", user.key().as_ref()],
    program_id
);
```

## The Vulnerability

Here's where people screw up: **they don't validate the PDA was derived correctly**.

Imagine this scenario:
1. Your program expects a vault PDA derived from the user's pubkey
2. Attacker creates their own account with the same data structure
3. Attacker passes their fake account instead of the real PDA
4. Your program doesn't check... and boom, they control the "vault"

It's like accepting a fake ID because you didn't check the hologram.

## Real Example: The Vault Exploit

Let's say you have a vault program where users deposit SOL:

```rust
// ❌ VULNERABLE
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub user: Signer<'info>,
    
    #[account(mut)]
    pub vault: Account<'info, Vault>,  // No PDA validation!
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Just checks if vault.owner matches user
    require!(vault.owner == ctx.accounts.user.key(), ErrorCode::Unauthorized);
    
    vault.balance -= amount;
    // Transfer SOL...
    Ok(())
}
```

**The attack:**
1. Alice deposits 100 SOL into her real vault PDA
2. Bob creates a fake "Vault" account with `owner = Alice's pubkey`
3. Bob calls withdraw with Alice's pubkey and HIS fake vault
4. Program checks: "Does vault.owner == Alice? Yes!" ✅
5. Bob withdraws from his fake vault (which has 0 balance)
6. Bob's fake vault balance goes negative (or underflows to max)
7. Bob now has infinite SOL to withdraw

Wait, that doesn't work because the transfer would fail... but you get the idea. The real danger is when the attacker can manipulate what account is used.

## Better Example: The Token Mint

Here's a more realistic exploit:

```rust
// ❌ VULNERABLE
pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
    // Mint tokens to user
    token::mint_to(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            },
        ),
        amount,
    )?;
    Ok(())
}

#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    
    /// CHECK: This should be a PDA but we're not validating it
    pub mint_authority: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
}
```

**The attack:**
1. Attacker creates their own mint authority keypair
2. Attacker passes their keypair as `mint_authority`
3. Program doesn't validate it's the correct PDA
4. Attacker mints infinite tokens

## The Fix: Validate Your PDAs

### Anchor Way (Easy Mode)

```rust
// ✅ SECURE
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub user: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, Vault>,
}
```

That's it. Anchor checks:
1. The PDA is derived from those exact seeds
2. The bump is correct
3. The account is owned by your program

If any check fails, transaction reverts before your code runs.

### Pinocchio Way (Manual Labor)

```rust
// ✅ SECURE
use pinocchio::{
    AccountView,
    Address,
    error::ProgramError,
    ProgramResult,
};

pub fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    let vault = &accounts[1];
    
    // Manually derive the PDA
    let seeds = &[b"vault", user.address().as_ref()];
    let (expected_vault, bump) = Address::find_program_address(seeds, program_id);
    
    // Validate it matches
    if vault.address() != &expected_vault {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Validate owner
    if vault.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    
    // Now safe to proceed...
    Ok(())
}
```

In Pinocchio, you do everything yourself. More code, but also more control.

## Common Mistakes

### Mistake 1: Forgetting the Bump

```rust
// ❌ WRONG
#[account(
    seeds = [b"vault", user.key().as_ref()],
    // Missing bump!
)]
pub vault: Account<'info, Vault>,
```

Without `bump`, Anchor doesn't validate the PDA properly.

### Mistake 2: Wrong Seeds Order

```rust
// ❌ WRONG - seeds in wrong order
#[account(
    seeds = [user.key().as_ref(), b"vault"],  // Reversed!
    bump,
)]
pub vault: Account<'info, Vault>,
```

Seeds order matters. `[b"vault", user]` ≠ `[user, b"vault"]`

### Mistake 3: Using AccountInfo Instead of Account

```rust
// ❌ WRONG
#[account(
    seeds = [b"vault", user.key().as_ref()],
    bump,
)]
pub vault: AccountInfo<'info>,  // Should be Account<'info, Vault>
```

`AccountInfo` doesn't deserialize and validate the data structure.

### Mistake 4: Storing the Bump Wrong

Some people store the bump in the account data:

```rust
#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub bump: u8,  // Stored bump
}
```

Then use it like:

```rust
// ⚠️ RISKY
#[account(
    seeds = [b"vault", user.key().as_ref()],
    bump = vault.bump,  // Using stored bump
)]
pub vault: Account<'info, Vault>,
```

**Problem:** If someone can modify `vault.bump`, they can potentially pass a different account. Always use `bump` without `=` to let Anchor find it.

## Testing the Exploit

Here's a test that demonstrates the attack:

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Keypair, PublicKey } from "@solana/web3.js";

describe("PDA Validation", () => {
  it("Vulnerable: Accepts fake PDA", async () => {
    const user = Keypair.generate();
    
    // Create a FAKE vault (not a PDA)
    const fakeVault = Keypair.generate();
    
    // Initialize fake vault with user as owner
    await vulnerableProgram.methods
      .initializeFakeVault()
      .accounts({
        vault: fakeVault.publicKey,
        owner: user.publicKey,
      })
      .signers([fakeVault])
      .rpc();
    
    // Try to withdraw using fake vault
    await vulnerableProgram.methods
      .withdraw(new anchor.BN(1000))
      .accounts({
        user: user.publicKey,
        vault: fakeVault.publicKey,  // Fake vault!
      })
      .signers([user])
      .rpc();
    
    // ❌ Attack succeeded - used fake vault
    console.log("Attack succeeded!");
  });

  it("Secure: Rejects fake PDA", async () => {
    const user = Keypair.generate();
    const fakeVault = Keypair.generate();
    
    try {
      await secureProgram.methods
        .withdraw(new anchor.BN(1000))
        .accounts({
          user: user.publicKey,
          vault: fakeVault.publicKey,  // Fake vault
        })
        .signers([user])
        .rpc();
      
      throw new Error("Should have failed");
    } catch (err) {
      // ✅ Attack blocked - PDA validation failed
      console.log("Attack blocked!");
    }
  });
});
```

## Why This Matters

PDA validation bugs have caused:
- **Unauthorized minting** - Attackers creating tokens out of thin air
- **Vault draining** - Accessing other users' funds
- **Authority bypass** - Taking control of program-owned accounts

One missing `seeds` constraint can cost millions.

## Security Checklist

Before deploying:

- [ ] All PDAs use `seeds` and `bump` constraints (Anchor)
- [ ] OR manually validate PDA derivation (Pinocchio)
- [ ] Seeds are in the correct order
- [ ] Seeds include all necessary components (user pubkey, etc.)
- [ ] Not using stored bumps for validation
- [ ] PDA owner is verified
- [ ] Tests attempt to pass fake accounts

## Anchor vs Pinocchio

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| PDA Derivation | `seeds` + `bump` constraint | Manual `find_program_address` |
| Validation | Automatic | Manual checks required |
| Code Length | Shorter | Longer |
| Safety | Harder to mess up | Easy to forget checks |
| Performance | Slightly slower | Faster (fewer checks) |

**Recommendation:** Use Anchor unless you really need the performance. PDA validation is too easy to screw up manually.

## Summary

**The vulnerability:** Not validating that a PDA was derived correctly  
**The impact:** Attackers can substitute malicious accounts  
**The fix:** Use `seeds` + `bump` in Anchor, or manually validate in Pinocchio  
**The lesson:** PDAs are only secure if you verify they're real

Don't trust accounts just because they have the right data structure. Verify the address was derived correctly.

---

**Next:** [Arithmetic Overflow →](/2025/01/27/arithmetic-overflow.html)
