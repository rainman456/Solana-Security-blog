---
layout: post
title: "Unsafe Account Closure: Zombie Accounts"
date: 2025-01-27
categories: vulnerabilities
---

# Unsafe Account Closure: Zombie Accounts

Closing an account in Solana seems simple: transfer out the lamports, done.

Nope. Not even close.

Mess this up and you get zombie accounts - accounts that should be dead but can be brought back to life. And when they come back, they bring problems.

## The Problem

In Solana, "closing" an account means:
1. Transfer all lamports out
2. Zero the data
3. Set the owner to the System Program

Most people do step 1. Some do step 2. Almost nobody does step 3 correctly.

## What's a Zombie Account?

An account with 0 lamports that still has data. Technically "closed", but not really.

Why is this bad?

1. **Revival attacks** - Someone can fund it again and reuse the old data
2. **Rent reclamation** - Attacker can reclaim rent from improperly closed accounts
3. **State confusion** - Your program thinks the account is closed, but it's not

## Real Example: The Vault Revival

```rust
// ❌ VULNERABLE
pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    let user = &ctx.accounts.user;
    
    // Transfer lamports to user
    let vault_lamports = vault.to_account_info().lamports();
    **vault.to_account_info().lamports.borrow_mut() = 0;
    **user.lamports.borrow_mut() += vault_lamports;
    
    // ❌ Forgot to zero the data!
    // ❌ Forgot to change owner!
    
    Ok(())
}
```

**The attack:**
1. Alice closes her vault (has 100 SOL balance in data)
2. Vault lamports → 0, but data still says balance = 100 SOL
3. Bob sends 0.001 SOL to the vault address (makes it rent-exempt again)
4. Bob calls `withdraw()` on the "closed" vault
5. Program reads balance = 100 SOL from old data
6. Bob withdraws 100 SOL that doesn't exist

Okay, the withdraw would fail because there's no actual SOL... but what if the program has other bugs? Or what if the data is used for something else?

## Better Example: The Token Account

```rust
#[account]
pub struct TokenVault {
    pub owner: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
}

// ❌ VULNERABLE
pub fn close_token_vault(ctx: Context<CloseTokenVault>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    let user = &ctx.accounts.user;
    
    // Transfer rent to user
    let lamports = vault.to_account_info().lamports();
    **vault.to_account_info().lamports.borrow_mut() = 0;
    **user.lamports.borrow_mut() += lamports;
    
    Ok(())
}
```

**Attack:**
1. Close vault (still has `owner` and `mint` data)
2. Attacker funds the account again
3. Attacker calls `deposit()` with the old owner's signature (if they can get it)
4. Tokens go into the "closed" account
5. Original owner lost their tokens

## The Fix: Properly Close Accounts

### Anchor Way (Easy)

```rust
// ✅ SECURE
#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        mut,
        close = user,  // ← This does everything correctly
        constraint = vault.owner == user.key()
    )]
    pub vault: Account<'info, Vault>,
}

pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
    // Anchor's `close` constraint handles:
    // 1. Transferring lamports to `user`
    // 2. Zeroing the data
    // 3. Setting owner to System Program
    Ok(())
}
```

That's it. The `close = user` constraint does everything.

### Pinocchio Way (Manual)

```rust
// ✅ SECURE
use pinocchio::{
    AccountView,
    error::ProgramError,
    ProgramResult,
};

pub fn close_vault(accounts: &[AccountView]) -> ProgramResult {
    let user = &accounts[0];
    let vault = &accounts[1];
    
    // 1. Verify user is signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // 2. Verify vault owner matches user
    let owner_bytes = &vault.data()[0..32];
    if owner_bytes != user.address().as_ref() {
        return Err(ProgramError::IllegalOwner);
    }
    
    // 3. Transfer ALL lamports to user
    let vault_lamports = **vault.lamports.borrow();
    **vault.lamports.borrow_mut() = 0;
    **user.lamports.borrow_mut() += vault_lamports;
    
    // 4. Zero the data
    vault.data().fill(0);
    
    // 5. Assign to System Program
    **vault.owner.borrow_mut() = system_program::ID;
    
    Ok(())
}
```

All 5 steps are necessary.

## Common Mistakes

### Mistake 1: Only Transferring Lamports

```rust
// ❌ WRONG
**vault.lamports.borrow_mut() = 0;
**user.lamports.borrow_mut() += vault_lamports;
// Forgot to zero data and change owner!
```

Data persists. Account can be revived.

### Mistake 2: Not Transferring ALL Lamports

```rust
// ❌ WRONG
let rent_exempt = Rent::get()?.minimum_balance(vault.data_len());
**vault.lamports.borrow_mut() = rent_exempt;  // Left some lamports!
**user.lamports.borrow_mut() += vault_lamports - rent_exempt;
```

Account is still rent-exempt. Not actually closed.

### Mistake 3: Zeroing Data But Not Changing Owner

```rust
// ❌ INCOMPLETE
vault.data().fill(0);
**vault.lamports.borrow_mut() = 0;
// Forgot to change owner!
```

Your program still owns the account. Can be reinitialized.

### Mistake 4: Wrong Close Destination

```rust
// ❌ DANGEROUS
#[account(
    mut,
    close = authority,  // Who is authority?
)]
pub vault: Account<'info, Vault>,
```

If `authority` can be manipulated, attacker can steal the rent.

## The Rent Reclamation Attack

Here's a subtle one:

```rust
// Program A closes an account, sending rent to user
#[account(mut, close = user)]
pub vault: Account<'info, Vault>,

// But Program B can also close the same account!
// If Program B runs first, it steals the rent
```

**Attack:**
1. User creates transaction: [Program B close, Program A close]
2. Program B closes account, sends rent to attacker
3. Program A tries to close account, but it's already closed
4. Program A fails, but Program B already stole the rent

**Fix:** Check that the account is still owned by your program before closing.

## Testing Account Closure

```typescript
describe("Account Closure", () => {
  it("Vulnerable: Account can be revived", async () => {
    // Create and close vault
    await vulnerableProgram.methods
      .closeVault()
      .accounts({ /* ... */ })
      .rpc();
    
    // Check account is "closed"
    let vaultAccount = await provider.connection.getAccountInfo(vaultPda);
    console.log("Lamports:", vaultAccount.lamports);  // 0
    console.log("Data:", vaultAccount.data);  // Still has data!
    
    // Fund the account again
    await provider.connection.requestAirdrop(vaultPda, 1_000_000);
    
    // Account is now "alive" again with old data
    vaultAccount = await provider.connection.getAccountInfo(vaultPda);
    console.log("Revived! Lamports:", vaultAccount.lamports);
    // ❌ Zombie account is back
  });

  it("Secure: Account properly closed", async () => {
    await secureProgram.methods
      .closeVault()
      .accounts({ /* ... */ })
      .rpc();
    
    // Check account is actually closed
    const vaultAccount = await provider.connection.getAccountInfo(vaultPda);
    
    console.log("Lamports:", vaultAccount.lamports);  // 0
    console.log("Data length:", vaultAccount.data.length);  // 0
    console.log("Owner:", vaultAccount.owner.toString());  // System Program
    
    // Try to revive
    await provider.connection.requestAirdrop(vaultPda, 1_000_000);
    
    // Account is now owned by System Program, can't be used by our program
    // ✅ Properly closed
  });
});
```

## When Does This Matter?

Account closure bugs are dangerous when:

1. **Accounts store value** - Tokens, SOL, NFTs
2. **Accounts store permissions** - Admin rights, ownership
3. **Accounts are reusable** - Same PDA can be recreated
4. **Rent is significant** - Attacker profits from stealing rent

If your accounts are small and worthless, you're probably fine. But why risk it?

## Security Checklist

- [ ] All lamports transferred out (not just some)
- [ ] Account data is zeroed
- [ ] Account owner set to System Program
- [ ] Close destination is validated (can't be manipulated)
- [ ] Tests verify account is fully closed
- [ ] Tests verify account can't be revived

## Anchor's `close` Constraint

The `close` constraint does this:

```rust
// What Anchor does internally:
// 1. Transfer all lamports to destination
**destination.lamports.borrow_mut() += account.lamports();
**account.lamports.borrow_mut() = 0;

// 2. Zero the data
account.data.borrow_mut().fill(0);

// 3. Set owner to System Program
**account.owner.borrow_mut() = system_program::ID;
```

Use it. Don't reinvent the wheel.

## Summary

**The vulnerability:** Not properly closing accounts (leaving data, lamports, or wrong owner)  
**The impact:** Zombie accounts, revival attacks, rent theft  
**The fix:** Transfer all lamports, zero data, set owner to System Program  
**The lesson:** Closing accounts is harder than it looks

In Anchor, use `close = destination`. In Pinocchio, do all 5 steps manually. Don't half-ass it.

---

**That's all 5 vulnerabilities!** Now go write secure programs.

[Back to Home](/)
