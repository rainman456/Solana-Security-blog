---
layout: post
title: "Arithmetic Overflow: When Numbers Lie"
date: 2025-01-27
categories: vulnerabilities
---

# Arithmetic Overflow: When Numbers Lie

Pop quiz: What's 255 + 1 in Rust?

If you said "256", you're wrong. Well, you're right in debug mode, but wrong in release mode.

In release mode (which Solana uses), it's **0**.

Yeah. Let that sink in.

## The Odometer Problem

Remember old cars with odometers that only went to 999,999 miles? Hit that limit and it rolled back to 000,000.

That's exactly what happens with integer overflow:

```rust
let balance: u8 = 255;
let new_balance = balance + 1;  // new_balance = 0 🤯
```

In Rust debug builds, this panics. In release builds (what Solana uses), it wraps around silently.

## Why This Is Dangerous

Imagine a token program:

```rust
// ❌ VULNERABLE
pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let from = &mut ctx.accounts.from;
    let to = &mut ctx.accounts.to;
    
    from.balance = from.balance - amount;  // Can underflow!
    to.balance = to.balance + amount;      // Can overflow!
    
    Ok(())
}
```

**The attack:**
1. Alice has 100 tokens
2. Alice tries to transfer 200 tokens
3. `100 - 200` underflows to `18,446,744,073,709,551,516` (max u64)
4. Alice now has infinite tokens

Or the reverse:
1. Bob has `u64::MAX - 50` tokens
2. Someone sends Bob 100 tokens
3. Overflow wraps to 49
4. Bob just lost billions of tokens

## Real Example: The Infinite Mint

Here's how this actually gets exploited:

```rust
// ❌ VULNERABLE
#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // No overflow check!
    vault.balance = vault.balance - amount;
    
    // Transfer SOL to user
    **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
    
    Ok(())
}
```

**Attack:**
1. Deposit 1 SOL into vault (balance = 1,000,000,000 lamports)
2. Withdraw `u64::MAX` lamports
3. `1,000,000,000 - u64::MAX` underflows
4. Vault balance wraps to some huge number
5. The actual SOL transfer fails, but balance is already corrupted
6. Repeat withdrawals until vault is drained

Wait, the transfer would fail... but what if we're clever?

```rust
// Withdraw just enough to underflow
let amount = vault.balance + 1;
// balance = 1,000,000,000
// amount = 1,000,000,001
// 1,000,000,000 - 1,000,000,001 = u64::MAX
```

Now the balance is corrupted, and we can withdraw in smaller chunks.

## The Fix: Checked Arithmetic

### Option 1: Enable Overflow Checks

In `Cargo.toml`:

```toml
[profile.release]
overflow-checks = true
```

Now overflows panic even in release mode. Simple, but adds overhead to EVERY arithmetic operation.

### Option 2: Use Checked Methods (Better)

```rust
// ✅ SECURE
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Use checked_sub - returns None on overflow
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientFunds)?;
    
    // Transfer SOL
    **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
    
    Ok(())
}
```

Rust's checked arithmetic methods:
- `checked_add(x)` - Returns `None` on overflow
- `checked_sub(x)` - Returns `None` on underflow
- `checked_mul(x)` - Returns `None` on overflow
- `checked_div(x)` - Returns `None` on division by zero

### Option 3: Saturating Arithmetic (Sometimes)

```rust
let balance = balance.saturating_sub(amount);
// If amount > balance, result is 0 (doesn't underflow)
```

**Warning:** Saturating can hide bugs. If you expect the operation to fail, use `checked_*` instead.

## Anchor Example

```rust
use anchor_lang::prelude::*;

#[program]
pub mod secure_vault {
    use super::*;
    
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ✅ Checked addition
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        
        // Transfer SOL
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.user.to_account_info(),
                to: vault.to_account_info(),
            },
        );
        system_program::transfer(cpi_context, amount)?;
        
        Ok(())
    }
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // ✅ Checked subtraction
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        
        // Transfer SOL
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
        
        Ok(())
    }
}

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
```

## Pinocchio Example

```rust
use pinocchio::{
    AccountView,
    error::ProgramError,
    ProgramResult,
};

pub fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    let vault = &accounts[1];
    
    // Read current balance (assuming it's stored at offset 0)
    let balance_bytes = &vault.data()[0..8];
    let balance = u64::from_le_bytes(balance_bytes.try_into().unwrap());
    
    // ✅ Checked subtraction
    let new_balance = balance
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;
    
    // Write new balance
    vault.data()[0..8].copy_from_slice(&new_balance.to_le_bytes());
    
    // Transfer lamports
    **vault.lamports.borrow_mut() -= amount;
    **user.lamports.borrow_mut() += amount;
    
    Ok(())
}
```

## Common Mistakes

### Mistake 1: Only Checking One Side

```rust
// ❌ WRONG
vault.balance = vault.balance.checked_sub(amount)?;
user.balance = user.balance + amount;  // Forgot to check!
```

Check BOTH operations. Addition can overflow too.

### Mistake 2: Checking After the Fact

```rust
// ❌ WRONG
vault.balance = vault.balance - amount;
require!(vault.balance >= 0, ErrorCode::Underflow);  // Too late!
```

The underflow already happened. Check BEFORE the operation.

### Mistake 3: Using Wrong Type

```rust
// ❌ RISKY
let amount: u64 = 1_000_000_000;
let fee: u8 = 10;  // u8 can only hold 0-255
let total = amount + fee as u64;  // Casting can truncate!
```

Be careful with type conversions. `u64` to `u32` can overflow.

## Testing Overflow

```typescript
import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";

describe("Arithmetic Overflow", () => {
  it("Vulnerable: Allows underflow", async () => {
    // Deposit 1 SOL
    await vulnerableProgram.methods
      .deposit(new BN(1_000_000_000))
      .accounts({ /* ... */ })
      .rpc();
    
    // Try to withdraw more than deposited
    await vulnerableProgram.methods
      .withdraw(new BN(2_000_000_000))
      .accounts({ /* ... */ })
      .rpc();
    
    // ❌ Balance underflowed to huge number
    const vault = await vulnerableProgram.account.vault.fetch(vaultPda);
    console.log("Balance:", vault.balance.toString());
    // Output: Balance: 18446744072709551616 (underflowed!)
  });

  it("Secure: Prevents underflow", async () => {
    await secureProgram.methods
      .deposit(new BN(1_000_000_000))
      .accounts({ /* ... */ })
      .rpc();
    
    try {
      await secureProgram.methods
        .withdraw(new BN(2_000_000_000))
        .accounts({ /* ... */ })
        .rpc();
      
      throw new Error("Should have failed");
    } catch (err) {
      // ✅ Transaction failed with InsufficientFunds
      console.log("Underflow prevented!");
    }
  });
});
```

## When to Use What

| Method | When to Use |
|--------|-------------|
| `checked_*` | Default choice - explicit error handling |
| `saturating_*` | When clamping to min/max is acceptable |
| `wrapping_*` | When overflow is intentional (rare) |
| `overflow-checks = true` | When you want global protection |

**Recommendation:** Use `checked_*` everywhere. Be explicit about overflow handling.

## Real-World Impact

Overflow bugs have caused:
- **Token minting exploits** - Creating tokens from nothing
- **Balance manipulation** - Negative balances becoming huge positive balances
- **Reward calculation errors** - Users claiming infinite rewards

One missing `checked_sub` can drain a protocol.

## Security Checklist

- [ ] All addition uses `checked_add` or overflow checks enabled
- [ ] All subtraction uses `checked_sub`
- [ ] All multiplication uses `checked_mul`
- [ ] Division checks for zero divisor
- [ ] Type conversions are safe (no truncation)
- [ ] Tests verify overflow/underflow is prevented

## Summary

**The vulnerability:** Arithmetic operations overflow/underflow silently in release mode  
**The impact:** Balance manipulation, infinite minting, fund drainage  
**The fix:** Use `checked_*` methods or enable overflow checks  
**The lesson:** Never trust arithmetic operations in Rust release builds

Rust doesn't protect you by default. You have to protect yourself.

---

**Next:** [Reentrancy Risk →](/2025/01/27/reentrancy-risk.html)
