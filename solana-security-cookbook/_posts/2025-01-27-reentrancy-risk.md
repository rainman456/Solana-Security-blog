---
layout: post
title: "Reentrancy in Solana: Not Your Ethereum Problem (But Still a Problem)"
date: 2025-01-27
categories: vulnerabilities
---

# Reentrancy in Solana: Not Your Ethereum Problem (But Still a Problem)

If you're coming from Ethereum, you know about reentrancy. The DAO hack. `checks-effects-interactions`. All that.

Solana's different. No external calls in the middle of execution, right? Wrong.

Solana has **CPI** (Cross-Program Invocation), and if you're not careful, you can still get rekt.

## What's Reentrancy?

Simple version: Your program calls another program, and that program calls back into yours before the first call finishes.

Ethereum example:
```solidity
// ❌ VULNERABLE
function withdraw() public {
    uint amount = balances[msg.sender];
    msg.sender.call{value: amount}("");  // External call
    balances[msg.sender] = 0;  // Too late!
}
```

Attacker's contract receives the ETH, calls `withdraw()` again, gets paid twice.

## Solana's Different... Sort Of

In Solana, you can't directly call back into a program during execution. But you CAN:

1. Call another program via CPI
2. That program modifies your accounts
3. Your program continues with stale state

It's not traditional reentrancy, but the effect is similar: **state changes happen in unexpected order**.

## The Real Vulnerability: State After CPI

Here's the actual bug pattern in Solana:

```rust
// ❌ VULNERABLE
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    let user = &ctx.accounts.user;
    
    // CPI to transfer tokens
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: vault.to_account_info(),
                to: user.to_account_info(),
                authority: vault.to_account_info(),
            },
        ),
        amount,
    )?;
    
    // ❌ Update state AFTER CPI
    vault.balance -= amount;
    
    Ok(())
}
```

**The attack:**
1. Call `withdraw(100)`
2. CPI transfers 100 tokens
3. Before state updates, call `withdraw(100)` again
4. Vault still shows full balance
5. Get 100 tokens again
6. Repeat until drained

Wait, how do you call it again before it finishes? You can't... directly.

## The Actual Attack Vector

The real danger is when your program can be called multiple times in the same transaction:

```rust
// User creates a transaction with multiple instructions:
// 1. withdraw(100)
// 2. withdraw(100)
// 3. withdraw(100)

// Each instruction sees the same initial state
// because state updates happen at the end
```

Or through CPI chains:
```
Your Program → Malicious Program → Your Program (via CPI)
```

The malicious program calls back into yours before the first call completes.

## Real Example: The Vault Drain

```rust
// ❌ VULNERABLE
#[program]
pub mod vulnerable_vault {
    use super::*;
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Check balance
        require!(vault.balance >= amount, ErrorCode::InsufficientFunds);
        
        // Transfer SOL via CPI
        let cpi_context = CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: vault.to_account_info(),
                to: ctx.accounts.user.to_account_info(),
            },
            &[&[b"vault", &[vault.bump]]],
        );
        system_program::transfer(cpi_context, amount)?;
        
        // ❌ State update AFTER transfer
        vault.balance -= amount;
        
        Ok(())
    }
}
```

**Attack:**
```typescript
// Create transaction with multiple withdraw instructions
const tx = new Transaction();

for (let i = 0; i < 10; i++) {
  tx.add(
    await program.methods
      .withdraw(new BN(1_000_000))
      .accounts({ /* ... */ })
      .instruction()
  );
}

// All 10 withdrawals see the same balance
// Each one succeeds
// Vault drained 10x
```

## The Fix: Update State First

```rust
// ✅ SECURE
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ Update state FIRST
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientFunds)?;
    
    // Then do CPI
    let cpi_context = CpiContext::new_with_signer(
        ctx.accounts.system_program.to_account_info(),
        system_program::Transfer {
            from: vault.to_account_info(),
            to: ctx.accounts.user.to_account_info(),
        },
        &[&[b"vault", &[vault.bump]]],
    );
    system_program::transfer(cpi_context, amount)?;
    
    Ok(())
}
```

Now if someone tries multiple withdrawals:
1. First withdrawal: balance = 1000 - 100 = 900 ✅
2. Second withdrawal: balance = 900 - 100 = 800 ✅
3. Tenth withdrawal: balance = 200 - 100 = 100 ✅
4. Eleventh withdrawal: 100 - 100 = 0 ✅
5. Twelfth withdrawal: 0 - 100 = underflow ❌ FAIL

## Checks-Effects-Interactions Pattern

This is the same pattern from Ethereum, just adapted:

1. **Checks** - Validate inputs, permissions, state
2. **Effects** - Update your program's state
3. **Interactions** - Call other programs via CPI

```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // 1. CHECKS
    require!(ctx.accounts.vault.owner == ctx.accounts.user.key(), ErrorCode::Unauthorized);
    require!(ctx.accounts.vault.balance >= amount, ErrorCode::InsufficientFunds);
    
    // 2. EFFECTS
    ctx.accounts.vault.balance -= amount;
    
    // 3. INTERACTIONS
    token::transfer(/* CPI call */)?;
    
    Ok(())
}
```

## Pinocchio Example

```rust
use pinocchio::{
    AccountView,
    error::ProgramError,
    ProgramResult,
};
use pinocchio_system::instructions::Transfer;

pub fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    let vault = &accounts[1];
    
    // Read current balance
    let balance_bytes = &vault.data()[0..8];
    let balance = u64::from_le_bytes(balance_bytes.try_into().unwrap());
    
    // 1. CHECKS
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // 2. EFFECTS - Update state FIRST
    let new_balance = balance
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;
    
    vault.data()[0..8].copy_from_slice(&new_balance.to_le_bytes());
    
    // 3. INTERACTIONS - CPI last
    Transfer {
        from: vault,
        to: user,
        lamports: amount,
    }
    .invoke_signed(&[&[b"vault", &[bump]]])?;
    
    Ok(())
}
```

## Common Mistakes

### Mistake 1: Checking State After CPI

```rust
// ❌ WRONG
token::transfer(cpi_ctx, amount)?;

// Check if balance is still valid
require!(vault.balance >= amount, ErrorCode::InsufficientFunds);
vault.balance -= amount;
```

The check is useless. The transfer already happened.

### Mistake 2: Multiple State Updates

```rust
// ❌ RISKY
vault.balance -= amount;  // First update

token::transfer(cpi_ctx, amount)?;

vault.last_withdrawal = Clock::get()?.unix_timestamp;  // Second update
```

If the CPI fails, the first update already happened. Use a single atomic update or revert everything.

### Mistake 3: Trusting Account State During CPI

```rust
// ❌ WRONG
let initial_balance = vault.balance;

some_cpi_call()?;  // This might modify vault!

// Don't trust initial_balance anymore
vault.balance = initial_balance - amount;
```

If the CPI can modify `vault`, your cached value is stale.

## Testing Reentrancy

```typescript
describe("Reentrancy", () => {
  it("Vulnerable: Allows multiple withdrawals", async () => {
    // Deposit 10 SOL
    await program.methods
      .deposit(new BN(10_000_000_000))
      .accounts({ /* ... */ })
      .rpc();
    
    // Create transaction with 20 withdrawals of 1 SOL each
    const tx = new Transaction();
    for (let i = 0; i < 20; i++) {
      tx.add(
        await vulnerableProgram.methods
          .withdraw(new BN(1_000_000_000))
          .accounts({ /* ... */ })
          .instruction()
      );
    }
    
    await provider.sendAndConfirm(tx);
    
    // ❌ Withdrew 20 SOL but only had 10
    const vault = await program.account.vault.fetch(vaultPda);
    console.log("Balance:", vault.balance.toString());
    // Balance is negative or underflowed
  });

  it("Secure: Prevents multiple withdrawals", async () => {
    await program.methods
      .deposit(new BN(10_000_000_000))
      .accounts({ /* ... */ })
      .rpc();
    
    const tx = new Transaction();
    for (let i = 0; i < 20; i++) {
      tx.add(
        await secureProgram.methods
          .withdraw(new BN(1_000_000_000))
          .accounts({ /* ... */ })
          .instruction()
      );
    }
    
    try {
      await provider.sendAndConfirm(tx);
      throw new Error("Should have failed");
    } catch (err) {
      // ✅ Transaction failed after 10 withdrawals
      console.log("Reentrancy prevented!");
    }
  });
});
```

## When Is This Actually Dangerous?

Reentrancy in Solana is dangerous when:

1. **Multiple instructions in one transaction** - User can call your program multiple times
2. **CPI chains** - Program A → Program B → Program A
3. **Composability** - Other programs integrate with yours
4. **Flash loans** - Borrow, exploit, repay in one transaction

If your program is isolated and only called once per transaction, you're probably safe. But don't bet on it.

## Security Checklist

- [ ] All state updates happen before CPI calls
- [ ] No state reads after CPI (they might be stale)
- [ ] Balance checks use `checked_sub` (prevents underflow)
- [ ] Tests include multiple instructions in one transaction
- [ ] Consider: Can this program be called via CPI?

## Anchor vs Pinocchio

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| CPI Calls | `CpiContext::new` | Manual `invoke_signed` |
| State Updates | Same pattern applies | Same pattern applies |
| Safety | No automatic protection | No automatic protection |

**Both frameworks require you to manually order operations correctly.**

## Summary

**The vulnerability:** Updating state after CPI calls  
**The impact:** Multiple withdrawals, drained vaults, double-spending  
**The fix:** Always update state before making CPI calls  
**The lesson:** Checks-Effects-Interactions isn't just for Ethereum

Solana's reentrancy is different from Ethereum's, but the solution is the same: update state first, then interact with other programs.

---

**Next:** [Unsafe Account Closure →](/2025/01/27/unsafe-account-closure.html)
