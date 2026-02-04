---
layout: post
title: "Integer Arithmetic Overflow"
date: 2025-01-27
category: "Data Integrity"
difficulty: "Beginner"
risk_level: "High"
description: "A u64 can't go below zero or above its max. If you subtract from zero, it wraps to a massive number. Attackers exploit this to turn 0 balance into trillions."
impact: "Complete loss of funds. An attacker can withdraw unlimited amounts by causing integer underflow."
recommendation: "Always use .checked_add(), .checked_sub(), .checked_mul() for all arithmetic operations involving user funds or critical state."
tags:
  - Rust
  - Math
  - Overflow
checklist: 
  - "Are you using .checked_add(), .checked_sub(), etc.?"
  - "Or: Are you compiling with overflow-checks = true in Cargo.toml?"
  - "Do you validate inputs to ensure they are within reasonable bounds?"
vulnerable_code: |
  pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
      // ❌ VULNERABLE: Using standard subtraction
      // If balance = 10, amount = 20...
      // Result: 18,446,744,073,709,551,606 (wrapped!)
      vault.balance = vault.balance - amount;
      
      // Transfer SOL
      **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
      **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? += amount;
      
      Ok(())
  }
secure_code: |
  pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
      // ✅ SECURE: Using checked arithmetic
      // Returns None if result would overflow/underflow
      vault.balance = vault.balance
          .checked_sub(amount)
          .ok_or(ErrorCode::InsufficientFunds)?;
      
      // Transfer SOL
      **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
      **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? += amount;
      
      Ok(())
  }
---

## 📖 The Scenario

Your car's odometer reads 999,999 miles. You drive one more mile. Suddenly, the odometer snaps back to 000,000. It looks brand new!

This is exactly how computer numbers work. A `u8` can hold 0 to 255. If you have 255 and add 1, it wraps around to 0. If you have 0 and subtract 1, it wraps around to the massive number 255. **In a vault, this means a hacker can turn 0 balance into millions.**

## 💡 The "Aha!" Moment

Computers typically use **fixed-size integers**. They don't have infinite space.

- `u64` max: ~18 quintillion
- `u64` min: 0

If your code allows a user to withdraw more than they have, `0 - 100` doesn't equal `-100`. In `u64` land, it equals `18,446,744,073,709,551,516`. Oops.

## ⚔️ The Exploit

{% include code-compare.html %}

## 🧠 Mental Model: The Odometer

Always remember the car odometer:
- **Overflow**: Going over the max (999,999 → 000,000)
- **Underflow**: Going below zero (0 → 999,999)

Rust in "Debug" mode panics on overflow. **Rust in "Release" mode (deployed to mainnet) usually wraps silently** for performance reasons, unless you explicitly change `Cargo.toml`.

## 🔒 Best Practices

1. **Always use checked arithmetic** for any calculation involving user money
2. **Configure Cargo.toml** to enable overflow checks in release builds:
   ```toml
   [profile.release]
   overflow-checks = true
   ```
3. **Validate inputs** before performing calculations
4. **Use saturating math** (`saturating_add`, `saturating_sub`) when appropriate

## 🧪 Testing for Overflow

```rust
#[test]
fn test_overflow_protection() {
    let balance: u64 = 10;
    let withdraw: u64 = 20;
    
    // This would panic in debug, wrap in release
    // let result = balance - withdraw; // DON'T DO THIS
    
    // This returns None, allowing safe error handling
    let result = balance.checked_sub(withdraw);
    assert!(result.is_none());
}
```

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Always use <code>checked_math</code> functions for any calculation involving user money. Silent wrapping is a silent disaster.
</blockquote>

## 📚 Further Reading

- [Rust Overflow Semantics](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- [Neodyme Overflow Exploits](https://blog.neodyme.io/)