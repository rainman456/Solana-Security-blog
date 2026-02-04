---
layout: post
title: "Integer Arithmetic Overflow"
date: 2025-01-27
category: "Data Integrity"
difficulty: "Beginner"
checklist: 
  - "Are you using `.checked_add()`, `.checked_sub()`, etc.?"
  - "Or: Are you compiling with `overflow-checks = true` in Cargo.toml?"
  - "Do you validate inputs to ensure they are within reasonable bounds?"
---

## 📖 The Scenario
Your car's odometer reads 999,999 miles. You drive one more mile. Suddenly, the odometer snaps back to 000,000. It looks brand new!

This is exactly how computer numbers work. A `u8` can hold 0 to 255. If you have 255 and add 1, it wraps around to 0. If you have 0 and subtract 1, it wraps around to the massive number 255. In a vault, this means a hacker can turn 0 balance into millions.

## 💡 The "Aha!" Moment
Computers typically use **fixed-size integers**. They don't have infinite space.
- `u64` max: ~18 quintillion.
- `u64` min: 0.

If your code allows a user to withdraw more than they have, `0 - 100` doesn't equal `-100`. In `u64` land, it equals `18,446,744,073,709,551,516`. Oops.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/arithmetic-overflow.svg" alt="Arithmetic Overflow Diagram">
</div>

## ⚔️ The Exploit
### Vulnerable vs Secure

{% capture vulnerable_desc %}
Using standard `+` or `-` operators allows "wrapping" behavior in release builds (unless configured otherwise).
{% endcapture %}

{% capture vulnerable_code %}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // ❌ Vulnerable to underflow!
    // If balance = 10, amount = 20...
    // New Balance = 18.4 Quintillion
    vault.balance = vault.balance - amount; 
    ...
}
{% endcapture %}

{% capture secure_desc %}
Using `.checked_sub()` ensures the operation returns `None` (error) if math is impossible.
{% endcapture %}

{% capture secure_code %}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // ✅ Safely fails if balance < amount
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientFunds)?;
    ...
}
{% endcapture %}

{% include comparison-card.html 
   vulnerable_desc=vulnerable_desc 
   vulnerable_code=vulnerable_code 
   secure_desc=secure_desc 
   secure_code=secure_code 
%}

## 🧠 Mental Model: The Odometer
Always remember the car odometer.
- **Overflow**: Going over the max (999 -> 0).
- **Underflow**: Going below zero (0 -> 999).

Rust in "Debug" mode panics on overflow. **Rust in "Release" mode (deployed to mainnet) usually wraps silently** for performance reasons, unless you explicitly change `Cargo.toml`.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Always use <code>checked_math</code> functions for any calculation involving user money. Silent wrapping is a silent header crash.
</blockquote>
