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

Ever had that moment when your old-school car odometer ticks over from 999,999 to 000,000 after one extra mile? It feels like you've got a fresh start, but really, it's just rolled over because it can't count any higher. Fun for a laugh in your beat-up ride, but imagine if your bank account did the same thing. Subtract a few bucks from zero, and suddenly you're a billionaire? That's the nightmare of integer overflow in Solana programs. Hackers love this glitch—it's like finding a vending machine that spits out endless candy bars if you punch in a negative number. In a vault holding user funds, one unchecked subtraction can flip a zero balance into a gazillion, letting bad guys waltz off with the entire pot. It's not magic; it's just how computers handle numbers when they run out of digits, and boy, does it keep devs up at night!

## 💡 The "Aha!" Moment

Let's geek out a bit without getting too buried in the weeds—think of it as uncovering why your microwave clock resets at 99:59. Computers stash numbers in fixed-size boxes, like a u64 that's got room for values from 0 up to about 18 quintillion (that's 18 followed by 18 zeros—mind-boggling, right?). Hit the ceiling and add one more? It flips back to zero, like that odometer. Dip below zero with a subtraction? It wraps around to the max value, turning your empty wallet into a treasure chest. The "aha!" clicks when you realize Solana programs often deal with huge numbers for tokens or lamports, and without safeguards, a simple math op can go haywire. Picture a game where scoring too high resets to zero, but in reverse—losing points below zero catapults you to leaderboards. Attackers craft inputs to force this wrap-around, like requesting a withdrawal bigger than your balance, and boom, infinite money glitch unlocked. It's sneaky, but once you see it, you'll never skip those checks again!

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/integer-overflow.svg" alt="Integer Overflow Diagram">
</div>

## 🌍 Real-World Case Study: Jet Protocol Near-Miss (Potential Multi-Million Dollar Vulnerability)

**2021** - Jet Protocol, a lending platform on Solana, dodged a bullet during an audit by Sec3 (formerly Soteria). Auditors spotted unchecked arithmetic in their code that could've led to disastrous overflows and underflows, potentially allowing attackers to manipulate balances and drain funds.

**The Vulnerability:**
In Jet's v1 code, there were spots where balances were updated without checks, like subtracting a note amount from total loan notes or adding to total deposits. Since these were u64 types, an underflow on subtraction (e.g., subtracting more than available) would've wrapped to a huge number, inflating balances artificially. Similarly, unchecked additions could've overflowed, resetting massive values to zero or small numbers.

**The Potential Attack:**
Imagine a user with a small loan trying to repay more than owed—unchecked sub would underflow the total_loan_notes to near-max u64, making it seem like the protocol owed them a fortune. Or depositing a crafted amount that overflows total_deposit, wiping out records. Flash loans could've amplified this, letting attackers borrow huge sums against fake inflated collateral, then vanish with real assets. While not exploited (fixed pre-launch), similar unchecked math has plagued other protocols, and in Jet's case, it could've exposed millions in TVL to theft.

**The Root Cause:**
```rust
// ❌ VULNERABLE CODE (simplified from Jet v1 audit findings)
total_loan_notes -= note_amount;  // Underflow if note_amount > total_loan_notes
total_deposit += token_amount;    // Overflow if sum > u64::MAX
```

**What Should Have Happened (The Fix):**
```rust
// ✅ SECURE VERSION
total_loan_notes = total_loan_notes
    .checked_sub(note_amount)
    .ok_or(ErrorCode::ArithmeticError)?;  // Errors on underflow

total_deposit = total_deposit
    .checked_add(token_amount)
    .ok_or(ErrorCode::ArithmeticError)?;   // Errors on overflow
```

**Lessons Learned:**
This near-miss highlights how even solid teams can overlook arithmetic safety in complex DeFi logic. Audits caught it, but imagine if deployed—losses could've rivaled other Solana hacks like Mango's $100M oracle play. It echoes issues in Ethereum's early days, like the BatchOverflow bug in BEC tokens that minted trillions from nothing. Always audit math ops, folks; one wrap-around can snowball into chaos. Since then, Jet reinforced checks, and the community pushed for tools like Checked Math analyzers to spot these pre-deployment.

## ⚔️ The Exploit

{% include code-compare.html %}

## 🎯 Attack Walkthrough

Buckle up—let's play bad guy for a minute and see how this overflow party gets started. It's like sneaking extra lives in an old arcade game by glitching the score counter.

### Step 1: Attacker Spots the Weakness
Scan the program code for unchecked math, like a simple balance -= amount without .checked_sub(). Zero in on withdraw or repay functions where underflow can flip negatives to positives.

### Step 2: The Attack Setup
```typescript
// Assume vulnerable vault with balance = 0
// Attacker calls withdraw with amount = 1 (or any small number)

// In vulnerable code:
vault.balance = 0 - 1;  // Underflows to u64::MAX (18 quintillion!)

// Program transfers that massive amount to attacker
await vulnerableProgram.methods
  .withdraw(new BN(1))
  .accounts({
    vault: vaultPda,
    user: attacker.publicKey,
  })
  .signers([attacker])
  .rpc();

// 💰 Attacker drains vault dry in one tx
```

### Step 3: What Actually Happens
```
1. Attacker invokes withdraw(1) on zero-balance vault
2. Unchecked sub: 0 - 1 = u64::MAX ❌ (wraps around)
3. Program sees "balance" as huge, allows transfer
4. Vault lamports -= massive amount (drains to attacker)
5. Transaction succeeds ✅
6. Protocol bankrupt 😱
```

## 🧠 Mental Model: The Odometer

Think of your program's integers like that clunky old car odometer—limited digits, no room for extras. Rack up too many miles (overflow), and it resets to zero, pretending nothing happened. Try rolling it backward below zero (underflow), and it jumps to the highest number, like time-traveling to a million miles. In Rust's release mode (what hits Solana mainnet), this wrapping is silent for speed, no alarms blaring. It's like driving blindfolded on a cliff—fine until it's not. Debug mode panics to warn you, but on-chain? Smooth sailing into disaster. Flip this mental switch: every +,-,*,/ is a potential rollover. Guard them like you'd lock your car in a shady lot!

## 🔍 Pinocchio Implementation

Pinocchio keeps it raw, so you've gotta handle checks manually—no Anchor magic here. It's like cooking from scratch: more control, but watch those ingredients!

```rust
use pinocchio::{ProgramResult, error::ProgramError};

fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let vault = &accounts[0];  // Assume deserialized vault
    let user = &accounts[1];

    // Deserialize balance from vault data
    let mut vault_data = vault.data_mut()?;
    let balance = u64::from_le_bytes(vault_data[0..8].try_into()?);

    // ✅ Manual checked sub
    let new_balance = balance.checked_sub(amount).ok_or(ProgramError::Custom(1))?;  // InsufficientFunds

    // Update vault data
    vault_data[0..8].copy_from_slice(&new_balance.to_le_bytes());

    // Transfer lamports safely (Pinocchio handles borrow checks)
    transfer_lamports(vault, user, amount)?;

    Ok(())
}
```

## 🛡️ Defense Patterns

Gear up with these tricks to keep your math bulletproof—think of them as seatbelts for your code's wild ride.

### Pattern 1: Checked Arithmetic Everywhere
```rust
// For any op involving funds
let new_balance = old_balance
    .checked_add(deposit)
    .ok_or(ErrorCode::Overflow)?;
```

### Pattern 2: Saturating Math for Safe Caps
```rust
// Clamps to min/max instead of erroring
let safe_value = risk_level.saturating_mul(factor);  // Won't overflow, caps at u64::MAX
```

### Pattern 3: Input Validation Gates
```rust
if amount > MAX_REASONABLE_AMOUNT || amount == 0 {
    return Err(ErrorCode::InvalidInput);
}
let safe_amount = amount.min(vault.balance);  // Extra layer
```

## 🚨 Common Mistakes

We've all been there—these slip-ups are like forgetting your keys on a road trip. Learn from 'em!

### Mistake 1: Forgetting Release Mode Wrapping
```rust
// ❌ Debug panics, release wraps silently
let result = a + b;  // Boom on mainnet
```

### Mistake 2: Unchecked Casts Between Types
```rust
// ❌ u128 to u64 without check
let small: u64 = big as u64;  // Truncates silently
```

### Mistake 3: Ignoring Mul/Div Order for Precision
```rust
// ❌ Loses fractions
let share = (total / pool) * contribution;  // Division first rounds down
```

### Mistake 4: Assuming Safe Inputs
```rust
// ❌ User can send u64::MAX
let total = user_input1 + user_input2;  // No bounds check
```

## 📊 Testing the Exploit

```typescript
describe("Integer Overflow Exploit", () => {
  it("Vulnerable: Underflow creates infinite balance", async () => {
    // Setup vault with balance 10
    const balanceBefore = 10;
    const withdrawAmount = 20;

    await vulnerableProgram.methods
      .withdraw(new BN(withdrawAmount))
      .accounts({
        vault: vaultPda,
        user: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();

    const vaultBalanceAfter = await getVaultBalance(vaultPda);
    console.log(`Vault balance after: ${vaultBalanceAfter}`);
    console.log(`💰 Attacker withdrew ${withdrawAmount} despite low balance`);

    // In reality, balance wrapped to huge number
    assert(vaultBalanceAfter < 0, "Should have drained beyond zero");  // Simulated
  });

  it("Secure: Checked sub blocks underflow", async () => {
    try {
      await secureProgram.methods
        .withdraw(new BN(20))
        .accounts({
          vault: vaultPda,
          user: attacker.publicKey,
        })
        .signers([attacker])
        .rpc();
      
      assert.fail("Should have errored on insufficient funds");
    } catch (err) {
      assert.include(err.message, "InsufficientFunds");
      console.log("✅ Attack blocked: Checked math prevented wrap-around");
    }
  });

  it("Secure: Legitimate withdraw succeeds", async () => {
    await secureProgram.methods
      .withdraw(new BN(5))
      .accounts({
        vault: vaultPda,
        user: user.publicKey,
      })
      .signers([user])
      .rpc();
    
    console.log("✅ Normal operation works fine");
  });
});
```

## 🔒 Best Practices

1. **Always use checked arithmetic** for any calculation involving user money—it's your first line of defense against the odometer flip.
2. **Configure Cargo.toml** to enable overflow checks in release builds: no silent surprises on mainnet.
   ```toml
   [profile.release]
   overflow-checks = true
   ```
3. **Validate inputs** before performing calculations—think bouncer at the club door, checking IDs.
4. **Use saturating math** (`saturating_add`, `saturating_sub`) when appropriate, like a thermostat that caps at max temp instead of exploding.

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

## 🎓 Key Takeaways

1. **Fixed-Size Limits Matter**: u64 isn't infinite—treat it like a gas tank that overflows messily.
2. **Checked Ops Save Lives**: .checked_* methods are your safety net; use 'em religiously for funds.
3. **Release vs Debug**: What panics locally wraps on-chain—test in release mode!
4. **Input Sanity Checks**: Never trust user numbers; cap and validate everything.
5. **Audits Are Gold**: Like Jet's close call, catch these before launch.
6. **Precision in Mul/Div**: Order ops to avoid rounding pitfalls.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Always use <code>checked_math</code> functions for any calculation involving user money. Silent wrapping is a silent disaster.
</blockquote>

## 🔗 Additional Resources

- [Rust Overflow Semantics](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- [Neodyme Overflow Exploits](https://blog.neodyme.io/)
- [Sec3 on Arithmetic Errors in Solana](https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts)
- [Example Code: Arithmetic Overflow](https://github.com/rainman456/Solana-Security-blog/tree/main/examples/03-arithmetic-overflow)

## ✅ Security Checklist

Before any math op:

- [ ] Using .checked_add/sub/mul/div for all arithmetic
- [ ] overflow-checks = true in Cargo.toml release profile
- [ ] Inputs validated for reasonable bounds
- [ ] Tests include overflow/underflow scenarios
- [ ] Saturating math where capping makes sense
- [ ] No unchecked casts between int types
- [ ] Mul before div for precision in calculations

**Remember**: Math in code isn't like school—computers don't borrow or carry like we do. One unchecked op can turn your secure vault into a piñata. The Jet near-miss shows it's real; stay vigilant!
