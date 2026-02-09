---
layout: post
title: "Cross-Program Reentrancy"
date: 2025-01-27
category: "External Interactions"
difficulty: "Advanced"
risk_level: "Critical"
description: "Malicious programs can call back into your program before state updates complete, draining funds repeatedly."
impact: "Complete loss of funds. Attackers can withdraw unlimited amounts by re-entering the withdraw function before balance updates."
recommendation: "Follow Checks-Effects-Interactions pattern: update all state BEFORE making any CPIs (Cross-Program Invocations)."
tags:
  - Rust
  - CPI
  - Reentrancy
checklist: 
  - "Do you update state BEFORE calling another program (CPI)?"
  - "Are you following the 'Checks-Effects-Interactions' pattern?"
  - "Be careful with 'invoke_signed' if you haven't updated balances yet."
vulnerable_code: |
  pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
      // ❌ VULNERABLE: Interactions BEFORE Effects
      
      // 1. Check Balance
      require!(
          ctx.accounts.vault.balance >= amount,
          ErrorCode::InsufficientFunds
      );
  
      // 2. Transfer (CPI) - DANGER ZONE 🚨
      // Control hands over to recipient here!
      // They can call withdraw() again before we update balance!
      anchor_lang::solana_program::program::invoke(
          &system_instruction::transfer(
              ctx.accounts.vault.key,
              ctx.accounts.user.key,
              amount,
          ),
          &[ctx.accounts.vault.to_account_info(), ctx.accounts.user.to_account_info()],
      )?;
  
      // 3. Update Balance (Too late! Re-entrant call sees old balance)
      ctx.accounts.vault.balance -= amount;
      
      Ok(())
  }
secure_code: |
  pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
      // ✅ SECURE: Checks-Effects-Interactions Pattern
      
      // 1. CHECKS: Verify the request is valid
      require!(
          ctx.accounts.vault.balance >= amount,
          ErrorCode::InsufficientFunds
      );
  
      // 2. EFFECTS: Update state FIRST ✅
      // Re-entrant calls will now see the updated (lower) balance
      ctx.accounts.vault.balance -= amount;
  
      // 3. INTERACTIONS: Now safe to call external programs 🚀
      anchor_lang::solana_program::program::invoke(
          &system_instruction::transfer(
              ctx.accounts.vault.key,
              ctx.accounts.user.key,
              amount,
          ),
          &[ctx.accounts.vault.to_account_info(), ctx.accounts.user.to_account_info()],
      )?;
      
      Ok(())
  }
---

## 📖 The Scenario
Think of yourself as a busy bartender at a crowded pub. A customer slides over a tab for $50. You grab the cash from the register and hand it over as change. Then, you turn to jot down "paid" on their tab slip.

But in that split second while you're scribbling, the sneaky customer shouts, "Hey, I think you forgot—my tab's still open!" Since you haven't marked it yet, you check the slip, see it's unpaid, and hand over another $50. They keep this up until the register's empty, all before you finish that one note. Chaos! In Solana, this is the reentrancy trap: your program hands over control during a CPI, and a malicious callee sneaks back in before you update the state, seeing the old "unpaid" balance and scoring multiple payouts. It's like a time loop where the bad guy gets infinite do-overs!

## 💡 The "Aha!" Moment
Let's unpack this like a mystery novel—you're the detective, and the villain is hiding in the call stack. When your Solana program makes a CPI, it's like outsourcing a job to another contractor. You pause your work, hand them the tools (accounts), and let them take the wheel.

Here's the plot twist: Solana's runtime makes classic reentrancy trickier than in Ethereum— the called program can't directly loop back to you in the same way, thanks to stack limits and account rules. But if you pass writable accounts and the callee is crafty, they can CPI back before your state updates, seeing the old data and exploiting it. The "aha!" is realizing CPIs are synchronous but can nest up to depth 4, and without proper ordering, a malicious callback can re-enter your logic with stale state. It's like lending your car keys to a "friend" who drives off, then sneaks back to borrow it again before you notice it's gone.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/reentrancy.svg" alt="Reentrancy Vulnerability Diagram">
</div>

## 🌍 Real-World Case Study: Potential Reentrancy in Solana Audits (From Security Audits like Sec3 and Helius Reports)

While major exploited reentrancy cases are rare in Solana (thanks to the runtime's built-in guards like call stack depth limit of 4 and no direct call-backs), audits have flagged potential issues. For instance, in Sec3's audits of Solana programs, they've noted risks where CPIs to untrusted programs with writable accounts could lead to reentrant-like behavior if not following CEI strictly.

**The Vulnerability:**
In a hypothetical lending protocol (inspired by audit findings in protocols like UXD or Tulip), the borrow function checks collateral, makes a CPI to transfer tokens to the borrower, then updates the debt balance. If the borrower is a malicious program, it could potentially CPI back (if stack allows) before the debt is recorded, borrowing again against the same collateral.

**The Attack:**
1. User (malicious program) calls borrow on lending protocol.
2. Lending protocol checks collateral, CPIs to token program or malicious's account to transfer loan.
3. Malicious program receives control, CPIs back to lending protocol's borrow with the same accounts (if writable passed).
4. Lending sees old debt (zero), approves another loan.
5. Repeat until stack limit or funds drained.
6. **Result: Multi-million dollar potential loss, though mitigated by stack depth.**

**The Root Cause:**
```rust
// ❌ VULNERABLE CODE (simplified from audit findings)
pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    // Check collateral
    require!(ctx.accounts.user.collateral >= amount * RATIO, ErrorCode::InsufficientCollateral);
    
    // CPI to transfer loan (passes writable accounts)
    transfer_loan(&ctx, amount)?;  // Malicious borrower can re-enter here
    
    // Update debt too late
    ctx.accounts.user.debt += amount;
}
```

**What Should Have Happened:**
```rust
// ✅ SECURE VERSION
pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    // Check collateral
    require!(ctx.accounts.user.collateral >= amount * RATIO, ErrorCode::InsufficientCollateral);
    
    // Update debt first
    ctx.accounts.user.debt += amount;
    
    // Now safe to transfer
    transfer_loan(&ctx, amount)?;
}
```

**Lessons Learned:**
Solana's design makes reentrancy harder— no fallback functions, synchronous CPIs, stack limits—but not impossible if you pass writable accounts to untrusted programs. Audits from teams like Sec3 and OtterSec emphasize CEI to prevent even rare cases. In Ethereum, reentrancy drained billions (like The DAO), but Solana's restrictions have kept major exploits at bay. Still, one slip in CPI order, and your protocol could be the first big case!

## ⚔️ The Exploit

{% include code-compare.html %}

## 🎯 Attack Walkthrough

Let's dive into the heist like we're planning a movie robbery—step by step, with the attacker as the clever thief exploiting that brief window.

### Step 1: Attacker Sets Up Malicious Program
```rust
// Malicious Borrower Program
use anchor_lang::prelude::*;

#[program]
pub mod malicious_borrower {
    use super::*;
    
    pub fn receive_loan(ctx: Context<ReceiveLoan>) -> Result<()> {
        msg!("Got the loan! Now re-enter lending program");
        
        // CPI back to lending program's borrow function
        // Uses writable accounts passed from lender
        lending_program::cpi::borrow(
            CpiContext::new(
                ctx.accounts.lending_program.to_account_info(),
                lending_program::Borrow {
                    user: ctx.accounts.user.to_account_info(),
                    // ... other accounts
                },
            ),
            AMOUNT,  // Borrow again!
        )?;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ReceiveLoan<'info> {
    pub lending_program: Program<'info, LendingProgram>,
    #[account(mut)]
    pub user: Account<'info, User>,
    // ... writable accounts from lender
}
```

### Step 2: The Attack
```typescript
// Attacker crafts transaction
const tx = new Transaction();

// Instruction 1: Call lending.borrow() - triggers CPI to malicious
tx.add(
  lendingProgram.methods
    .borrow(new BN(AMOUNT))
    .accounts({
      user: attackerUser,
      borrower: maliciousProgramAccount,  // Malicious as recipient
      // ... writable vault/user accounts
    })
    .instruction()
);

// Sign and send
await sendTransaction(tx, connection, { signers: [attacker] });
```

### Step 3: What Actually Happens
```
1. Attacker calls lending.withdraw()
2. Lending checks balance (ok)
3. Lending CPIs to malicious for transfer
4. Malicious receives control, CPIs back to lending.withdraw()
5. Lending sees old balance (still high) ❌
6. Lending CPIs again to malicious
7. Malicious calls back again (up to stack depth)
8. Finally, balances updated after all CPIs
9. Vault drained multiple times 😱
```

## 🧠 Mental Model: The Ledger First

Picture your program as a meticulous bookkeeper in an old-timey bank. A customer comes in for a withdrawal.

1. **Checks**: Flip through the ledger to confirm they have funds.
2. **Effects**: Ink the withdrawal in the ledger right away—no delays!
3. **Interactions**: Only then, count out the cash and hand it over.

This CEI ritual ensures even if the customer tries a fast one (like yelling for another withdrawal mid-handover), your ledger already shows the money's gone. In Solana, skipping Effects before Interactions is like leaving the ledger open—malicious CPIs can "re-read" the old entry and double-dip.

## 🔍 Pinocchio Implementation

In Pinocchio, you handle CPIs manually, so stick to CEI like glue—update state before invoking.

```rust
use pinocchio::{AccountView, ProgramResult, error::ProgramError};

fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let user = &accounts[1];

    // Deserialize vault data
    let mut vault_data = vault.data_mut()?;
    let balance = u64::from_le_bytes(vault_data[0..8].try_into()?);

    // CHECKS
    if balance < amount {
        return Err(ProgramError::Custom(1));  // InsufficientFunds
    }

    // EFFECTS: Update balance first
    let new_balance = balance - amount;
    vault_data[0..8].copy_from_slice(&new_balance.to_le_bytes());

    // INTERACTIONS: Now safe to CPI
    let transfer_ix = solana_program::system_instruction::transfer(
        vault.address(),
        user.address(),
        amount,
    );
    invoke(&transfer_ix, &[vault.clone(), user.clone()])?;

    Ok(())
}
```

## 🛡️ Defense Patterns

Lock down your program with these strategies—think of them as your vault's combination lock, only opening after everything's tallied.

### Pattern 1: Strict CEI in All Functions
```rust
pub fn process(ctx: Context<Process>, amount: u64) -> Result<()> {
    // Checks
    require!(condition, ErrorCode::Invalid);
    
    // Effects
    update_state(&mut ctx.accounts.state, amount)?;
    
    // Interactions
    make_cpi(&ctx, amount)?;
}
```

### Pattern 2: Reentrancy Guards for Self-CPI
```rust
#[account]
pub struct State {
    pub is_processing: bool,
}

pub fn process(ctx: Context<Process>) -> Result<()> {
    require!(!ctx.accounts.state.is_processing, ErrorCode::Reentrant);
    ctx.accounts.state.is_processing = true;
    
    // ... logic ...
    
    ctx.accounts.state.is_processing = false;
}
```

### Pattern 3: Minimize Writable Accounts in CPIs
```rust
// Only pass what's necessary
let cpi_accounts = vec![read_only_account.clone()];
invoke(&ix, &cpi_accounts)?;
```

## 🚨 Common Mistakes

These pitfalls trip up even vets—like forgetting sunscreen on a beach day. Dodge 'em!

### Mistake 1: Updating After Transfer
```rust
// ❌ Effects after Interactions
transfer_funds(...)?;
update_balance(...);  // Too late!
```

### Mistake 2: Ignoring Self-Reentrancy
```rust
// ❌ No guard for self-CPI
self_cpi(...);  // Could re-enter unprotected
```

### Mistake 3: Passing Unnecessary Writable Accounts
```rust
// ❌ Gives callee too much power
invoke(&ix, &[writable_vault.clone()]);  // Malicious can abuse
```

### Mistake 4: Not Handling CPI Errors Properly
```rust
// ❌ Assumes CPI succeeds
invoke(&ix, &accounts)?;
// No rollback if fails
```

## 📊 Testing the Exploit

```typescript
describe("Cross-Program Reentrancy Exploit", () => {
  it("Vulnerable: Malicious callee drains vault via reentrancy", async () => {
    // Deploy malicious borrower
    const malicious = await deployMaliciousProgram();
    
    const vaultBalanceBefore = await getVaultBalance(vaultPda);
    
    // ATTACK: Call vulnerable withdraw, triggers reentrancy
    await vulnerableProgram.methods
      .withdraw(new BN(AMOUNT))
      .accounts({
        vault: vaultPda,
        user: malicious,  // Malicious as recipient
      })
      .signers([attacker])
      .rpc();

    const vaultBalanceAfter = await getVaultBalance(vaultPda);
    console.log(`💰 Attacker drained multiple times`);
    assert(vaultBalanceAfter < vaultBalanceBefore - AMOUNT);
  });

  it("Secure: CEI blocks reentrancy", async () => {
    const malicious = await deployMaliciousProgram();

    try {
      await secureProgram.methods
        .withdraw(new BN(AMOUNT))
        .accounts({
          vault: vaultPda,
          user: malicious,  // Tries reentrancy
        })
        .signers([attacker])
        .rpc();
      
      assert.fail("Should have failed on reentrancy");
    } catch (err) {
      assert.include(err.message, "InsufficientFunds");  // Sees updated balance
      console.log("✅ Reentrancy blocked by early state update");
    }
  });

  it("Secure: Normal withdrawal succeeds", async () {
    await secureProgram.methods
      .withdraw(new BN(AMOUNT))
      .accounts({
        vault: vaultPda,
        user: legitimateUser,
      })
      .signers([user])
      .rpc();
    
    console.log("✅ Legit operation works");
  });
});
```

## 🎓 Key Takeaways

1. **Solana's Twist on Reentrancy**: Less common thanks to stack limits and no callbacks, but possible with writable accounts—always assume malicious callees.

2. **CEI is King**: Checks first, effects second, interactions last. It's your shield against time-loop tricks.

3. **Runtime Helps, But Don't Rely**: Solana's VM prevents some attacks, but bad code order can still bite.

4. **Audit for Nested CPIs**: Test with malicious callees to simulate reentrancy.

5. **Self-Reentrancy Watch**: Rare, but guard if your program calls itself.

6. **Account Control**: Minimize writable passes to untrusted programs.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  <strong>Checks-Effects-Interactions</strong>. Memorize it. Live it. Update your state <em>before</em> you call <code>invoke</code> or <code>invoke_signed</code>.
</blockquote>

## 🔗 Additional Resources

- [Solana Stack Exchange on Reentrancy](https://solana.stackexchange.com/questions/23581/why-reentrancy-is-generally-not-an-issue-in-solana)
- [Helius Guide to Solana Security](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- [Sec3 Blog on Solana Security](https://www.sec3.dev/blog/on-smart-contracts-why-solana-is-more-secure)
- [Example Code: Cross-Program Reentrancy](https://github.com/rainman456/Solana-Security-blog/tree/main/examples/04-reentrancy-risk)

## ✅ Security Checklist

Before any CPI:

- [ ] State updates (effects) before CPIs (interactions)
- [ ] Following CEI pattern strictly
- [ ] Careful with invoke_signed on PDA authorities
- [ ] Minimize writable accounts in CPIs
- [ ] Tests include malicious callee for reentrancy sim
- [ ] Guards for self-reentrancy if applicable
- [ ] Stack depth considered in nested CPIs

**Remember**: Solana's design makes reentrancy tougher, but one misordered line can open the door. Follow CEI like it's your mantra, and you'll sleep better knowing your vault's locked tight.
