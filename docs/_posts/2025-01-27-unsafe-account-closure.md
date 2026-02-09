---
layout: post
title: "Unsafe Account Closure"
date: 2025-01-27
category: "Data Integrity"
difficulty: "Intermediate"
risk_level: "High"
description: "Draining lamports without zeroing data and reassigning ownership creates zombie accounts that can be revived and exploited."
impact: "Revival attacks. Attackers can re-fund closed accounts and exploit stale data/permissions to drain funds or manipulate state."
recommendation: "Always use Anchor's `close = target` constraint. If manual closure is required, transfer lamports, zero data, AND reassign owner to System Program."
tags:
  - Rust
  - Account Management
  - Anchor
checklist: 
  - "Are you using Anchor's `close` constraint?"
  - "If manual: Did you transfer ALL lamports out?"
  - "If manual: Did you zero the data array?"
  - "If manual: Did you assign the owner to System Program?"
vulnerable_code: |
  pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
      // ❌ VULNERABLE: Only transfers lamports!
      // Account remains owned by program with data intact
      
      let vault = &ctx.accounts.vault;
      let user = &ctx.accounts.user;
      
      // Transfer lamports to user
      **user.to_account_info().try_borrow_mut_lamports()? += vault.to_account_info().lamports();
      **vault.to_account_info().try_borrow_mut_lamports()? = 0;
      
      // ❌ CRITICAL FLAWS:
      // 1. Account still owned by our program
      // 2. Data (vault.owner, vault.balance) still exists
      // 3. Attacker can re-fund and exploit stale data
      
      Ok(())
  }
secure_code: |
  // ✅ SECURE: Using Anchor's close constraint
  #[derive(Accounts)]
  pub struct CloseVault<'info> {
      #[account(mut)]
      pub user: Signer<'info>,
      
      #[account(
          mut,
          close = user,  // ← Magic! Does all 3 steps:
          // 1. Transfers lamports to 'user'
          // 2. Zeros account data
          // 3. Reassigns owner to System Program
          constraint = vault.owner == user.key()
      )]
      pub vault: Account<'info, Vault>,
  }
  
  pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
      // ✅ Anchor handles everything automatically
      // Account is properly destroyed and cannot be revived
      Ok(())
  }
---

## 📖 The Scenario
Ever watched a zombie movie where the undead just won't stay down? You think you've buried them, but nope—they claw their way back, hungrier than ever. That's your Solana account on a bad day. Imagine you've got this vault full of treasures (lamports and data). You decide to close it up: drain the gold, hand it over, and call it a day. But if you forget to bulldoze the vault, change the locks, and post "Condemned" signs everywhere, some sneaky grave-robber can sneak in, toss in a few coins, and boom—the vault's back online with all its old secrets intact. Now they're using your old permissions to raid the place all over again. Spooky, fun, and totally avoidable with the right rituals!

## 💡 The "Aha!" Moment
Buckle up—this is where the light switches on like spotting a plot twist in a thriller. In Solana, accounts aren't just wallets; they're like persistent storage units holding data, ownership, and rent (lamports to keep 'em alive). "Closing" one sounds simple, but it's a three-act play: empty the rent, wipe the data clean, and hand ownership back to the System Program so no one can mess with it. Skip any act, and you've got a "zombie account"—drained but not dead. Anyone can sprinkle some SOL dust (lamports) to revive it, and since the old data (like balances or owners) lingers, your program thinks it's legit and lets the chaos resume. The "aha!" hits when you realize Solana's garbage collector only trashes accounts at transaction's end if they're broke and unowned. Mess up the closure, and attackers turn your cleanup into their playground.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/account-closure.svg" alt="Account Closure Vulnerability Diagram">
</div>

## 🌍 Real-World Case Study: Staking Protocol Revival Vulnerability (Based on Audit Discoveries)

While major exploits from revival attacks are rare (thanks to increasing awareness), they're a staple in Solana security audits. FuzzingLabs, a blockchain security firm, highlighted a common pattern in staking vaults during their reviews—think protocols like those handling user stakes for rewards.

**The Vulnerability:**
In a typical staking setup, users deposit tokens into a PDA (program-derived account) vault. When unstaking, the program redeems rewards, transfers assets, and "closes" the vault by draining lamports. But if it skips zeroing data or reassigning ownership, the account becomes a zombie—revivable with a sprinkle of SOL.

**The Attack:**
Attackers bundle instructions in one transaction: first, call unstake to claim rewards and drain; second, transfer lamports back to revive. The vault pops back with stale data (like unclaimed rewards flags), letting them unstake again. Repeat, and the pool drains dry. In audits, this has led to potential double-dips on one-time rewards or infinite loops siphoning funds.

**The Root Cause:**
```rust
// ❌ VULNERABLE CODE (simplified from audit patterns)
pub fn redeem_staked_tokens(ctx: Context<RedeemStakedTokens>) -> Result<()> {
    // Transfer rewards and tokens
    transfer_rewards(&ctx, ctx.accounts.user_stake.rewards)?;
    
    // Drain lamports
    **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? += 
        ctx.accounts.user_stake.to_account_info().lamports();
    **ctx.accounts.user_stake.try_borrow_mut_lamports()? = 0;
    
    // Missing: zero data, set discriminator, reassign owner
    Ok(())
}
```

**What Should Have Happened:**
```rust
// ✅ SECURE VERSION
pub fn redeem_staked_tokens(ctx: Context<RedeemStakedTokens>) -> Result<()> {
    transfer_rewards(&ctx, ctx.accounts.user_stake.rewards)?;
    
    // Zero data
    let mut data = ctx.accounts.user_stake.data.borrow_mut();
    data.fill(0);
    
    // Set closed discriminator (e.g., first 8 bytes)
    data[0..8].copy_from_slice(&CLOSED_DISCRIMINATOR.to_le_bytes());
    
    // Drain lamports
    **ctx.accounts.user.to_account_info().try_borrow_mut_lamports()? += 
        ctx.accounts.user_stake.to_account_info().lamports();
    **ctx.accounts.user_stake.try_borrow_mut_lamports()? = 0;
    
    // Reassign owner to System Program
    ctx.accounts.user_stake.assign(&system_program::ID);
    
    Ok(())
}
```

**Lessons Learned:**
This pattern pops up in bug bounties and audits from firms like Sec3 and OtterSec. No billion-dollar heist yet, but it's prevented millions in potential losses. It echoes Ethereum's reentrancy woes but Solana-style—zombies instead of loops. Always audit closures; one zombie can zombie-fy your whole protocol!

## ⚔️ The Exploit

{% include code-compare.html %}

## 🎯 Attack Walkthrough

Let's zombie-hunt this exploit like a video game level—step by step, with the attacker as the undead mastermind.

### Step 1: Attacker Identifies Zombie Potential
Scan the program for incomplete closures: drains lamports but skips data wipe or owner reassign.

### Step 2: Craft the Revival Transaction
```typescript
// Attacker builds tx with bundled instructions
const tx = new Transaction();

// Ix 1: Call vulnerable close_vault - drains but leaves zombie
tx.add(
  vulnerableProgram.methods
    .closeVault()
    .accounts({
      vault: vaultPda,
      user: attacker.publicKey,
    })
    .instruction()
);

// Ix 2: Transfer lamports back to revive
tx.add(
  SystemProgram.transfer({
    fromPubkey: attacker.publicKey,
    toPubkey: vaultPda,
    lamports: RENT_EXEMPT_AMOUNT,  // Enough to keep alive
  })
);

// Send tx
await sendAndConfirmTransaction(connection, tx, [attacker]);
```

### Step 3: What Actually Happens
```
1. Tx starts: close_vault drains lamports, but data/owner intact
2. Account temporarily broke, but tx not over
3. Transfer Ix revives with lamports ❌
4. Tx ends: Garbage collector skips (rent-exempt now)
5. Zombie vault alive with stale data ⚠️
6. Attacker exploits old permissions (e.g., withdraw again)
7. Protocol confused, funds siphoned 💰
```

## 🧠 Mental Model: The Burn & Salting

Think of closing an account like disposing of a haunted house. You can't just evict the ghosts (drain lamports)—you gotta exorcise (zero data) and demolish (reassign to System). Otherwise, it's a fixer-upper waiting for squatters. In ancient times, victors salted enemy fields to prevent regrowth; here, salting is your discriminator and zeroing—ensuring nothing sprouts back. Skip it, and your "closed" account is a horror sequel waiting to happen!

## 🔍 Pinocchio Implementation

Pinocchio strips it down, so manual closure is key—think DIY demolition.

```rust
use pinocchio::{AccountView, ProgramResult, error::ProgramError};
use solana_program::system_instruction;

fn close_vault(accounts: &[AccountView]) -> ProgramResult {
    let vault = &accounts[0];
    let user = &accounts[1];
    let system_program = &accounts[2];

    // ✅ Zero data first
    let mut vault_data = vault.data_mut()?;
    vault_data.fill(0);

    // Set closed discriminator (e.g., first 8 bytes)
    vault_data[0..8].copy_from_slice(&[0; 8]);  // Or your closed value

    // Transfer ALL lamports
    let lamports = vault.lamports();
    let transfer_ix = system_instruction::transfer(
        vault.address(),
        user.address(),
        lamports,
    );
    invoke(&transfer_ix, &[vault.clone(), user.clone()])?;

    // Reassign owner to System Program
    let assign_ix = system_instruction::assign(
        vault.address(),
        &system_program::ID,
    );
    invoke(&assign_ix, &[vault.clone()])?;

    Ok(())
}
```

## 🛡️ Defense Patterns

Fortify your closures with these blueprints—like building a zombie-proof bunker.

### Pattern 1: Anchor Close Constraint
```rust
#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut, close = user @ ErrorCode::InvalidClose)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
}
```

### Pattern 2: Manual Closure with Discriminator
```rust
// After draining
let mut data = vault.data.borrow_mut();
data.fill(0);
data[0..8].copy_from_slice(&CLOSED_DISCRIMINATOR);
vault.assign(&system_program::ID);
```

### Pattern 3: Validate on Re-Init
```rust
// In init functions
require_neq!(
    account.discriminator,
    CLOSED_DISCRIMINATOR,
    ErrorCode::RevivedAccount
);
```

## 🚨 Common Mistakes

These slip-ups are like leaving your door unlocked in zombie town—avoid at all costs!

### Mistake 1: Draining Lamports Only
```rust
// ❌ No zero, no reassign
**user.lamports() += vault.lamports();
**vault.lamports() = 0;
```

### Mistake 2: Forgetting Discriminator
```rust
// ❌ Zeros data but no closed flag
data.fill(0);  // Attacker can revive and pass as new
```

### Mistake 3: Partial Zeroing
```rust
// ❌ Only clears some fields
vault.balance = 0;  // Other data lingers
```

### Mistake 4: No Re-Init Checks
```rust
// ❌ Assumes closed stays closed
// No discriminator validation on reuse
```

## 📊 Testing the Exploit

```typescript
describe("Unsafe Account Closure Exploit", () => {
  it("Vulnerable: Revive zombie and exploit stale data", async () => {
    // Setup vault with data (e.g., balance: 100)
    
    // Call vulnerable close
    await vulnerableProgram.methods
      .closeVault()
      .accounts({
        vault: vaultPda,
        user: attacker.publicKey,
      })
      .rpc();

    // Revive by transferring lamports
    await connection.sendTransaction(
      SystemProgram.transfer({
        fromPubkey: attacker.publicKey,
        toPubkey: vaultPda,
        lamports: MIN_RENT,
      }),
      [attacker]
    );

    // Exploit: e.g., withdraw using stale balance
    await vulnerableProgram.methods
      .withdraw(new BN(100))  // Sees old data
      .accounts({ vault: vaultPda })
      .rpc();

    console.log("💰 Zombie revived, funds stolen again");
  });

  it("Secure: Proper closure prevents revival", async () => {
    await secureProgram.methods
      .closeVault()
      .accounts({
        vault: vaultPda,
        user: user.publicKey,
      })
      .rpc();

    try {
      // Try to revive and withdraw
      await connection.sendTransaction(...);  // Transfer
      await secureProgram.methods.withdraw(...).rpc();
      assert.fail("Should error on closed account");
    } catch (err) {
      assert.include(err.message, "AccountClosed");
      console.log("✅ Zombie slayed: Revival blocked");
    }
  });
});
```

## 🎓 Key Takeaways

1. **Three Steps to Closure Heaven**: Drain, zero, reassign—miss one, invite zombies.

2. **Anchor's Your Buddy**: `close = target` automates the magic.

3. **Discriminators Matter**: They're your "Do Not Resuscitate" order.

4. **Test the Undead**: Simulate revivals in tests.

5. **Audits Catch 'Em**: Common in bounties—don't skip.

6. **No Assumptions**: Closed ain't closed till garbage-collected.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Use Anchor's <code>close = target</code> constraint whenever possible. If you must do it manually, you MUST perform all 3 steps: Empty Lamports, Zero Data, Assign to System Program.
</blockquote>

## 🔗 Additional Resources

- [FuzzingLabs on Revival Attacks](https://fuzzinglabs.com/revival-attacks-solana-programs)
- [Solana Program Security: Closing Accounts](https://docs.solana.com/developing/programming-model/accounts#closing-accounts)
- [Anchor Close Constraint Docs](https://www.anchor-lang.com/docs/account-constraints#close)
- [Example Code: Unsafe Account Closure](https://github.com/your-repo/examples/05-unsafe-account-closure)

## ✅ Security Checklist

For every closure:

- [ ] Using Anchor's `close = target` for auto-handling
- [ ] Manual: Transferred ALL lamports to recipient
- [ ] Manual: Zeroed entire data array
- [ ] Manual: Reassigned owner to System Program
- [ ] Set closed discriminator to prevent re-init
- [ ] Tests include revival attempt scenarios
- [ ] Validate discriminators in all init/reuse functions

**Remember**: Improper closure is like burying treasure without a map—someone'll dig it up. Slay those zombies right, and your protocol stays undead-free!