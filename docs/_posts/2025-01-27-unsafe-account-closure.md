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
You sell your house. You hand the keys to the new owner and they pay you.
But... you keep a spare key. And you leave all your furniture inside. And technically, your name is still on the deed at City Hall.

Later, you use your spare key to walk back in, claim "this is still my house," and trick a moving company into emptying it for you again.

## 💡 The "Aha!" Moment
Closing an account in Solana isn't just about draining the money. It's about **Garbage Collection**.

If you drain the lamports but leave the account **owned by your program** with its data intact, it's a "Zombie Account". Anyone can send a tiny amount of SOL to it later, revive it, and because the old data (e.g., specific user permissions) is still there, they can exploit it.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/account-closure.svg" alt="Account Closure Vulnerability Diagram">
</div>

## ⚔️ The Exploit

{% include code-compare.html %}

## 🧠 Mental Model: The Burn & Salting
Closing an account effectively means destroying it forever.
1. **Empty the safe** (Transfer Lamports).
2. **Burn the contents** (Zero Data).
3. **Change the Locks** (Reassign Owner to System Program).

If you skip step 3, the account is just "dormant" under your control, waiting to be re-awakened (Revival Attack).

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Use Anchor's <code>close = target</code> constraint whenever possible. If you must do it manually, you MUST perform all 3 steps: Empty Lamports, Zero Data, Assign to System Program.
</blockquote>
