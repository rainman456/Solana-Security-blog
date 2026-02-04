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
You are a cashier. A customer hands you a check for $100.
1. You hand them $100 cash.
2. You turn around to write "$100 withdrawn" in your ledger.

Between step 1 and 2, while your back is turned, the customer quickly hands you **the same check again**. Since you haven't written in the ledger yet, you think "Oh, they haven't withdrawn anything!" and hand them another $100. They drain your register before you write a single line.

## 💡 The "Aha!" Moment
Solana programs can call other programs (**CPI** - Cross-Program Invocation).
Crucially, when you call another program, you **pause** your execution and hand control to them.

If that other program (the "customer") is malicious, it can call **back** into your program (`withdraw`) *before* you finished updating your balances. It sees the old balance and withdraws again.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/reentrancy.svg" alt="Reentrancy Vulnerability Diagram">
</div>

## ⚔️ The Exploit

{% include code-compare.html %}

## 🧠 Mental Model: The Ledger First
Always behave like a paranoid accountant.
1. **Checks**: Verify the check is valid.
2. **Effects**: Write down "Money Gone" in the ledger.
3. **Interactions**: Finally, hand over the cash.

This order (CEI) guarantees that no matter what the customer does with the cash (or if they try to trick you), your books are already closed on that transaction.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  <strong>Checks-Effects-Interactions</strong>. Memorize it. Live it. Update your state <em>before</em> you call <code>invoke</code> or <code>invoke_signed</code>.
</blockquote>
