---
layout: post
title: "Missing Mint Validation"
date: 2025-01-27
category: "Identity & Access Control"
difficulty: "Intermediate"
risk_level: "Critical"
description: "Programs that don't validate token account mints allow attackers to deposit worthless tokens and withdraw valuable ones."
impact: "Complete loss of funds. Attackers can create fake tokens, deposit them, and withdraw real valuable tokens from the vault."
recommendation: "Always validate that token_account.mint matches the expected mint address using Anchor constraints or manual checks in Pinocchio."
tags:
  - Rust
  - SPL Token
  - Anchor
checklist: 
  - "Are you validating that token account mints match expected mints?"
  - "Do you check vault_token_account.mint == vault.token_mint?"
  - "For Anchor: Are you using constraint checks on mint fields?"
vulnerable_code: |
  #[derive(Accounts)]
  pub struct Deposit<'info> {
      #[account(mut)]
      pub user: Signer<'info>,
      
      // ❌ VULNERABLE: No mint validation!
      // Attacker can pass ANY token account here
      #[account(
          mut,
          constraint = vault_token_account.owner == vault.key()
      )]
      pub vault_token_account: Account<'info, TokenAccount>,
      
      #[account(
          seeds = [b"vault", vault.token_mint.as_ref()],
          bump = vault.bump,
      )]
      pub vault: Account<'info, Vault>,
      
      // ❌ No check that user_token_account.mint matches vault.token_mint
      #[account(mut)]
      pub user_token_account: Account<'info, TokenAccount>,
  }
  
  pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
      // ❌ Transfers happen without mint validation
      // User could deposit ScamCoin and withdraw real USDC!
      token::transfer(
          CpiContext::new(
              ctx.accounts.token_program.to_account_info(),
              token::Transfer {
                  from: ctx.accounts.user_token_account.to_account_info(),
                  to: ctx.accounts.vault_token_account.to_account_info(),
                  authority: ctx.accounts.user.to_account_info(),
              },
          ),
          amount,
      )?;
      Ok(())
  }
secure_code: |
  #[derive(Accounts)]
  pub struct Deposit<'info> {
      #[account(mut)]
      pub user: Signer<'info>,
      
      // ✅ SECURE: Validate vault token account mint
      #[account(
          mut,
          constraint = vault_token_account.owner == vault.key() 
              @ VaultError::InvalidOwner,
          constraint = vault_token_account.mint == vault.token_mint 
              @ VaultError::InvalidMint,  // ← Critical check!
      )]
      pub vault_token_account: Account<'info, TokenAccount>,
      
      #[account(
          seeds = [b"vault", vault.token_mint.as_ref()],
          bump = vault.bump,
      )]
      pub vault: Account<'info, Vault>,
      
      // ✅ SECURE: Validate user token account mint matches
      #[account(
          mut,
          constraint = user_token_account.mint == vault.token_mint 
              @ VaultError::InvalidMint,  // ← Critical check!
      )]
      pub user_token_account: Account<'info, TokenAccount>,
  }
  
  pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
      // ✅ Now safe: Both accounts verified to use correct mint
      token::transfer(
          CpiContext::new(
              ctx.accounts.token_program.to_account_info(),
              token::Transfer {
                  from: ctx.accounts.user_token_account.to_account_info(),
                  to: ctx.accounts.vault_token_account.to_account_info(),
                  authority: ctx.accounts.user.to_account_info(),
              },
          ),
          amount,
      )?;
      Ok(())
  }
---

## 📖 The Scenario
Imagine you run a bank vault that stores gold bars. A customer wants to withdraw their gold, so you ask them to show their account balance. They hand you a statement from a completely different bank - one that deals in Monopoly money, not gold - showing they have "1000 units."

Without checking that this statement is actually from YOUR bank (the gold vault), you might accidentally give them real gold bars in exchange for their worthless Monopoly money balance. This is exactly what happens with missing mint validation.

## 💡 The "Aha!" Moment
In Solana's SPL Token system, a **token account** stores tokens of a specific **mint** (the token type). Every token account has a `mint` field that identifies which token it holds.

The vulnerability occurs when your program accepts a token account without verifying that its `mint` field matches the expected token type. An attacker can exploit this by:

1. Creating a worthless token (like "ScamCoin")
2. Minting themselves billions of ScamCoin
3. Passing their ScamCoin token account to your program
4. Your program treats their ScamCoin balance as if it were valuable USDC or SOL

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/mint-validation.svg" alt="Missing Mint Validation Diagram">
</div>

## ⚔️ The Exploit

{% include code-compare.html %}

## 🧠 Mental Model: The Currency Exchange Fraud

Think of token mints like different currencies, and token accounts like bank accounts denominated in those currencies.

**Without Mint Validation:**
- You run a USD vault
- Attacker shows you their Zimbabwe Dollar account with 1 trillion ZWD
- You don't check the currency type
- You give them 1 trillion USD because "the numbers match"
- **You just lost everything**

**With Mint Validation:**
- Attacker: "I have 1 trillion in this account!"
- You: "Let me check... this is Zimbabwe Dollars, not USD"
- You: "Sorry, this vault only accepts USD"
- **Transaction rejected, vault protected**

The mint address is like the currency code (USD vs ZWD vs EUR). You MUST verify it matches your expected currency before accepting any deposits or honoring any withdrawals.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Every token account interaction must validate: (1) Ownership is correct, (2) <strong>Mint matches expectations</strong>. Missing either check is a critical vulnerability.
</blockquote>
