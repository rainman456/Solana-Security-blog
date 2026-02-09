---
layout: post
title: "Missing Mint Validation"
date: 2025-01-27
category: "Identity & Access Control"
difficulty: "Intermediate"
risk_level: "Critical"
description: "Programs that don't validate token account mints allow attackers to pass worthless tokens and withdraw valuable ones."
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
Okay, let's paint a picture: you're the proud owner of a high-end jewelry store, specializing in real diamonds. A slick customer strolls in, wanting to trade some "gems" for one of your sparkling beauties. They pull out a bag of what looks like stones and say, "These are worth a fortune—trust me!" But if you don't bother checking if they're actual diamonds or just fancy glass beads from a craft store, you might hand over the real deal and end up with a bunch of worthless fakes. Heartbreaking, right? In Solana land, this is the mint validation mishap: your program (the store) accepts any old token account without verifying the mint (the gem type), so attackers swap in their homemade "ScamGems" for your legit USDC or SOL. It's like running a currency exchange but forgetting to spot counterfeit bills—recipe for going broke fast!

## 💡 The "Aha!" Moment
Here's where it clicks, like finally understanding why your coffee tastes off—wrong beans! In the SPL Token world, every token account is like a wallet pocket dedicated to one specific currency (the mint). That mint field? It's the label saying "This holds USDC" or "This is full of Bitcoin." Skip checking it, and your program might mistake a pocket of play money for the real McCoy. Boom, attackers craft a bogus mint, stuff their account with zillions of fake tokens (costs nada), and feed it to your deposit function. Your code, blissfully unaware, credits them for depositing "value" and later lets them withdraw the genuine article from your vault. The lightbulb? Validation isn't optional—it's the bouncer ensuring only VIP tokens (matching mints) get in. Without it, your vault's a free-for-all candy store for hackers.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/mint-validation.svg" alt="Missing Mint Validation Diagram">
</div>

## 🌍 Real-World Case Study: The Cashio Infinite Mint Glitch ($52M)

**March 2022** - Cashio, a Solana-based stablecoin protocol, got hit hard in what's now infamous as the "infinite mint glitch." What started as a promising DeFi project ended up losing $52 million in minutes, tanking their CASH token from $1 to pennies. It wasn't some super-sophisticated zero-day; it was a classic mint validation slip-up that let an attacker print money like it was going out of style.

**The Vulnerability:**
Cashio's deposit system was supposed to require legit Saber USDT-USDC LP tokens as collateral for minting CASH. But oops—they missed validating the mint field in key accounts like saber_swap.arrow. This meant the program didn't check if the provided "collateral" was the real deal or just a faker whipped up by the attacker. It was like a bank accepting IOUs scribbled on napkins as loan security.

**The Attack:**
The hacker started by forging a chain of bogus accounts: a fake saber_swap.arrow, a phony bank via crate_mint, and worthless tokens minted for free. They passed these fakes as collateral, and since no mint checks kicked in, Cashio's code happily minted billions in real CASH. Then, the attacker swapped and bridged the loot—netting millions in USDT, USDC, and ETH. Fun fact: they left a cheeky on-chain message about refunding small holders and donating the rest to charity. Spoiler: the charity bit? Total fiction—they kept it all.

**The Root Cause:**
```rust
// ❌ VULNERABLE CODE (simplified from exploit)
pub fn crate_collateral_tokens(ctx: Context<CrateCollateralTokens>) -> Result<()> {
    // No mint validation on saber_swap.arrow!
    let arrow = &ctx.accounts.arrow;
    
    // Attacker passes fake arrow with fake mint
    // Program trusts without checking mint legitimacy
    verify_collateral(arrow, &ctx.accounts.bank)?;
    
    // Proceeds to mint real CASH against junk
    mint_cash(...)?;
}
```

**What Should Have Happened:**
```rust
// ✅ SECURE VERSION
pub fn crate_collateral_tokens(ctx: Context<CrateCollateralTokens>) -> Result<()> {
    // Hardcode or validate expected mint
    require!(
        ctx.accounts.arrow.mint == EXPECTED_SABER_LP_MINT,
        ErrorCode::InvalidMint
    );
    
    verify_collateral(&ctx.accounts.arrow, &ctx.accounts.bank)?;
    mint_cash(...)?;
}
```

**Lessons Learned:**
This wasn't Cashio's first rodeo with bugs, but skipping an audit sealed the deal. It shows how one unchecked mint field can unravel a whole protocol, letting fakes masquerade as value. Echoes in other Solana woes, like protocols blindly accepting user-supplied mints for staking or lending. Post-hack, the community hammered home: anchor validations to unforgeable roots, like hardcoded mints or whitelists. If they'd added that mint check, $52M stays put. Pro tip: audits aren't optional—they're your bug bounty before the bad guys collect.

## ⚔️ The Exploit

{% include code-compare.html %}

## 🎯 Attack Walkthrough

Let's sleuth this out like a caper film—step by step, watching the thief pull off the switcheroo with unchecked mints.

### Step 1: Attacker Crafts Fake Tokens
```rust
// Attacker deploys their own mint program
use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};

#[program]
pub mod scam_token {
    use super::*;
    
    pub fn create_scam_mint(ctx: Context<CreateMint>) -> Result<()> {
        // Mint billions of ScamCoin to themselves - free!
        token::mint_to(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::MintTo {
                    mint: ctx.accounts.scam_mint.to_account_info(),
                    to: ctx.accounts.scam_account.to_account_info(),
                    authority: ctx.accounts.attacker.to_account_info(),
                },
            ),
            1_000_000_000_000,  // Infinite supply!
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateMint<'info> {
    #[account(init, payer = attacker, mint::decimals = 6)]
    pub scam_mint: Account<'info, Mint>,
    #[account(init, payer = attacker, token::mint = scam_mint)]
    pub scam_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub attacker: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
```

### Step 2: The Attack
```typescript
// Deploy scam mint and account
const scamMint = await createScamMint();
const scamAccount = await createTokenAccount(scamMint, attacker.publicKey);

// Call vulnerable deposit with scam account
await vulnerableProgram.methods
  .deposit(new BN(1_000_000_000_000))
  .accounts({
    user: attacker.publicKey,
    vaultTokenAccount: vaultUsdcAccount,  // Real USDC vault!
    vault: vaultPda,
    userTokenAccount: scamAccount,  // ❌ Fake ScamCoin!
  })
  .signers([attacker])
  .rpc();

// ❌ Program deposits "value" without checking mint
// Now attacker can withdraw real USDC against fake deposit!
```

### Step 3: What Actually Happens
```
1. Attacker creates scam mint and mints trillions
2. Calls deposit with scam_token_account (mint = scam)
3. Vulnerable program skips mint check ❌
4. Transfers scam tokens to vault (worthless)
5. Credits attacker with "deposit" in vault state
6. Attacker calls withdraw for real value ⚠️
7. Program sends real USDC/SOL to attacker
8. Transaction succeeds ✅
9. Vault drained 💰
```

## 🧠 Mental Model: The Currency Exchange Fraud

Envision token mints as world currencies, each with its own value—USD solid, while some obscure play money is zilch. Token accounts? Bank statements for those currencies.

**Without Mint Validation:**
- Your vault deals in USD only.
- Shady customer flashes a statement: "1 trillion Venezuelan Bolívars!"
- You glance at the number but skip the currency code.
- "Wow, that's a lot—here's your trillion USD!"
- **Poof, bankrupt. You traded gold for paper.**

**With Mint Validation:**
- Customer: "Look at my trillion-unit balance!"
- You: "Hold up, is this USD? Nope, Bolívars—worth pennies."
- You: "Sorry, we only swap USD here."
- **Deal denied, your USD safe and sound.**

The mint is your fraud detector, like sniffing a bill for that watermark. No check? You're inviting counterfeit chaos. Remember, in Solana, users control what accounts they pass—always assume they're trying to sneak in fakes!

## 🔍 Pinocchio Implementation

Pinocchio dials it back to basics, so you'll handle mint checks by hand—like double-knotting your shoelaces before a run.

```rust
use pinocchio::{AccountView, ProgramResult, error::ProgramError};
use spl_token::state::Account as TokenAccount;

// Expected mint constant
const EXPECTED_MINT: [u8; 32] = [...];  // USDC mint, e.g.

fn deposit(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    let vault_token_account = &accounts[1];
    let vault = &accounts[2];
    let user_token_account = &accounts[3];

    // Deserialize token accounts
    let vault_ta: TokenAccount = TokenAccount::unpack(vault_token_account.data())?;
    let user_ta: TokenAccount = TokenAccount::unpack(user_token_account.data())?;

    // ✅ Validate mints match expected
    if vault_ta.mint.as_ref() != &EXPECTED_MINT {
        return Err(ProgramError::Custom(1));  // InvalidVaultMint
    }
    if user_ta.mint.as_ref() != &EXPECTED_MINT {
        return Err(ProgramError::Custom(2));  // InvalidUserMint
    }

    // Additional checks (ownership, etc.)
    if vault_ta.owner != vault.address() {
        return Err(ProgramError::Custom(3));  // InvalidOwner
    }

    // Safe to transfer
    Transfer {
        from: user_token_account,
        to: vault_token_account,
        authority: user,
        amount,
    }
    .invoke()?;

    Ok(())
}
```

## 🛡️ Defense Patterns

Arm your code with these tried-and-true shields—think of them as your vault's alarm system, buzzing at any funny business.

### Pattern 1: Anchor Constraints for Mint Checks
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        constraint = vault_token_account.mint == vault.token_mint @ ErrorCode::InvalidMint
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        constraint = user_token_account.mint == vault.token_mint @ ErrorCode::InvalidMint
    )]
    pub user_token_account: Account<'info, TokenAccount>,
}
```

### Pattern 2: Hardcoded Mint Constants
```rust
// Top of file
pub const USDC_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

// In function
require_eq!(
    token_account.mint,
    USDC_MINT,
    ErrorCode::InvalidMint
);
```

### Pattern 3: Dynamic Mint from Config (with Care)
```rust
#[account]
pub struct VaultConfig {
    pub allowed_mints: Vec<Pubkey>,  // Whitelist
}

pub fn deposit(ctx: Context<Deposit>) -> Result<()> {
    require!(
        ctx.accounts.config.allowed_mints.contains(&ctx.accounts.user_token_account.mint),
        ErrorCode::InvalidMint
    );
    // Proceed
}
```

## 🚨 Common Mistakes

These gotchas snag even pros—like stepping on Legos in the dark. Spot 'em early!

### Mistake 1: Checking Ownership but Skipping Mint
```rust
// ❌ Half-baked - Owner ok, but wrong mint!
constraint = token_account.owner == expected_owner
```

### Mistake 2: Assuming Mint from PDA Seeds
```rust
// ❌ Derives PDA but doesn't verify account mint
#[account(seeds = [b"vault", mint.as_ref()])]
pub vault: Account<'info, Vault>,
// Still need to check token_account.mint!
```

### Mistake 3: Validating Only One Account
```rust
// ❌ Checks user but not vault
constraint = user_token_account.mint == expected
// Attacker swaps vault account mint
```

### Mistake 4: Ignoring Associated Token Accounts
```rust
// ❌ Forgets ATAs might have different mints
let ata = associated_token::get_associated_token_address(...);
// Must still validate ata.mint
```

## 📊 Testing the Exploit

```typescript
describe("Missing Mint Validation Exploit", () => {
  it("Vulnerable: Deposits fake tokens, withdraws real", async () => {
    // Create scam mint and account with billions
    const scamMint = await createMint(attacker.publicKey);
    const scamAccount = await createTokenAccount(scamMint, attacker.publicKey);
    await mintTo(scamAccount, 1_000_000_000_000);

    // ❌ Deposit fake to real vault
    await vulnerableProgram.methods
      .deposit(new BN(1_000_000_000_000))
      .accounts({
        user: attacker.publicKey,
        vaultTokenAccount: vaultRealAccount,  // Real mint vault
        vault: vaultPda,
        userTokenAccount: scamAccount,  // Fake!
      })
      .signers([attacker])
      .rpc();

    // Now withdraw real value
    await vulnerableProgram.methods
      .withdraw(new BN(1_000_000_000_000))
      .accounts({...})
      .rpc();

    const vaultBalanceAfter = await getBalance(vaultRealAccount);
    console.log(`💰 Attacker stole massive real tokens`);
    assert.equal(vaultBalanceAfter, 0);
  });

  it("Secure: Mint validation blocks fake deposit", async () => {
    const scamAccount = await createScamAccount();

    try {
      await secureProgram.methods
        .deposit(new BN(1_000_000))
        .accounts({
          user: attacker.publicKey,
          vaultTokenAccount: vaultAccount,
          vault: vaultPda,
          userTokenAccount: scamAccount,  // ❌ Wrong mint
        })
        .signers([attacker])
        .rpc();
      
      assert.fail("Should have rejected wrong mint");
    } catch (err) {
      assert.include(err.message, "InvalidMint");
      console.log("✅ Attack stopped: Mint check saved the day");
    }
  });

  it("Secure: Legit mint deposit succeeds", async () => {
    await secureProgram.methods
      .deposit(new BN(1_000_000))
      .accounts({
        user: user.publicKey,
        vaultTokenAccount: vaultAccount,
        vault: vaultPda,
        userTokenAccount: realUserAccount,  // ✅ Matching mint
      })
      .signers([user])
      .rpc();
    
    console.log("✅ Real deal goes through smooth");
  });
});
```

## 🎓 Key Takeaways

1. **Mint is Your Gatekeeper**: Always verify token_account.mint == expected_mint—it's the difference between gold and glitter.

2. **Validate Every Token Account**: User, vault, collateral—check 'em all, every time.

3. **Anchor Makes It Easy**: Use constraints for auto-checks; they're your set-it-and-forget-it security.

4. **Pinocchio Needs Manual Love**: Deserialize and compare mints explicitly.

5. **Whitelists for Flexibility**: If supporting multiple mints, validate against a list.

6. **Test the Fakes**: Simulate attacks with bogus mints in your tests.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Every token account interaction must validate: (1) Ownership is correct, (2) <strong>Mint matches expectations</strong>. Missing either check is a critical vulnerability.
</blockquote>

## 🔗 Additional Resources

- [Cashio Exploit Post-Mortem](https://blog.neodyme.io/posts/cashio_exploit/)
- [SPL Token Security Guide](https://spl.solana.com/token)
- [Anchor Account Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Example Code: Missing Mint Validation](https://github.com/your-repo/examples/03-missing-mint-validation)

## ✅ Security Checklist

Before any token interaction:

- [ ] token_account.mint == expected_mint for ALL token accounts
- [ ] Using Anchor constraints like constraint = mint == expected @ Error
- [ ] Manual mint comparison in Pinocchio after deserializing
- [ ] Ownership checks paired with mint validation
- [ ] Tests include wrong-mint attack attempts
- [ ] Whitelists if multiple mints allowed
- [ ] No assumptions about PDA-derived mints

**Remember**: Mints are your truth serum for tokens. Skip validation, and you're inviting a counterfeit party. Cashio's $52M lesson? Check twice, deploy once.
