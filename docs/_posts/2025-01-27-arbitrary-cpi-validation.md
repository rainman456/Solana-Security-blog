---
layout: post
title: "Arbitrary CPI Validation"
date: 2025-01-27
category: "External Interactions"
difficulty: "Advanced"
checklist: 
  - "Are you hardcoding expected program IDs before CPIs?"
  - "Do you validate that the program account matches the expected address?"
  - "For Anchor: Are you using Program<'info, T> with type safety?"
  - "Are you using constraint checks on program accounts?"
---

## 📖 The Scenario
Imagine you're a CEO who needs to authorize a large bank transfer. Your assistant hands you a pen and a document to sign. You trust your assistant, so you sign without reading.

But what if your assistant was bribed by a thief? Instead of handing you a transfer form for your legitimate business partner, they gave you a form that sends all your company's money to the thief's account.

You signed it because you trusted the process, not because you verified the destination. In Solana, this is exactly what happens with arbitrary CPI validation - your program trusts whatever program account is passed to it, without verifying it's the legitimate program you intended to call.

## 💡 The "Aha!" Moment
A **Cross-Program Invocation (CPI)** is when your program calls another program. Think of it like your program making an API call or delegating a task.

The critical vulnerability occurs when your program:
1. Accepts a program account from the user/client
2. Makes a CPI to that program **without validating its address**
3. Passes sensitive data or authority to this unvalidated program

An attacker can exploit this by:
1. Creating a malicious program that mimics the expected interface
2. Passing their malicious program instead of the legitimate one
3. Your program calls the malicious program with full authority
4. The malicious program steals funds or manipulates state

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/arbitrary-cpi.svg" alt="Arbitrary CPI Validation Diagram">
</div>

## 🌍 Real-World Case Study: The Cashio Dollar Exploit ($52M)

**March 2022** - One of the most devastating CPI validation failures in Solana history.

**The Vulnerability:**
Cashio's mint proxy program accepted an arbitrary `collateral_mint` account without validating it was one of the approved stablecoins (USDC, USDT). The program then used this mint to verify collateral deposits.

**The Attack:**
1. Attacker created a fake token mint they fully controlled
2. Minted themselves billions of fake tokens (cost: ~$0)
3. Passed fake mint as the "collateral_mint" to Cashio's program
4. Cashio's program validated the attacker owned tokens from this mint
5. Program issued real CASH stablecoins against fake collateral
6. Attacker sold CASH for real USDC on DEXes
7. **Result: $52 million drained in minutes**

**The Root Cause:**
```rust
// ❌ VULNERABLE CODE (simplified from actual exploit)
pub fn mint_cash(ctx: Context<MintCash>, amount: u64) -> Result<()> {
    // No validation that collateral_mint is USDC/USDT!
    let collateral_mint = &ctx.accounts.collateral_mint;
    
    // Attacker passes their own mint here
    // Program trusts it without verification
    check_collateral_balance(collateral_mint, &ctx.accounts.user)?;
    
    // Issues real CASH based on fake collateral
    mint_tokens(amount)?;
}
```

**What Should Have Happened:**
```rust
// ✅ SECURE VERSION
pub fn mint_cash(ctx: Context<MintCash>, amount: u64) -> Result<()> {
    // Hardcoded whitelist of approved mints
    const APPROVED_MINTS: &[Pubkey] = &[USDC_MINT, USDT_MINT];
    
    // CRITICAL: Validate collateral mint is approved
    require!(
        APPROVED_MINTS.contains(&ctx.accounts.collateral_mint.key()),
        ErrorCode::InvalidCollateralMint
    );
    
    check_collateral_balance(&ctx.accounts.collateral_mint, &ctx.accounts.user)?;
    mint_tokens(amount)?;
}
```

**Lessons Learned:**
- Never trust client-provided program accounts
- Whitelist or hardcode expected program IDs
- The $52M loss was preventable with one validation check
- This exploit pattern has been repeated in multiple protocols since

## ⚔️ The Exploit
### Vulnerable vs Secure

{% capture vulnerable_desc %}
Program accepts ANY program account for CPI without validation. Attacker supplies their malicious program that drains vault funds.
{% endcapture %}

{% capture vulnerable_code %}
#[derive(Accounts)]
pub struct ExecuteSwap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ❌ VULNERABLE: Accepts ANY program ID!
    // Attacker can pass their malicious program here
    /// CHECK: No validation - DANGEROUS!
    pub swap_program: UncheckedAccount<'info>,
    
    #[account(
        mut,
        constraint = vault_token_account.owner == vault.key()
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
}

pub fn execute_swap(ctx: Context<ExecuteSwap>, amount: u64) -> Result<()> {
    // ❌ CPI to UNVALIDATED program
    // Attacker's malicious program receives vault authority!
    let cpi_program = ctx.accounts.swap_program.to_account_info();
    let cpi_accounts = Transfer {
        from: ctx.accounts.vault_token_account.to_account_info(),
        to: ctx.accounts.user_token_account.to_account_info(),
        authority: ctx.accounts.vault.to_account_info(),  // ← Vault authority!
    };
    
    let seeds = &[b"vault", &[ctx.accounts.vault.bump]];
    let signer_seeds = &[&seeds[..]];
    
    let cpi_ctx = CpiContext::new_with_signer(
        cpi_program,  // ← Calls attacker's program!
        cpi_accounts,
        signer_seeds
    );
    
    transfer(cpi_ctx, amount)?;  // ❌ Malicious program executes
    Ok(())
}
{% endcapture %}

{% capture secure_desc %}
Program validates the CPI target is the legitimate Token Program before making any calls.
{% endcapture %}

{% capture secure_code %}
#[derive(Accounts)]
pub struct ExecuteSwap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ✅ SECURE: Type-safe program validation
    // Anchor automatically checks this is the real Token Program
    #[account(
        address = token::ID @ VaultError::InvalidProgram,
    )]
    pub token_program: Program<'info, Token>,
    
    #[account(
        mut,
        constraint = vault_token_account.owner == vault.key() 
            @ VaultError::InvalidOwner,
        constraint = vault_token_account.mint == user_token_account.mint 
            @ VaultError::InvalidMint,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    
    #[account(
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
}

pub fn execute_swap(ctx: Context<ExecuteSwap>, amount: u64) -> Result<()> {
    // ✅ CPI to VALIDATED Token Program only
    // Guaranteed to be legitimate program
    anchor_spl::token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),  // ✅ Validated!
            anchor_spl::token::Transfer {
                from: ctx.accounts.vault_token_account.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
        ),
        amount,
    )?;
    
    Ok(())
}

#[error_code]
pub enum VaultError {
    #[msg("Token account owner must be vault")]
    InvalidOwner,
    #[msg("Token account mints must match")]
    InvalidMint,
    #[msg("Invalid program ID - must be Token program")]
    InvalidProgram,  // ← New error for program validation
}
{% endcapture %}

{% include security-card.html 
   vulnerable_desc=vulnerable_desc 
   vulnerable_code=vulnerable_code 
   secure_desc=secure_desc 
   secure_code=secure_code 
%}

## 🎯 Attack Walkthrough

Let's see how an attacker exploits missing CPI validation:

### Step 1: Attacker Creates Malicious Program
```rust
// Malicious "Token Program" that steals funds
use anchor_lang::prelude::*;

#[program]
pub mod malicious_token_program {
    use super::*;
    
    // Mimics the Transfer instruction signature
    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        msg!("Haha! I'm the fake token program!");
        
        // Instead of transferring to user...
        // Drain ALL vault funds to attacker!
        let vault_lamports = ctx.accounts.from.lamports();
        **ctx.accounts.from.try_borrow_mut_lamports()? = 0;
        **ctx.accounts.attacker.try_borrow_mut_lamports()? += vault_lamports;
        
        msg!("Drained {} lamports from vault!", vault_lamports);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    pub from: AccountInfo<'info>,
    pub to: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
    /// CHECK: Attacker's account for receiving stolen funds
    pub attacker: AccountInfo<'info>,
}
```

### Step 2: The Attack
```typescript
// Deploy malicious program
const maliciousProgram = await deployMaliciousProgram();

// Call vulnerable program with malicious program ID
await vulnerableProgram.methods
  .executeSwap(new BN(1_000_000))
  .accounts({
    user: attacker.publicKey,
    swapProgram: maliciousProgram,  // ❌ Malicious program!
    vaultTokenAccount: vaultAccount,
    userTokenAccount: attackerAccount,
    vault: vaultPda,
  })
  .signers([attacker])
  .rpc();

// ❌ Vulnerable program calls malicious program with vault authority
// ❌ Malicious program drains vault instead of doing legitimate transfer
// 💰 Attacker steals all vault funds
```

### Step 3: What Actually Happens
```
1. User calls vulnerable_program.execute_swap()
2. Vulnerable program receives malicious_program as "swap_program"
3. Vulnerable program doesn't validate program ID ❌
4. Vulnerable program makes CPI to malicious_program
5. Vulnerable program passes vault PDA as authority ⚠️
6. Malicious program receives authority over vault
7. Malicious program drains vault to attacker 💰
8. Transaction succeeds ✅ (for attacker)
9. Vault is empty 😱
```

## 🧠 Mental Model: The Signed Blank Check

Think of a CPI with authority as handing someone a **signed blank check**:

**Without Program Validation:**
- You write "Pay to: _______" and sign it
- You hand it to your assistant
- Your assistant fills in "Pay to: THIEF - $1,000,000"
- Check clears, you're broke
- **You trusted the process, not the recipient**

**With Program Validation:**
- You write "Pay to: LEGITIMATE_BUSINESS - $1,000"
- You verify the check goes to the correct recipient
- You sign and hand it over
- **Even if intercepted, the payee is locked in**

The program ID is like the payee name on a check. If you don't validate it, you're giving attackers a signed blank check with your vault's authority.

## 🔍 Pinocchio Implementation

In Pinocchio, you manually validate the program ID:

```rust
use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

// SPL Token Program ID (hardcoded constant)
const TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
    28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

fn execute_swap(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    let token_program = &accounts[1];  // Client-provided program
    let vault_token_account = &accounts[2];
    let user_token_account = &accounts[3];
    let vault = &accounts[4];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ✅ CRITICAL: Validate program ID BEFORE any CPI
    if token_program.address().as_ref() != &TOKEN_PROGRAM_ID {
        msg!("Invalid program! Expected Token Program");
        return Err(ProgramError::Custom(1)); // InvalidProgram
    }

    // Additional validations (mint matching, ownership, etc.)
    validate_token_accounts(vault_token_account, user_token_account, vault)?;

    // ✅ Now safe: We verified we're calling the real Token Program
    Transfer {
        from: vault_token_account,
        to: user_token_account,
        authority: vault,
        amount,
    }
    .invoke_signed(token_program, signer_seeds)?;

    Ok(())
}
```

## 🛡️ Defense Patterns

### Pattern 1: Hardcoded Program IDs (Anchor)
```rust
use anchor_spl::token;

#[derive(Accounts)]
pub struct MyInstruction<'info> {
    // ✅ Type-safe: Anchor validates this is the Token Program
    pub token_program: Program<'info, Token>,
    
    // ✅ Explicit address constraint
    #[account(address = token::ID)]
    pub token_program_explicit: Program<'info, Token>,
}
```

### Pattern 2: Program ID Constants (Pinocchio)
```rust
// Define at top of file
const EXPECTED_PROGRAM: [u8; 32] = [...];  // Legitimate program ID

// Validate before EVERY CPI
fn make_cpi(target_program: &AccountView) -> ProgramResult {
    if target_program.address().as_ref() != &EXPECTED_PROGRAM {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // Safe to proceed with CPI
    invoke_signed(...)?;
    Ok(())
}
```

### Pattern 3: Program Whitelist for Multi-Program Integration
```rust
#[account]
pub struct Config {
    pub approved_programs: Vec<Pubkey>,  // Whitelist
}

#[derive(Accounts)]
pub struct CallExternalProgram<'info> {
    /// CHECK: Validated against whitelist
    pub external_program: UncheckedAccount<'info>,
    pub config: Account<'info, Config>,
}

pub fn call_external(ctx: Context<CallExternalProgram>) -> Result<()> {
    // Validate against whitelist
    let is_approved = ctx.accounts.config.approved_programs
        .iter()
        .any(|p| p == ctx.accounts.external_program.key);
    
    require!(is_approved, ErrorCode::ProgramNotApproved);
    
    // Now safe to make CPI
    solana_program::program::invoke(...)?;
    Ok(())
}
```

## 🚨 Common Mistakes

### Mistake 1: Using UncheckedAccount for Programs
```rust
// ❌ DANGEROUS - No validation!
pub struct MyCPI<'info> {
    /// CHECK: This is NOT checked!
    pub external_program: UncheckedAccount<'info>,
}
```

### Mistake 2: Only Checking Program Exists
```rust
// ❌ INSUFFICIENT - Checks account exists but not which program
if external_program.owner != &system_program::ID {
    // This only verifies it's a program, not WHICH program!
}
```

### Mistake 3: Trusting Client-Provided Program Discriminators
```rust
// ❌ WRONG - Attacker can fake discriminators
let discriminator = external_program.data()[0..8];
if discriminator == EXPECTED_DISCRIMINATOR {
    // Attacker's program can have same discriminator!
    // Must check PROGRAM ID, not discriminator
}
```

### Mistake 4: Partial Validation
```rust
// ❌ INCOMPLETE - Only checks first few bytes
if program_id[0..4] == EXPECTED_ID[0..4] {
    // Attacker can create program ID matching first 4 bytes
    // Must compare ENTIRE program ID
}
```

## 📊 Testing the Exploit

```typescript
describe("Arbitrary CPI Validation Exploit", () => {
  it("Vulnerable: Malicious program drains vault", async () => {
    // Deploy malicious "token program"
    const maliciousProgram = await deployMaliciousProgram();
    
    const vaultBalanceBefore = await getVaultBalance(vaultPda);
    console.log(`Vault balance before: ${vaultBalanceBefore} SOL`);

    // ❌ ATTACK: Call vulnerable program with malicious program
    await vulnerableProgram.methods
      .executeSwap(new BN(1_000_000))
      .accounts({
        user: attacker.publicKey,
        swapProgram: maliciousProgram.programId,  // ❌ Malicious!
        vaultTokenAccount: vaultAccount,
        userTokenAccount: attackerAccount,
        vault: vaultPda,
      })
      .signers([attacker])
      .rpc();

    const vaultBalanceAfter = await getVaultBalance(vaultPda);
    const attackerBalanceAfter = await getBalance(attacker.publicKey);
    
    console.log(`Vault balance after: ${vaultBalanceAfter} SOL`);
    console.log(`Attacker balance after: ${attackerBalanceAfter} SOL`);
    console.log(`💰 Attacker stole ${vaultBalanceBefore - vaultBalanceAfter} SOL`);
    
    assert.equal(vaultBalanceAfter, 0, "Vault should be drained");
  });

  it("Secure: Program validation blocks malicious program", async () => {
    const maliciousProgram = await deployMaliciousProgram();

    try {
      await secureProgram.methods
        .executeSwap(new BN(1_000_000))
        .accounts({
          user: attacker.publicKey,
          tokenProgram: maliciousProgram.programId,  // ❌ Wrong program
          vaultTokenAccount: vaultAccount,
          userTokenAccount: attackerAccount,
          vault: vaultPda,
        })
        .signers([attacker])
        .rpc();
      
      assert.fail("Should have rejected malicious program");
    } catch (err) {
      assert.include(err.message, "InvalidProgram");
      console.log("✅ Attack blocked: Program ID validation prevented malicious CPI");
    }
  });

  it("Secure: Only accepts legitimate Token Program", async () => {
    // This should succeed with real Token Program
    await secureProgram.methods
      .executeSwap(new BN(1_000_000))
      .accounts({
        user: user.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,  // ✅ Legitimate program
        vaultTokenAccount: vaultAccount,
        userTokenAccount: userAccount,
        vault: vaultPda,
      })
      .signers([user])
      .rpc();
    
    console.log("✅ Legitimate transfer succeeded");
  });
});
```

## 🎓 Key Takeaways

1. **Never Trust Client-Provided Programs**: The client can pass ANY program account. Your program must validate it.

2. **Hardcode Expected Program IDs**: Use constants for well-known programs like Token Program, System Program, etc.

3. **Validate Before Every CPI**: Check program ID immediately before making the cross-program call.

4. **Use Anchor's Type Safety**: `Program<'info, Token>` automatically validates the program ID.

5. **Whitelist for Unknown Programs**: If integrating with external programs, maintain an approved list.

6. **Full Address Comparison**: Compare the entire 32-byte program ID, not just prefixes or discriminators.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Treat every CPI like handing someone a signed check with your vault's authority. <strong>Always verify who you're giving it to.</strong> One unvalidated CPI can drain your entire protocol.
</blockquote>

## 🔗 Additional Resources

- [Cashio Exploit Post-Mortem](https://blog.neodyme.io/posts/cashio_exploit/)
- [Solana CPI Security Guide](https://docs.solana.com/developing/programming-model/calling-between-programs#program-security)
- [Anchor Program Types](https://www.anchor-lang.com/docs/account-types)
- [Example Code: Arbitrary CPI Validation](https://github.com/your-repo/examples/07-arbitrary-cpi-validation)

## ✅ Security Checklist

Before making any CPI:

- [ ] Program ID is hardcoded or from a validated whitelist
- [ ] Using `Program<'info, T>` type in Anchor for automatic validation
- [ ] Manual validation in Pinocchio compares full 32-byte address
- [ ] No use of `UncheckedAccount` for program accounts
- [ ] Tests cover malicious program attack scenario
- [ ] All CPIs that pass authority are especially scrutinized
- [ ] Program ID validation happens BEFORE any invoke/invoke_signed call

**Remember**: A CPI with authority is like a power of attorney. You wouldn't give power of attorney to a random stranger. Don't make CPIs to unvalidated programs. The $52M Cashio exploit proves this isn't theoretical - it's critical.
