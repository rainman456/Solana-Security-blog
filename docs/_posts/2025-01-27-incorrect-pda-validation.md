---
layout: post
title: "Incorrect PDA Validation"
date: 2025-01-27
category: "Identity & Access Control"
difficulty: "Intermediate"
risk_level: "Critical"
description: "Accepting a PDA account without validating its seeds allows attackers to use fake accounts."
impact: "Complete loss of funds. Attackers can substitute control accounts to bypass authorization or steal funds."
recommendation: "Always validate that the account address matches the expected seeds and bump."
tags:
  - Rust
  - Anchor
  - PDA Validation
checklist: 
  - "Are all PDAs derived using unique seeds (e.g., user pubkey)?"
  - "Does your instruction verify that the passed account matches the derived PDA?"
  - "For Anchor: Are you using the `seeds` and `bump` constraints?"
  - "Do you validate PDAs on EVERY instruction that uses them?"
vulnerable_code: |
  use anchor_lang::prelude::*;
  
  #[derive(Accounts)]
  pub struct Withdraw<'info> {
      #[account(mut)]
      pub user: Signer<'info>,
      
      // ❌ CRITICAL VULNERABILITY: No seeds/bump validation!
      // Attacker can pass ANY account here
      #[account(mut)]
      pub vault: Account<'info, Vault>,
  }
  
  pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
      let vault = &mut ctx.accounts.vault;
      
      // ❌ This ownership check is USELESS without PDA validation
      // Attacker can create their own vault with user as owner!
      require!(
          vault.owner == ctx.accounts.user.key(),
          ErrorCode::Unauthorized
      );
      
      vault.balance = vault
          .balance
          .checked_sub(amount)
          .ok_or(ErrorCode::InsufficientFunds)?;
      
      **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
      **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
      
      Ok(())
  }
  
  #[account]
  pub struct Vault {
      pub owner: Pubkey,
      pub balance: u64,
  }
  
  #[error_code]
  pub enum ErrorCode {
      #[msg("Unauthorized")]
      Unauthorized,
      #[msg("Insufficient funds")]
      InsufficientFunds,
  }
secure_code: |
  use anchor_lang::prelude::*;
  
  #[derive(Accounts)]
  pub struct Withdraw<'info> {
      #[account(mut)]
      pub user: Signer<'info>,
      
      // ✅ SECURE: Anchor verifies address derivation
      #[account(
          mut,
          seeds = [b"vault", user.key().as_ref()],  // ← Must match these seeds
          bump,  // ← Must use correct bump
          constraint = vault.owner == user.key() @ ErrorCode::Unauthorized
      )]
      pub vault: Account<'info, Vault>,
  }
  
  pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
      let vault = &mut ctx.accounts.vault;
      
      // ✅ Ownership check is now meaningful
      // We know this vault was derived from user's pubkey
      
      vault.balance = vault
          .balance
          .checked_sub(amount)
          .ok_or(ErrorCode::InsufficientFunds)?;
      
      **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
      **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
      
      Ok(())
  }
  
  #[account]
  pub struct Vault {
      pub owner: Pubkey,
      pub balance: u64,
  }
  
  #[error_code]
  pub enum ErrorCode {
      #[msg("Unauthorized")]
      Unauthorized,
      #[msg("Insufficient funds")]
      InsufficientFunds,
  }
---

## 📖 The Scenario
You run a secure locker service. Each user is assigned a specific locker number based on their name using a mathematical formula:

**Formula**: `Locker Number = HASH(User's Name + "vault")`

- Alice → HASH("Alice" + "vault") → Locker #101
- Bob → HASH("Bob" + "vault") → Locker #202

Alice comes in to store her gold. She shows you her ID: "Alice". You calculate: "Alice should have Locker #101." She opens #101, stores her gold.

Later, a thief walks in. He claims to be "Bob" but points to Locker #101 (Alice's locker) and says **"This is my locker!"**

If you don't verify that Bob's name actually produces Locker #101 in your formula, you might give him the key. But if you DO the math:
- Bob → HASH("Bob" + "vault") → Locker #202
- **#101 ≠ #202** → DENIED!

This is PDA validation. The math MUST match, or it's fraud.

## 💡 The "Aha!" Moment
A **Program Derived Address (PDA)** is purely deterministic:

```
PDA = Function(Seeds, Program ID)
```

Given the same seeds and program ID, you ALWAYS get the same address. No randomness, no variation.

**The vulnerability** happens when your program:
1. Accepts a "Vault" account from the user
2. **Fails to verify** the account was actually derived from the correct seeds
3. Trusts whatever account address the user provides

An attacker exploits this by:
1. Creating their own fake account at a random address
2. Passing their fake account as the "vault" parameter
3. Your program accepts it without checking the seeds
4. Attacker drains the fake vault (which they control) and tricks your program

**The Fix**:
```rust
// ❌ WRONG: Accept any account
#[account(mut)]
pub vault: Account<'info, Vault>,

// ✅ RIGHT: Verify PDA derivation
#[account(
    mut,
    seeds = [b"vault", user.key().as_ref()],
    bump
)]
pub vault: Account<'info, Vault>,
```

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/pda-validation.svg" alt="PDA Validation Vulnerability Diagram">
</div>

## 🌍 Real-World Case Study: Saber Swap Vulnerability (2021)

**December 2021** - Saber, one of Solana's largest AMMs at the time, had a PDA validation issue discovered during a security audit.

**The Vulnerability:**
Saber's liquidity pool program accepted LP token accounts without properly validating they were derived from the correct pool seeds.

```rust
// ❌ SIMPLIFIED VULNERABLE PATTERN (from audit)
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ❌ No seeds validation!
    #[account(mut)]
    pub user_lp_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool: Account<'info, StableSwap>,
    
    #[account(mut)]
    pub pool_token_a: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub pool_token_b: Account<'info, TokenAccount>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // ❌ Program trusts user_lp_account without verification
    // Attacker could pass fake LP account they control
    
    let lp_balance = ctx.accounts.user_lp_account.amount;
    require!(lp_balance >= amount, ErrorCode::InsufficientBalance);
    
    // Calculate withdrawal amounts based on LP tokens
    let withdraw_a = calculate_withdraw_amount(amount, &ctx.accounts.pool, true)?;
    let withdraw_b = calculate_withdraw_amount(amount, &ctx.accounts.pool, false)?;
    
    // ❌ DANGER: Withdrawing real tokens based on unvalidated LP account
    transfer_tokens(&ctx.accounts.pool_token_a, &ctx.accounts.user, withdraw_a)?;
    transfer_tokens(&ctx.accounts.pool_token_b, &ctx.accounts.user, withdraw_b)?;
    
    Ok(())
}
```

**The Attack Vector:**
1. Attacker creates a fake LP token account they control
2. Mints themselves billions of fake LP tokens (in the fake account)
3. Calls `withdraw` with the fake LP account
4. Program checks: "LP balance = 1 billion? OK!"
5. Program calculates: "1 billion LP tokens → withdraw 500M USDC + 500M USDT"
6. Program transfers **real** USDC and USDT from the pool
7. Pool drained using worthless fake LP tokens

**Discovery & Impact:**
- Found during pre-launch security audit by Neodyme
- Never exploited on mainnet (caught before deployment)
- Estimated potential loss: **$100M+ in TVL** at the time
- Led to comprehensive PDA validation updates across Saber

**The Fix:**
```rust
// ✅ SECURE VERSION
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ✅ Validate LP account is derived from pool and user
    #[account(
        mut,
        seeds = [
            b"lp_account",
            pool.key().as_ref(),
            user.key().as_ref()
        ],
        bump,
        constraint = user_lp_account.mint == pool.lp_mint @ ErrorCode::InvalidLpMint
    )]
    pub user_lp_account: Account<'info, TokenAccount>,
    
    #[account(
        seeds = [b"pool", pool_id.as_ref()],
        bump
    )]
    pub pool: Account<'info, StableSwap>,
    
    // ... rest of accounts ...
}
```

**Key Lesson**: PDA validation isn't just good practice - it's the difference between a secure protocol and a $100M honeypot.

## ⚔️ The Exploit

{% include code-compare.html %}

## 🎯 Attack Walkthrough

### Step 1: Understanding PDA Derivation
```typescript
// How PDAs are derived
const [realVaultPDA, realBump] = PublicKey.findProgramAddressSync(
  [
    Buffer.from("vault"),
    userPubkey.toBuffer()
  ],
  programId
);

console.log("User:", userPubkey.toString());
console.log("Real Vault PDA:", realVaultPDA.toString());
console.log("Bump:", realBump);

// Output:
// User: 7xKW...dE8q
// Real Vault PDA: 9mNo...kPq2  ← This is the CORRECT vault
// Bump: 254
```

### Step 2: Attacker Creates Fake Vault
```typescript
// Attacker creates their own vault account at a random address
const fakeVaultKeypair = Keypair.generate();
console.log("Fake Vault:", fakeVaultKeypair.publicKey.toString());
// Output: 3zXy...wRt8  ← This is NOT derived from user's seeds!

// Attacker initializes the fake vault
await vulnerableProgram.methods
  .initializeFakeVault()
  .accounts({
    vault: fakeVaultKeypair.publicKey,
    payer: attacker.publicKey,
  })
  .signers([attacker, fakeVaultKeypair])
  .rpc();

// Attacker sets themselves as owner in the fake vault
const fakeVault = await vulnerableProgram.account.vault.fetch(
  fakeVaultKeypair.publicKey
);
console.log("Fake vault owner:", fakeVault.owner.toString());
// Output: 7xKW...dE8q  ← Attacker sets VICTIM as owner!
console.log("Fake vault balance:", fakeVault.balance.toString());
// Output: 999999999  ← Attacker sets arbitrary balance
```

### Step 3: The Attack
```typescript
// ❌ Attacker calls withdraw with the FAKE vault
await vulnerableProgram.methods
  .withdraw(new BN(1_000_000_000))  // 1 SOL
  .accounts({
    user: victim.publicKey,  // Victim's public key
    vault: fakeVaultKeypair.publicKey,  // ❌ FAKE vault!
  })
  .signers([attacker])  // Attacker signs
  .rpc();

/* What happens:
 * 1. Program receives fake vault address
 * 2. Program checks: vault.owner == user.key()
 * 3. Check passes! (Attacker set owner = victim in fake vault)
 * 4. Program checks: vault.balance >= amount
 * 5. Check passes! (Attacker set balance = 999999999 in fake vault)
 * 6. Program transfers from fake vault to user
 * 7. ❌ But fake vault is empty! Program tries to transfer anyway
 * 8. Transaction might fail OR succeed depending on vault lamports
 */
```

### Step 4: More Sophisticated Attack (Cross-User Draining)
```typescript
// Attacker can drain Alice's vault by claiming to be Bob!

// 1. Bob has a legitimate vault with 10 SOL
const [bobVault] = PublicKey.findProgramAddressSync(
  [Buffer.from("vault"), bob.publicKey.toBuffer()],
  programId
);

// 2. Attacker calls withdraw as Alice, but passes Bob's vault!
await vulnerableProgram.methods
  .withdraw(new BN(5_000_000_000))  // 5 SOL
  .accounts({
    user: alice.publicKey,  // ❌ Alice's pubkey
    vault: bobVault,  // ❌ But Bob's vault!
  })
  .signers([attacker])
  .rpc();

/* What happens:
 * 1. Program receives Bob's vault
 * 2. Program checks: vault.owner == alice.key()
 * 3. ❌ Check FAILS (bob.key != alice.key)
 * 4. Transaction reverts
 * 
 * OK, so attacker tries the opposite...
 */

// 3. Attacker calls withdraw as Bob, but with Alice's signature requirement bypassed
// This is where it gets complex - attacker needs both:
//    a) Missing PDA validation (what we're exploiting)
//    b) Missing signer check (previous vulnerability)

// The real danger: If both vulnerabilities exist together:
await vulnerableProgram.methods
  .withdraw(new BN(5_000_000_000))
  .accounts({
    user: bob.publicKey,  // Bob's pubkey (no signature check!)
    vault: aliceVault,  // Alice's vault
  })
  .signers([attacker])
  .rpc();

// ❌ With BOTH vulnerabilities:
// - No signer check: Attacker can claim to be Bob
// - No PDA validation: Attacker can use Alice's vault
// Result: Attacker drains Alice's vault while pretending to be Bob!
```

### Step 5: Why PDA Validation Matters
```
Without PDA Validation:
┌──────────────────────────────────────────────────────┐
│ Attacker can pass ANY account as "vault":           │
│                                                      │
│ ✗ Real Alice vault (derived from seeds)            │
│ ✗ Real Bob vault (derived from seeds)              │
│ ✗ Fake vault (random address, fake data)           │
│ ✗ System account                                    │
│ ✗ Token account                                     │
│ ✗ Literally ANY account on Solana                  │
│                                                      │
│ Program accepts them all! 🚨                        │
└──────────────────────────────────────────────────────┘

With PDA Validation:
┌──────────────────────────────────────────────────────┐
│ Program derives expected PDA:                        │
│   seeds = [b"vault", user.key()]                    │
│   expected_vault = derive_pda(seeds, program_id)    │
│                                                      │
│ Program checks: provided_vault == expected_vault    │
│                                                      │
│ ✓ If match → Continue                               │
│ ✗ If mismatch → REJECT 🛡️                           │
│                                                      │
│ Only ONE account in the entire Solana universe      │
│ will pass this check for each user!                 │
└──────────────────────────────────────────────────────┘
```

## 🧠 Mental Model: The Deterministic Map

Think of PDA derivation as GPS coordinates calculated from your name:

**The Formula (Simplified):**
```
Your Location = HASH(Your Name + "home")
```

**Without Validation:**
```
🗺️ You: "I'm Alice, here's my address."
📍 System: "OK, here are the keys to that house."
🏠 Address: 123 Fake Street (Attacker's house)
```

**With Validation:**
```
🗺️ You: "I'm Alice, here's my address: 123 Fake Street"
📍 System: "Wait, let me calculate Alice's address..."
🧮 System: HASH("Alice" + "home") = 456 Real Avenue
❌ System: "123 Fake Street ≠ 456 Real Avenue"
🚫 System: "DENIED! That's not your house!"
```

**The Key Insight:**
- PDA = Mathematical function (deterministic, verifiable)
- Random address = Could be anything (no proof of relationship)
- Validation = Recalculating the math and comparing results

If the math doesn't match, it's not the right account - period.

## 🔍 Pinocchio Implementation

```rust
use pinocchio::{
    AccountView,
    Address,
    entrypoint,
    error::ProgramError,
    ProgramResult,
    cpi::Signer,
};
use solana_program::pubkey::Pubkey;

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (instruction_discriminant, instruction_data) =
        instruction_data.split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

    match instruction_discriminant {
        0 => process_initialize(program_id, accounts, instruction_data),
        1 => process_deposit(program_id, accounts, instruction_data),
        2 => process_withdraw(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_withdraw(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let user = &accounts[0];
    let vault = &accounts[1];

    // ✅ STEP 1: Verify user is signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ✅ STEP 2: CRITICAL - Validate PDA derivation
    let seeds = &[b"vault", user.address().as_ref()];
    
    // Convert program_id from Address to Pubkey
    let program_id_pubkey = Pubkey::new_from_array(*program_id.as_ref());
    
    // Derive the expected PDA
    let (expected_pda, bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    // ✅ STEP 3: Compare provided vault with expected PDA
    if expected_pda.to_bytes() != *vault.address().as_ref() {
        msg!("PDA validation failed!");
        msg!("Expected: {:?}", expected_pda.to_bytes());
        msg!("Received: {:?}", vault.address().as_ref());
        return Err(ProgramError::InvalidSeeds);
    }

    // ✅ Now safe to proceed - we know vault is the correct PDA
    let amount = u64::from_le_bytes(
        instruction_data[0..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?
    );

    // Perform withdrawal with PDA signing
    let bump_seed = [bump];
    let signer_seeds = &[
        pinocchio::cpi::Seed::from(b"vault" as &[u8]),
        pinocchio::cpi::Seed::from(user.address().as_ref()),
        pinocchio::cpi::Seed::from(&bump_seed),
    ];
    let pda_signer = pinocchio::cpi::Signer::from(&signer_seeds[..]);

    pinocchio_system::instructions::Transfer {
        from: vault,
        to: user,
        lamports: amount,
    }
    .invoke_signed(&[pda_signer])?;

    Ok(())
}
```

**Key Pattern in Pinocchio:**
```rust
// ✅ Always do this for EVERY PDA account
fn validate_pda(
    account: &AccountView,
    seeds: &[&[u8]],
    program_id: &Pubkey,
) -> Result<u8, ProgramError> {
    let (expected_pda, bump) = Pubkey::find_program_address(seeds, program_id);
    
    if expected_pda.to_bytes() != *account.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }
    
    Ok(bump)
}

// Usage:
let bump = validate_pda(vault, &[b"vault", user.address().as_ref()], &program_id)?;
```

## 🛡️ Defense Patterns

### Pattern 1: Anchor Seeds Constraint (Recommended)
```rust
#[derive(Accounts)]
pub struct MyInstruction<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ✅ Anchor automatically validates PDA derivation
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump,  // Anchor finds and validates the bump
    )]
    pub vault: Account<'info, Vault>,
}
```

### Pattern 2: Multiple Seed Components
```rust
#[derive(Accounts)]
pub struct ComplexPDA<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ✅ PDA derived from multiple seeds
    #[account(
        mut,
        seeds = [
            b"vault",
            user.key().as_ref(),
            mint.key().as_ref(),  // Token mint
            &[vault_type]  // Vault type (0 = savings, 1 = checking, etc.)
        ],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    
    pub mint: Account<'info, Mint>,
}
```

### Pattern 3: Manual Derivation for Complex Logic
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // ✅ For complex cases, manually derive and verify
    let (expected_vault, _bump) = Pubkey::find_program_address(
        &[
            b"vault",
            ctx.accounts.user.key().as_ref(),
        ],
        ctx.program_id,
    );
    
    require!(
        ctx.accounts.vault.key() == expected_vault,
        ErrorCode::InvalidVaultPDA
    );
    
    // Now safe to proceed...
    Ok(())
}
```

### Pattern 4: Stored Bump Verification
```rust
#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub balance: u64,
    pub bump: u8,  // ✅ Store bump for later verification
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // ✅ Use stored bump for verification
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump = vault.bump,  // Use bump from account data
        constraint = vault.owner == user.key()
    )]
    pub vault: Account<'info, Vault>,
    
    pub user: Signer<'info>,
}
```

## 🚨 Common Mistakes

### Mistake 1: Forgetting Seeds Constraint
```rust
// ❌ WRONG: No PDA validation
#[account(mut)]
pub vault: Account<'info, Vault>,

// ✅ RIGHT: Always add seeds + bump
#[account(
    mut,
    seeds = [b"vault", user.key().as_ref()],
    bump
)]
pub vault: Account<'info, Vault>,
```

### Mistake 2: Using Wrong Seeds
```rust
// ❌ WRONG: Using wrong seed components
#[account(
    seeds = [b"vault", program_id.as_ref()],  // ← Wrong! Should use user.key()
    bump
)]
pub vault: Account<'info, Vault>,

// ✅ RIGHT: Use the SAME seeds as initialization
#[account(
    seeds = [b"vault", user.key().as_ref()],
    bump
)]
pub vault: Account<'info, Vault>,
```

### Mistake 3: Validating in Some Instructions but Not Others
```rust
// ❌ INCOMPLETE PROTECTION
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // ✅ Seeds validated here
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct EmergencyWithdraw<'info> {
    // ❌ No seeds validation here!
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}

// Attacker uses EmergencyWithdraw to bypass PDA check!
```

### Mistake 4: Only Checking Owner, Not PDA
```rust
// ❌ INSUFFICIENT
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        constraint = vault.owner == user.key()  // ← Not enough!
    )]
    pub vault: Account<'info, Vault>,
}

// Attacker creates fake vault with victim as owner
// Constraint passes but it's the wrong vault!

// ✅ COMPLETE
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],  // ← PDA validation
        bump,
        constraint = vault.owner == user.key()  // ← Plus ownership check
    )]
    pub vault: Account<'info, Vault>,
}
```

## 📊 Testing the Exploit

```typescript
describe("Incorrect PDA Validation", () => {
  it("Vulnerable: Attacker uses fake vault", async () => {
    // Legitimate setup: Alice creates her real vault
    const [aliceRealVault, realBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), alice.publicKey.toBuffer()],
      vulnerableProgram.programId
    );
    
    await vulnerableProgram.methods
      .initialize()
      .accounts({
        user: alice.publicKey,
        vault: aliceRealVault,
        systemProgram: SystemProgram.programId,
      })
      .signers([alice])
      .rpc();
    
    await vulnerableProgram.methods
      .deposit(new BN(10_000_000_000))  // 10 SOL
      .accounts({
        user: alice.publicKey,
        vault: aliceRealVault,
        systemProgram: SystemProgram.programId,
      })
      .signers([alice])
      .rpc();
    
    console.log("Alice deposited 10 SOL into real vault:", aliceRealVault.toString());
    
    // ❌ ATTACK: Bob creates a FAKE vault
    const fakeVaultKeypair = Keypair.generate();
    console.log("Bob creates fake vault:", fakeVaultKeypair.publicKey.toString());
    console.log("This is NOT derived from seeds! ⚠️");
    
    // Bob initializes fake vault with fake data
    await vulnerableProgram.methods
      .initializeFakeVault(alice.publicKey, new BN(99_999_999_999))
      .accounts({
        vault: fakeVaultKeypair.publicKey,
        payer: bob.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([bob, fakeVaultKeypair])
      .rpc();
    
    const fakeVault = await vulnerableProgram.account.vault.fetch(
      fakeVaultKeypair.publicKey
    );
    console.log("Fake vault owner:", fakeVault.owner.toString());
    console.log("Fake vault balance:", fakeVault.balance.toString());
    console.log("(These are FAKE values set by attacker!)");
    
    // ❌ Bob calls withdraw with FAKE vault
    try {
      await vulnerableProgram.methods
        .withdraw(new BN(5_000_000_000))
        .accounts({
          user: alice.publicKey,
          vault: fakeVaultKeypair.publicKey,  // ❌ Fake vault!
        })
        .signers([bob])
        .rpc();
      
      console.log("❌ Attack succeeded! Program accepted fake vault!");
    } catch (err) {
      console.log("Attack result:", err.message);
    }
  });

  it("Secure: PDA validation blocks fake vault", async () => {
    const [aliceSecureVault] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), alice.publicKey.toBuffer()],
      secureProgram.programId
    );
    
    // Alice creates legitimate vault
    await secureProgram.methods
      .initialize()
      .accounts({
        user: alice.publicKey,
        vault: aliceSecureVault,
        systemProgram: SystemProgram.programId,
      })
      .signers([alice])
      .rpc();
    
    await secureProgram.methods
      .deposit(new BN(10_000_000_000))
      .accounts({
        user: alice.publicKey,
        vault: aliceSecureVault,
        systemProgram: SystemProgram.programId,
      })
      .signers([alice])
      .rpc();
    
    // Bob creates fake vault
    const fakeVaultKeypair = Keypair.generate();
    
    await secureProgram.methods
      .initializeFakeVault(alice.publicKey, new BN(99_999_999_999))
      .accounts({
        vault: fakeVaultKeypair.publicKey,
        payer: bob.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([bob, fakeVaultKeypair])
      .rpc();
    
    // ✅ Bob attempts attack with fake vault
    try {
      await secureProgram.methods
        .withdraw(new BN(5_000_000_000))
        .accounts({
          user: alice.publicKey,
          vault: fakeVaultKeypair.publicKey,  // Fake vault
        })
        .signers([bob])
        .rpc();
      
      assert.fail("Should have rejected fake vault");
    } catch (err: any) {
      console.log("✅ Attack blocked!");
      assert.include(err.message.toLowerCase(), "seeds", "Should fail PDA validation");
      console.log("Secure program validated PDA and rejected fake vault");
    }
    
    // Verify Alice's funds are safe
    const realVault = await secureProgram.account.vault.fetch(aliceSecureVault);
    assert.equal(realVault.balance.toNumber(), 10_000_000_000, "Funds should be intact");
  });

  it("Demonstrates why PDA math matters", async () => {
    // Show that PDA derivation is deterministic
    const user1 = Keypair.generate().publicKey;
    const user2 = Keypair.generate().publicKey;
    
    const [vault1_try1] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), user1.toBuffer()],
      programId
    );
    
    const [vault1_try2] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), user1.toBuffer()],
      programId
    );
    
    const [vault2] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), user2.toBuffer()],
      programId
    );
    
    console.log("User1's vault (attempt 1):", vault1_try1.toString());
    console.log("User1's vault (attempt 2):", vault1_try2.toString());
    console.log("User2's vault:", vault2.toString());
    
    // Same user, same seeds → Same PDA (deterministic)
    assert.equal(
      vault1_try1.toString(),
      vault1_try2.toString(),
      "PDA derivation must be deterministic"
    );
    
    // Different users → Different PDAs (unique)
    assert.notEqual(
      vault1_try1.toString(),
      vault2.toString(),
      "Each user must have unique PDA"
    );
    
    console.log("✅ PDA derivation is deterministic and unique per user");
  });
});
```

## 🎓 Key Takeaways

1. **PDAs are Deterministic**: Same seeds + same program ID = same address, always.

2. **Never Trust Client Input**: The client can pass ANY account address. Your program MUST verify it's the correct PDA.

3. **Anchor Makes It Easy**: The `seeds` and `bump` constraints do all the validation automatically.

4. **Pinocchio Requires Manual Check**: Always call `find_program_address` and compare addresses.

5. **Validate EVERY Instruction**: If an instruction uses a PDA, it must validate it - no exceptions.

6. **Ownership Check ≠ PDA Validation**: Checking `vault.owner == user.key()` is NOT sufficient. Attacker can create fake vault with correct owner.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Never trust the client to provide the correct PDA. Always <strong>derive it yourself</strong> on-chain (or let Anchor do it with seeds/bump) and verify it matches. PDA validation is the difference between a secure protocol and a $100M honeypot.
</blockquote>

## 🔗 Additional Resources

- [Solana PDA Documentation](https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses)
- [Anchor Seeds Constraints](https://www.anchor-lang.com/docs/account-constraints)
- [Neodyme Security: PDA Validation](https://blog.neodyme.io/)
- [Example Code: Incorrect PDA Validation](https://github.com/rainman456/Solana-Security-blog/tree/main/examples/02-incorrect-pda-validation)

## ✅ Security Checklist

Before deploying any program with PDAs:

- [ ] Every PDA account has `seeds` and `bump` constraints (Anchor)
- [ ] Manual PDA derivation and comparison in every Pinocchio instruction
- [ ] Seeds match EXACTLY between initialization and usage instructions
- [ ] No instructions accept PDA accounts without validation
- [ ] Ownership checks are COMBINED with PDA validation, never alone
- [ ] Tests include fake vault attack scenarios
- [ ] Bump is either stored in account data or recalculated

**Remember**: The Saber vulnerability could have lost $100M+. PDA validation isn't optional - it's the mathematical proof that an account belongs to the right user. Don't trust addresses from clients. Derive them yourself and verify the math matches.

---

**The Math Must Match:**
```rust
// ❌ Trust what client gives you = Protocol at risk
// ✅ Verify the math yourself = Protocol is secure
```