---
layout: post
title: "Missing Mint Validation"
date: 2025-01-27
category: "Identity & Access Control"
difficulty: "Intermediate"
checklist: 
  - "Are you validating that token account mints match expected mints?"
  - "Do you check vault_token_account.mint == vault.token_mint?"
  - "For Anchor: Are you using constraint checks on mint fields?"
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

## 🌍 Real-World Case Study: The $8M Wormhole Exploit

While Wormhole's 2022 exploit was primarily a signature verification issue, mint validation problems have plagued numerous Solana protocols. A notable pattern emerged in early AMM implementations where:

**The Attack Pattern:**
1. Protocol accepts token deposits and issues LP tokens
2. User creates a fake token with the same symbol as a valuable asset
3. User deposits fake tokens, receives LP tokens based on fake balance
4. User redeems LP tokens for real, valuable assets from the pool
5. **Result:** Attacker trades worthless tokens for real value

**Real Impact:**
- Multiple DeFi protocols lost funds to mint confusion attacks in 2021-2022
- One lending protocol lost over $1M when attackers deposited fake "USDC"
- The fake tokens had identical symbols but different mint addresses
- Without proper validation, the protocol treated them as legitimate collateral

## ⚔️ The Exploit
### Vulnerable vs Secure

{% capture vulnerable_desc %}
The program accepts ANY token account without checking if the mint matches the vault's expected token type. Attacker can supply a worthless token account.
{% endcapture %}

{% capture vulnerable_code %}
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
{% endcapture %}

{% capture secure_desc %}
The program validates that both token accounts use the correct mint before allowing any transfers.
{% endcapture %}

{% capture secure_code %}
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

#[error_code]
pub enum VaultError {
    #[msg("Token account owner must be vault")]
    InvalidOwner,
    #[msg("Token account mint must match vault mint")]
    InvalidMint,  // ← New error for mint mismatch
}
{% endcapture %}

{% include comparison-card.html 
   vulnerable_desc=vulnerable_desc 
   vulnerable_code=vulnerable_code 
   secure_desc=secure_desc 
   secure_code=secure_code 
%}

## 🎯 Attack Walkthrough

Let's see how an attacker exploits missing mint validation:

### Step 1: Setup
```typescript
// Vault stores valuable USDC (mint address: USDC_MINT)
const vaultMint = USDC_MINT;

// Attacker creates worthless "ScamCoin"
const scamMint = await createMint(
  connection,
  attacker,
  attacker.publicKey,
  null,
  6  // Same decimals as USDC for extra deception
);

// Attacker mints themselves 1 billion ScamCoin
const attackerScamAccount = await createAccount(
  connection,
  attacker,
  scamMint,
  attacker.publicKey
);
await mintTo(
  connection,
  attacker,
  scamMint,
  attackerScamAccount,
  attacker,
  1_000_000_000_000_000  // 1 billion tokens
);
```

### Step 2: The Exploit (Deposit)
```typescript
// Attacker deposits ScamCoin pretending it's USDC
await program.methods
  .deposit(new BN(1_000_000))
  .accounts({
    user: attacker.publicKey,
    vaultTokenAccount: vaultUsdcAccount,  // Legitimate USDC vault
    vault: vaultPda,
    userTokenAccount: attackerScamAccount,  // ❌ ScamCoin account!
    tokenProgram: TOKEN_PROGRAM_ID,
  })
  .signers([attacker])
  .rpc();

// ❌ Vulnerable program doesn't check mint
// Attacker's ScamCoin balance is recorded as USDC deposit
```

### Step 3: The Profit (Withdraw)
```typescript
// Attacker withdraws real USDC using fake ScamCoin balance
await program.methods
  .withdraw(new BN(1_000_000))
  .accounts({
    user: attacker.publicKey,
    vaultTokenAccount: vaultUsdcAccount,  // Real USDC
    vault: vaultPda,
    userTokenAccount: attackerUsdcAccount,  // Real USDC account
    tokenProgram: TOKEN_PROGRAM_ID,
  })
  .signers([attacker])
  .rpc();

// ✅ Attacker receives real USDC
// 💰 Vault drained using worthless ScamCoin as "proof of deposit"
```

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

## 🔍 Pinocchio Implementation

In Pinocchio, you manually extract and validate the mint field:

```rust
// Helper to extract mint from token account (SPL Token layout)
fn get_token_account_mint(account: &AccountView) -> Result<Address, ProgramError> {
    let data = account.data();
    if data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    // Mint is at offset 0-32 in SPL Token account
    let mint_bytes: [u8; 32] = data[0..32]
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(Address::new(mint_bytes))
}

fn deposit(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let vault_token_account = &accounts[1];
    let vault = &accounts[2];
    let user_token_account = &accounts[3];

    // Get expected mint from vault state
    let vault_mint = get_vault_mint(vault)?;
    
    // ✅ CRITICAL: Verify vault token account mint
    let vault_ta_mint = get_token_account_mint(vault_token_account)?;
    if vault_ta_mint.as_ref() != vault_mint.as_ref() {
        return Err(ProgramError::Custom(0)); // InvalidMint
    }
    
    // ✅ CRITICAL: Verify user token account mint
    let user_ta_mint = get_token_account_mint(user_token_account)?;
    if user_ta_mint.as_ref() != vault_mint.as_ref() {
        return Err(ProgramError::Custom(0)); // InvalidMint
    }

    // Now safe to proceed with transfer
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

### Pattern 1: Explicit Mint Constraints (Anchor)
```rust
#[account(
    mut,
    constraint = token_account.mint == expected_mint @ ErrorCode::InvalidMint
)]
pub token_account: Account<'info, TokenAccount>,
```

### Pattern 2: Defensive Account Validation (Pinocchio)
```rust
// Always validate BOTH accounts in a swap/transfer
let vault_mint = get_mint(vault_token_account)?;
let user_mint = get_mint(user_token_account)?;

if vault_mint != expected_mint {
    return Err(ProgramError::Custom(INVALID_MINT));
}
if user_mint != expected_mint {
    return Err(ProgramError::Custom(INVALID_MINT));
}
```

### Pattern 3: Mint Whitelist for Multi-Token Vaults
```rust
#[account]
pub struct Vault {
    pub allowed_mints: Vec<Pubkey>,  // List of accepted tokens
    pub bump: u8,
}

// In instruction
let is_allowed = ctx.accounts.vault.allowed_mints
    .iter()
    .any(|mint| mint == &ctx.accounts.token_account.mint);

require!(is_allowed, ErrorCode::MintNotAllowed);
```

## 🚨 Common Mistakes

### Mistake 1: Only Checking Owner
```rust
// ❌ INSUFFICIENT - Only checks ownership, not mint
#[account(
    mut,
    constraint = token_account.owner == vault.key()
)]
pub token_account: Account<'info, TokenAccount>,
```

### Mistake 2: Assuming Token Account Derivation = Validation
```rust
// ❌ WRONG - PDA derivation doesn't validate mint
#[account(
    mut,
    seeds = [b"vault_token", user.key().as_ref()],
    bump,
)]
pub vault_token_account: Account<'info, TokenAccount>,
// Still need: constraint = vault_token_account.mint == expected_mint!
```

### Mistake 3: Validating Only One Side
```rust
// ❌ INCOMPLETE - Validates vault account but not user account
#[account(
    mut,
    constraint = vault_token_account.mint == vault.token_mint
)]
pub vault_token_account: Account<'info, TokenAccount>,

#[account(mut)]
pub user_token_account: Account<'info, TokenAccount>,  // ← Missing validation!
```

## 📊 Testing the Exploit

Here's a test that demonstrates the vulnerability:

```typescript
it("Vulnerable: Attacker deposits ScamCoin, withdraws USDC", async () => {
  // Setup: Vault expects USDC
  const vaultMint = USDC_MINT;
  
  // Attacker creates ScamCoin
  const scamMint = await createMint(connection, attacker, ...);
  const attackerScamAccount = await createAccount(connection, attacker, scamMint, ...);
  await mintTo(connection, attacker, scamMint, attackerScamAccount, 1_000_000);

  // ❌ ATTACK: Deposit ScamCoin (vulnerable program accepts it)
  await vulnerableProgram.methods
    .deposit(new BN(1_000_000))
    .accounts({
      userTokenAccount: attackerScamAccount,  // ScamCoin!
      vaultTokenAccount: vaultUsdcAccount,    // USDC vault
      ...
    })
    .rpc();

  console.log("✅ Attacker deposited ScamCoin as USDC");

  // ❌ ATTACK: Withdraw real USDC
  await vulnerableProgram.methods
    .withdraw(new BN(1_000_000))
    .accounts({
      userTokenAccount: attackerUsdcAccount,   // Real USDC
      vaultTokenAccount: vaultUsdcAccount,     // Real USDC
      ...
    })
    .rpc();

  const balance = await getAccount(connection, attackerUsdcAccount);
  console.log(`💰 Attacker stole ${balance.amount} USDC using worthless ScamCoin!`);
});

it("Secure: Mint validation blocks the attack", async () => {
  const scamMint = await createMint(connection, attacker, ...);
  const attackerScamAccount = await createAccount(connection, attacker, scamMint, ...);

  try {
    await secureProgram.methods
      .deposit(new BN(1_000_000))
      .accounts({
        userTokenAccount: attackerScamAccount,  // ScamCoin
        vaultTokenAccount: vaultUsdcAccount,    // USDC
        ...
      })
      .rpc();
    
    assert.fail("Should have rejected mismatched mint");
  } catch (err) {
    assert.include(err.message, "InvalidMint");
    console.log("✅ Attack blocked: Mint validation prevented ScamCoin deposit");
  }
});
```

## 🎓 Key Takeaways

1. **Token Account ≠ Token Type**: A token account stores tokens of a specific mint. Always verify the mint matches your expectations.

2. **Validate Both Sides**: In any transfer or swap, validate the mint of BOTH the source and destination token accounts.

3. **Don't Trust Client Data**: The client can pass any account. Your program must validate it's the correct token type.

4. **Anchor Makes It Easy**: Use `constraint = token_account.mint == expected_mint` on every token account.

5. **Pinocchio Requires Manual Checks**: Extract the mint from account data and compare it yourself.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Every token account interaction must validate: (1) Ownership is correct, (2) <strong>Mint matches expectations</strong>. Missing either check is a critical vulnerability.
</blockquote>

## 🔗 Additional Resources

- [SPL Token Account Layout](https://spl.solana.com/token#account-layout)
- [Anchor Token Constraints](https://www.anchor-lang.com/docs/token-constraints)
- [Neodyme: Token Validation Best Practices](https://blog.neodyme.io/)
- [Example Code: Missing Mint Validation](https://github.com/your-repo/examples/06-missing-mint-validation)

## ✅ Security Checklist

Before deploying any program that handles tokens:

- [ ] Every `TokenAccount` has a mint constraint
- [ ] The constraint references the correct expected mint (from vault state or instruction parameter)
- [ ] Both source AND destination accounts are validated in transfers
- [ ] Tests cover the attack scenario (wrong mint)
- [ ] If using Pinocchio, manual mint extraction and comparison is implemented
- [ ] Error messages clearly indicate mint mismatch

**Remember**: Mint validation is not optional. It's as critical as checking signatures. Without it, attackers can drain your protocol by trading worthless tokens for real value.
