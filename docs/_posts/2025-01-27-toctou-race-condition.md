---
layout: post
title: "TOCTOU Race Condition"
date: 2025-01-27
category: "External Interactions"
difficulty: "Advanced"
checklist: 
  - "Do you update state BEFORE making external calls (CPIs)?"
  - "Are you using a reentrancy guard (locked flag) when needed?"
  - "Does your instruction follow Checks-Effects-Interactions pattern?"
  - "Are state changes atomic and complete before any CPI?"
---

## 📖 The Scenario
You're a bank teller. A customer hands you their checkbook showing a balance of $10,000 and asks to withdraw $8,000.

1. You **CHECK** the balance: "$10,000 available, $8,000 withdrawal is fine"
2. You hand them the $8,000 cash
3. While you're counting the cash, the customer **quickly runs to another teller**
4. They show the SAME checkbook to the other teller: "I have $10,000, withdraw $8,000"
5. The other teller checks: "Yup, $10,000 balance, here's your $8,000"
6. The customer runs back to you while you're still counting
7. You **USE** the checkbook and write "$2,000 remaining"
8. Customer runs to other teller, who also writes "$2,000 remaining"

**Result**: Customer withdrew $16,000 from a $10,000 account because neither teller updated the balance BEFORE handing out cash. This is a **Time-Of-Check to Time-Of-Use (TOCTOU)** vulnerability.

## 💡 The "Aha!" Moment
TOCTOU is a **race condition** where:

1. **Time of Check**: Your program validates something (e.g., "user has enough balance")
2. **External Call**: Your program makes a CPI or hands control to another program
3. **Reentrancy Window**: The external program can call BACK into your program
4. **Time of Use**: Your program updates state based on the original check

If state isn't updated BEFORE step 2, the reentrant call sees the OLD state and can exploit it.

**In Solana specifically:**
- When your program makes a CPI, execution pauses
- The called program can invoke YOUR program again (reentrancy)
- If you haven't updated state, the reentrant call sees stale data
- Attacker drains your protocol by exploiting the time gap

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/toctou.svg" alt="TOCTOU Race Condition Diagram">
</div>

## 🌍 Real-World Case Study: The 2016 DAO Hack (Ethereum)

While this is an Ethereum example, TOCTOU/reentrancy vulnerabilities are cross-platform and have affected Solana protocols.

**June 2016** - The DAO, Ethereum's first major smart contract project, lost **$60 million** (3.6M ETH).

**The Vulnerability:**
```solidity
// Ethereum code (simplified)
function withdraw(uint amount) public {
    // TIME OF CHECK: Verify balance
    require(balances[msg.sender] >= amount);
    
    // EXTERNAL CALL: Send ETH BEFORE updating state
    msg.sender.call.value(amount)();  // ← Reentrancy happens here!
    
    // TIME OF USE: Update balance AFTER sending funds
    balances[msg.sender] -= amount;  // ← Too late!
}
```

**The Attack:**
1. Attacker calls `withdraw(1 ETH)`
2. DAO checks balance: "You have 10 ETH, withdrawal approved"
3. DAO sends 1 ETH to attacker's contract
4. Attacker's contract receives ETH, **immediately calls withdraw() again**
5. DAO checks balance again: "Still shows 10 ETH!" (not updated yet)
6. DAO sends another 1 ETH
7. This loops until DAO is drained
8. Only THEN does DAO update balance to 9 ETH (once for first withdrawal)

**Impact:**
- 3.6 million ETH stolen (~$60M at the time)
- Led to Ethereum's controversial hard fork
- Birth of Ethereum Classic (the chain that didn't reverse the hack)
- Changed how the entire blockchain industry thinks about smart contract security

**Solana Parallel: Saber Stablecoin Pools (2021)**

In 2021, several Solana AMM pools had similar TOCTOU vulnerabilities where:
1. Pool checks user's LP token balance
2. Pool burns LP tokens and sends back underlying assets
3. If burn happens before state update, attacker could re-enter
4. Attacker drains pool by repeatedly withdrawing same LP position

While not as catastrophic as The DAO, these incidents demonstrated that reentrancy is NOT just an Ethereum problem - **Solana programs are equally vulnerable if developers don't follow Checks-Effects-Interactions.**

## ⚔️ The Exploit
### Vulnerable vs Secure

{% capture vulnerable_desc %}
Program checks balance, makes CPI to transfer funds, THEN updates state. During the CPI, attacker re-enters and exploits stale state.
{% endcapture %}

{% capture vulnerable_code %}
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    
    /// CHECK: Malicious program can exploit reentrancy
    pub callback_program: UncheckedAccount<'info>,
    
    pub token_program: Program<'info, Token>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    let vault_ta = &ctx.accounts.vault_token_account;
    
    // ⏰ TIME OF CHECK: Verify sufficient balance
    require!(
        vault_ta.amount >= amount, 
        VaultError::InsufficientFunds
    );
    
    // 🚨 VULNERABILITY: Callback before state update
    // This creates a reentrancy window
    if ctx.accounts.callback_program.key() != &Pubkey::default() {
        // Attacker's program can call withdraw() again here!
        invoke_callback(ctx.accounts.callback_program)?;
    }
    
    // 🔓 CPI BEFORE STATE UPDATE - DANGEROUS!
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: vault_ta.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
        ),
        amount,
    )?;
    
    // ⏰ TIME OF USE: Update state AFTER transfer
    // ❌ Too late! Reentrant call already drained funds
    vault.total_deposits = vault
        .total_deposits
        .checked_sub(amount)
        .unwrap();
    
    Ok(())
}
{% endcapture %}

{% capture secure_desc %}
Program uses reentrancy guard and updates state BEFORE making any external calls (Checks-Effects-Interactions pattern).
{% endcapture %}

{% capture secure_code %}
#[account]
pub struct Vault {
    pub total_deposits: u64,
    pub bump: u8,
    pub locked: bool,  // ✅ Reentrancy guard
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    let vault_ta = &ctx.accounts.vault_token_account;
    
    // ✅ STEP 0: Reentrancy guard
    require!(!vault.locked, VaultError::ReentrancyBlocked);
    vault.locked = true;
    
    // ✅ STEP 1: CHECKS - Validate all preconditions
    require!(
        vault_ta.amount >= amount, 
        VaultError::InsufficientFunds
    );
    
    // ✅ STEP 2: EFFECTS - Update state BEFORE external calls
    vault.total_deposits = vault
        .total_deposits
        .checked_sub(amount)
        .unwrap();
    
    // ✅ STEP 3: INTERACTIONS - External calls AFTER state update
    // Even if reentrancy occurs, state is already updated
    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: vault_ta.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: vault.to_account_info(),
            },
        ),
        amount,
    )?;
    
    // ✅ Release reentrancy guard
    vault.locked = false;
    
    Ok(())
}

#[error_code]
pub enum VaultError {
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Reentrancy attempt blocked")]
    ReentrancyBlocked,  // ✅ New error
}
{% endcapture %}

{% include comparison-card.html 
   vulnerable_desc=vulnerable_desc 
   vulnerable_code=vulnerable_code 
   secure_desc=secure_desc 
   secure_code=secure_code 
%}

## 🎯 Attack Walkthrough

### Step 1: Attacker Creates Malicious Program
```rust
// Malicious program that re-enters the vulnerable vault
#[program]
pub mod attacker_program {
    use super::*;
    
    // Called during the CPI from vulnerable program
    pub fn callback(ctx: Context<Callback>) -> Result<()> {
        msg!("Malicious callback executing!");
        
        // ❌ RE-ENTER the vulnerable program's withdraw!
        // State hasn't been updated yet, so we can withdraw again
        invoke_withdraw_again(ctx.accounts.vault_program)?;
        
        Ok(())
    }
    
    fn invoke_withdraw_again(vault_program: &AccountInfo) -> Result<()> {
        // Call withdraw() on vulnerable program again
        // Balance still shows original amount!
        msg!("Calling withdraw again while first withdraw is in progress!");
        // ... invoke code ...
        Ok(())
    }
}
```

### Step 2: The Attack Sequence
```typescript
describe("TOCTOU Attack", () => {
  it("Vulnerable: Reentrancy drains vault", async () => {
    // Vault has 10,000 tokens
    const vaultBalance = 10_000_000_000; // 10,000 with 6 decimals
    
    console.log(`Initial vault balance: ${vaultBalance}`);
    
    // ❌ Attacker calls withdraw with malicious callback
    await vulnerableProgram.methods
      .withdraw(new BN(8_000_000_000))  // Withdraw 8,000
      .accounts({
        user: attacker.publicKey,
        vault: vaultPda,
        vaultTokenAccount: vaultTokenAccount,
        userTokenAccount: attackerTokenAccount,
        callbackProgram: maliciousCallbackProgram,  // ← Malicious!
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([attacker])
      .rpc();
    
    /* What happens:
     * 1. Vault checks balance: ✅ 10,000 >= 8,000
     * 2. Vault calls malicious callback program
     * 3. Malicious program calls withdraw() AGAIN
     * 4. Vault checks balance: ✅ Still shows 10,000! (not updated)
     * 5. Vault sends another 8,000 tokens
     * 6. First withdraw sends 8,000 tokens
     * 7. Finally vault updates: total_deposits -= 8,000 (only once!)
     * 
     * Result: Attacker got 16,000 tokens from 10,000 vault!
     */
    
    const finalBalance = await getVaultBalance(vaultTokenAccount);
    console.log(`Final vault balance: ${finalBalance}`);
    console.log(`❌ Vault should have 2,000 but has ${finalBalance}`);
    console.log(`💰 Attacker stole ${16_000_000_000 - vaultBalance} tokens via reentrancy!`);
  });
});
```

### Step 3: Visual Timeline
```
Time 0: Vault Balance = 10,000
        Attacker calls withdraw(8,000)

Time 1: [CHECK] Vault checks: 10,000 >= 8,000 ✓
        
Time 2: [CALLBACK] Vault calls malicious program
        
Time 3: [RE-ENTER] Malicious program calls withdraw(8,000) AGAIN
        
Time 4: [CHECK] Vault checks: 10,000 >= 8,000 ✓  ← Still sees 10,000!
        
Time 5: [TRANSFER] Inner withdraw sends 8,000 tokens
        
Time 6: [UPDATE] Inner withdraw updates: balance = 2,000
        
Time 7: [RETURN] Inner withdraw completes
        
Time 8: [TRANSFER] Outer withdraw sends 8,000 tokens  ← Second transfer!
        
Time 9: [UPDATE] Outer withdraw updates: balance = 2,000  ← Wrong! Should be -6,000

Result: Attacker received 16,000 tokens
        Vault thinks balance is 2,000
        Actual vault balance is -6,000 (impossible, but drained)
```

## 🧠 Mental Model: The Double-Spending Bank Teller

**Classic TOCTOU:** The ATM Problem
1. You check your balance: $1,000
2. You insert your card in ATM #1, start withdrawing $800
3. While ATM #1 is counting bills, you run to ATM #2
4. ATM #2 checks balance: Still $1,000! (not updated)
5. You withdraw $800 from ATM #2
6. ATM #1 finishes, dispenses $800, updates balance to $200
7. ATM #2 finishes, dispenses $800, updates balance to $200
8. **You withdrew $1,600 from a $1,000 account**

**The Fix:** The Locked Flag
1. You start withdrawal at ATM #1
2. Bank sets "account locked" flag
3. You try ATM #2: "Account is locked, please wait"
4. ATM #1 finishes withdrawal AND updates balance
5. Bank clears "account locked" flag
6. Now you can use ATM #2, but balance is correctly $200

This is exactly how reentrancy guards work - they lock the account during critical operations.

## 🔍 Pinocchio Implementation

```rust
use pinocchio::{AccountView, ProgramResult, error::ProgramError};

// Vault data layout: [discriminator: 8][balance: 8][bump: 1][locked: 1]
const LOCKED_OFFSET: usize = 17;

fn get_locked(vault: &AccountView) -> Result<bool, ProgramError> {
    let data = vault.data();
    if data.len() < 18 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[LOCKED_OFFSET] != 0)
}

fn set_locked(vault: &AccountView, locked: bool) -> ProgramResult {
    unsafe {
        let mut data = vault.borrow_mut_data_unchecked();
        if data.len() < 18 {
            return Err(ProgramError::InvalidAccountData);
        }
        data[LOCKED_OFFSET] = if locked { 1 } else { 0 };
    }
    Ok(())
}

fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let vault = &accounts[1];
    let vault_token_account = &accounts[2];
    let user_token_account = &accounts[3];
    
    // ═══════════════════════════════════════════════════════════
    // STEP 0: REENTRANCY GUARD
    // ═══════════════════════════════════════════════════════════
    
    // ✅ Check if locked
    if get_locked(vault)? {
        msg!("Reentrancy detected! Vault is locked.");
        return Err(ProgramError::Custom(3)); // ReentrancyBlocked
    }
    
    // ✅ Lock the vault
    set_locked(vault, true)?;
    
    // ═══════════════════════════════════════════════════════════
    // STEP 1: CHECKS
    // ═══════════════════════════════════════════════════════════
    
    let vault_balance = get_token_balance(vault_token_account)?;
    if vault_balance < amount {
        set_locked(vault, false)?;  // Release lock on error
        return Err(ProgramError::InsufficientFunds);
    }
    
    // ═══════════════════════════════════════════════════════════
    // STEP 2: EFFECTS - Update state BEFORE external call
    // ═══════════════════════════════════════════════════════════
    
    update_vault_balance(vault, |balance| {
        balance.checked_sub(amount)
            .ok_or(ProgramError::InsufficientFunds)
    })?;
    
    // ═══════════════════════════════════════════════════════════
    // STEP 3: INTERACTIONS - External call AFTER state update
    // ═══════════════════════════════════════════════════════════
    
    // Even if this CPI enables reentrancy, state is already updated
    // Reentrant call will see reduced balance and locked flag
    Transfer {
        from: vault_token_account,
        to: user_token_account,
        authority: vault,
        amount,
    }
    .invoke_signed(token_program, signer_seeds)?;
    
    // ✅ Release lock
    set_locked(vault, false)?;
    
    Ok(())
}
```

## 🛡️ Defense Patterns

### Pattern 1: Reentrancy Guard (Locked Flag)
```rust
#[account]
pub struct Vault {
    pub balance: u64,
    pub locked: bool,  // ✅ Reentrancy guard
}

pub fn critical_operation(ctx: Context<CriticalOp>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Check and set lock
    require!(!vault.locked, ErrorCode::Reentrancy);
    vault.locked = true;
    
    // ... perform operations ...
    
    // Release lock
    vault.locked = false;
    Ok(())
}
```

### Pattern 2: Checks-Effects-Interactions
```rust
pub fn safe_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // 1️⃣ CHECKS: Validate everything
    require!(vault.balance >= amount, ErrorCode::InsufficientFunds);
    require!(user.is_authorized(), ErrorCode::Unauthorized);
    
    // 2️⃣ EFFECTS: Update ALL state
    vault.balance -= amount;
    vault.total_withdrawals += amount;
    user.last_withdraw_time = Clock::get()?.unix_timestamp;
    
    // 3️⃣ INTERACTIONS: Make external calls LAST
    token::transfer(cpi_context, amount)?;
    
    Ok(())
}
```

### Pattern 3: State Snapshot Validation
```rust
pub fn complex_operation(ctx: Context<ComplexOp>) -> Result<()> {
    // Take snapshot before external call
    let balance_before = ctx.accounts.vault.balance;
    
    // Make external call
    make_cpi()?;
    
    // Verify state wasn't unexpectedly modified
    require!(
        ctx.accounts.vault.balance == balance_before,
        ErrorCode::UnexpectedStateChange
    );
    
    Ok(())
}
```

## 🚨 Common Mistakes

### Mistake 1: Only Protecting Some Paths
```rust
// ❌ Lock only in one function but not others
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    require!(!vault.locked, ErrorCode::Reentrancy);
    vault.locked = true;
    // ... protected ...
}

pub fn emergency_withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // ❌ No lock! Attacker can re-enter through this function
    token::transfer(cpi_ctx, amount)?;
}
```

### Mistake 2: Forgetting to Release Lock on Error
```rust
// ❌ Lock is never released if error occurs
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.locked = true;
    
    // If this fails, lock is never released!
    require!(vault.balance >= amount, ErrorCode::InsufficientFunds);
    
    // ❌ Program is permanently locked
}

// ✅ Always release lock, even on error
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    require!(!vault.locked, ErrorCode::Reentrancy);
    vault.locked = true;
    
    let result = perform_withdraw(ctx, amount);
    
    vault.locked = false;  // ✅ Always release
    result
}
```

### Mistake 3: Using Global Locks
```rust
#[account]
pub struct GlobalState {
    pub locked: bool,  // ❌ One lock for ALL operations
}

// ❌ User A's withdrawal locks out User B's deposit
```

### Mistake 4: Updating Some State Before, Some After
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // ✅ Update this before
    vault.balance -= amount;
    
    // CPI happens here
    token::transfer(cpi_ctx, amount)?;
    
    // ❌ Update this after - WRONG!
    // Reentrant call sees updated balance but old withdrawal count
    vault.total_withdrawals += 1;
    
    Ok(())
}
```

## 📊 Testing for TOCTOU

```typescript
describe("TOCTOU/Reentrancy Testing", () => {
  // Test 1: Verify reentrancy guard blocks reentrant calls
  it("Secure: Reentrancy guard blocks double withdrawal", async () => {
    try {
      // Attempt reentrant call
      await secureProgram.methods
        .withdraw(new BN(1000))
        .accounts({ /* ... */ })
        .remainingAccounts([
          { pubkey: maliciousCallback, isWritable: false, isSigner: false }
        ])
        .rpc();
      
      assert.fail("Should block reentrancy");
    } catch (err) {
      assert.include(err.message, "ReentrancyBlocked");
    }
  });
  
  // Test 2: Verify state updates before CPI
  it("Secure: State updated before external call", async () => {
    const balanceBefore = await getVaultBalance();
    
    // Intercept and verify state during CPI
    const tx = await secureProgram.methods
      .withdraw(new BN(1000))
      .accounts({ /* ... */ })
      .rpc();
    
    // Verify balance was updated BEFORE transfer completed
    const logs = await getProgramLogs(tx);
    const stateUpdateLog = logs.find(l => l.includes("balance updated"));
    const transferLog = logs.find(l => l.includes("transfer executed"));
    
    const stateUpdateIndex = logs.indexOf(stateUpdateLog);
    const transferIndex = logs.indexOf(transferLog);
    
    assert.isTrue(stateUpdateIndex < transferIndex, 
      "State must be updated before transfer");
  });
  
  // Test 3: Stress test with rapid calls
  it("Secure: Handles rapid concurrent withdrawals", async () => {
    const promises = Array(100).fill(null).map((_, i) => 
      secureProgram.methods
        .withdraw(new BN(10))
        .accounts({ /* ... */ })
        .rpc()
        .catch(err => ({ error: err, index: i }))
    );
    
    const results = await Promise.all(promises);
    const errors = results.filter(r => r.error);
    
    // Some should be blocked by lock, but NO double-spending
    const finalBalance = await getVaultBalance();
    const expectedBalance = INITIAL_BALANCE - (100 - errors.length) * 10;
    
    assert.equal(finalBalance, expectedBalance, "Balance must be consistent");
  });
});
```

## 🎓 Key Takeaways

1. **TOCTOU = Time Gap Exploitation**: The vulnerability exists in the time between checking state and using state.

2. **Reentrancy in Solana**: When your program makes a CPI, the called program can invoke your program again before the first call completes.

3. **Checks-Effects-Interactions**: ALWAYS follow this pattern:
   - **Checks**: Validate all preconditions
   - **Effects**: Update ALL state
   - **Interactions**: Make external calls LAST

4. **Reentrancy Guards**: Use a `locked` flag to prevent reentrant calls during critical operations.

5. **Atomic State Updates**: All related state changes must happen together, before any external calls.

6. **Not Just Ethereum**: Reentrancy vulnerabilities affect ALL smart contract platforms, including Solana.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  <strong>Update your ledger BEFORE handing out the cash.</strong> Every CPI is a potential reentrancy window. Treat it like handing your vault keys to someone else - make sure your books are settled first.
</blockquote>

## 🔗 Additional Resources

- [The DAO Hack Explained](https://www.gemini.com/cryptopedia/the-dao-hack-makerdao)
- [Solana Reentrancy Patterns](https://blog.neodyme.io/posts/solana_reentrancy/)
- [Checks-Effects-Interactions Pattern](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)
- [Example Code: TOCTOU Race Condition](https://github.com/your-repo/examples/08-toctou-race-condition)

## ✅ Security Checklist

Before deploying any program with CPIs:

- [ ] All state updates happen BEFORE any external calls (CPIs)
- [ ] Reentrancy guard (locked flag) implemented for critical operations
- [ ] Lock is released in ALL code paths (success and error)
- [ ] Follows Checks-Effects-Interactions pattern strictly
- [ ] Tests include reentrancy attack scenarios
- [ ] Rapid concurrent call testing performed
- [ ] All related state changes are atomic and complete before CPI
- [ ] No global locks that could DoS other users

**Remember**: The DAO hack lost $60M because of this exact pattern. TOCTOU/reentrancy isn't theoretical - it's one of the most exploited vulnerabilities in blockchain history. Every CPI is a potential attack vector. Update state first, interact later, always.
