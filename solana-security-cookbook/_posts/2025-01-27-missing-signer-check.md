# Missing Signer Check: The \$10M Mistake

::: danger CRITICAL VULNERABILITY
This vulnerability has led to **millions of dollars in losses** across Solana programs. It's the #1 most common security flaw in blockchain development.
:::

## The Story

Imagine you're building a digital vault. Users can deposit their money (SOL) and withdraw it later. Simple, right?

Here's what your code might look like:

```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    let user = &ctx.accounts.user;
    
    // Subtract money from vault
    vault.balance -= amount;
    
    // Send it to user
    transfer_sol(vault, user, amount)?;
    
    Ok(())
}
```

Looks fine, right? **Wrong.** This code has a critical flaw that lets anyone steal anyone's money.

## The Attack

Here's what a hacker would do:

1. **Find your vault** - Let's say you have 100 SOL in your vault
2. **Create a transaction** - The hacker creates a withdrawal transaction
3. **Put YOUR address** - The hacker puts your public key as the "user"
4. **Sign with THEIR key** - The hacker signs with their own keypair
5. **Submit it** - The program processes it... and **gives your money to the hacker**

::: details Wait, how does that work?
The program never checks WHO signed the transaction. It just sees:
- Instruction: "withdraw 100 SOL"
- User account: "YourPublicKey123"
- Vault account: "YourVault456"

The program assumes if someone provided your public key, they must be you. **WRONG!**

Anyone can provide any public key. The program must verify the **signature**.
:::

## Real-World Impact

This vulnerability has caused:

- **Direct theft** - Hackers draining user wallets
- **Protocol exploits** - DeFi protocols losing liquidity
- **Smart contract failures** - Programs becoming completely unusable
- **Loss of trust** - Users abandoning vulnerable protocols

**Cost to the ecosystem: Tens of millions of dollars.**

## The Fix

The fix is embarrassingly simple. Change ONE word:

```rust{3}
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,  // ← Changed from AccountInfo to Signer
    
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
```

That's it. **One word protects millions of dollars.**

## Why Does This Work?

The `Signer` type does three things:

1. **Checks the signature** - Verifies cryptographic signature is valid
2. **Verifies the account** - Ensures signature matches the account
3. **Happens automatically** - Before your code even runs

If someone tries to withdraw without signing, the transaction **fails immediately**:

```
Error: Missing required signature for account: YourPublicKey123
```

## Common Mistakes

### Mistake #1: Using AccountInfo

```rust
// ❌ WRONG - No signature check
pub user: AccountInfo<'info>
```

```rust
// ✅ RIGHT - Automatic signature check
pub user: Signer<'info>
```

### Mistake #2: Manual Check (Forgetting It)

```rust
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    let user = &ctx.accounts.user;
    
    // ❌ FORGOT TO CHECK: user.is_signer
    
    // Rest of code...
}
```

Even if you use `AccountInfo`, you MUST manually check:

```rust
require!(user.is_signer, ErrorCode::Unauthorized);
```

But it's easy to forget. **Use `Signer<'info>` instead.**

### Mistake #3: Checking Wrong Account

```rust
pub struct Withdraw<'info> {
    pub user: Signer<'info>,      // ✅ Good
    pub recipient: AccountInfo,    // ❌ Wait, who's receiving money?
}

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // User signed, but money goes to recipient
    // Attacker can set recipient to their address!
    transfer_sol(vault, recipient, amount)?;
}
```

Make sure you're sending money to the person who signed!

## Testing the Vulnerability

Run this test to see the attack in action:

```bash
bun test tests/01-missing-signer-check.test.ts
```

You'll see:

```
❌ Vulnerable: Bob can steal Alice's money
  💰 Alice deposits: 10 SOL
  💸 Bob attempts to withdraw: 5 SOL
  ⚠️  Bob is NOT Alice!
  ❌ ATTACK SUCCEEDED - Bob stole 5 SOL

✅ Secure: Bob's attack is blocked
  🛡️  Secure program checks: Did Alice sign?
  ✅ Alice didn't sign → Transaction rejected
  ✅ ATTACK BLOCKED!
```

## The Code Comparison

### Vulnerable Version

```rust
use anchor_lang::prelude::*;

#[program]
pub mod vulnerable_vault {
    use super::*;
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let user = &ctx.accounts.user;
        
        // 🚨 No signer check - anyone can call this!
        
        vault.balance -= amount;
        
        **user.to_account_info().lamports.borrow_mut() += amount;
        **vault.to_account_info().lamports.borrow_mut() -= amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: AccountInfo<'info>,  // ❌ NOT checking signature
    
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
```

### Secure Version

```rust
use anchor_lang::prelude::*;

#[program]
pub mod secure_vault {
    use super::*;
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let user = &ctx.accounts.user;
        
        // ✅ Signer<'info> already verified signature!
        
        require!(
            vault.owner == user.key(),
            ErrorCode::Unauthorized
        );
        
        vault.balance -= amount;
        
        **user.to_account_info().lamports.borrow_mut() += amount;
        **vault.to_account_info().lamports.borrow_mut() -= amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,  // ✅ Signature required!
    
    #[account(
        mut,
        constraint = vault.owner == user.key() @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
}
```

## Pinocchio Version

In Pinocchio, there's no automatic checking. You MUST manually verify:

```rust
pub fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    let vault = &accounts[1];
    
    // ✅ CRITICAL: Manual signer check
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Now safe to proceed...
}
```

::: warning Pinocchio Requires Discipline
In Pinocchio, every security check is manual. If you forget `is_signer()`, you're vulnerable.

**Anchor is safer** because `Signer<'info>` makes it impossible to forget.
:::

## Security Checklist

Before deploying your program, verify:

- [ ] All privileged operations use `Signer<'info>` (Anchor)
- [ ] OR manually check `is_signer()` (Pinocchio)
- [ ] Withdrawals require signer check
- [ ] Transfers require signer check
- [ ] Admin functions require signer check
- [ ] ANY operation that needs authorization has signer check
- [ ] Tests verify unauthorized access is blocked

## When to Use Signer

Use `Signer<'info>` for:

- ✅ Withdrawals
- ✅ Transfers
- ✅ Admin operations
- ✅ Privilege escalation
- ✅ State changes that need authorization
- ✅ Anything where you ask "Is this user allowed?"

Don't need `Signer` for:

- ✅ Read-only operations
- ✅ Public functions anyone can call
- ✅ Operations where authorization is checked another way

## Quiz Yourself

### Question 1

```rust
pub struct DepositTokens<'info> {
    pub user: AccountInfo<'info>,
    pub user_token_account: Account<'info, TokenAccount>,
}
```

**Is this vulnerable?**

::: details Answer
**YES!** Depositing tokens is a privileged operation. The user should be `Signer<'info>`.

Otherwise, an attacker could deposit from anyone's token account without their permission.
:::

### Question 2

```rust
pub struct ViewBalance<'info> {
    pub user: AccountInfo<'info>,
    pub vault: Account<'info, Vault>,
}
```

**Is this vulnerable?**

::: details Answer
**NO.** Viewing a balance is read-only. No signature needed.

Anyone can check anyone's balance - that's fine for public data.
:::

### Question 3

```rust
pub struct CloseAccount<'info> {
    pub authority: Signer<'info>,
    pub account: Account<'info, MyAccount>,
    pub recipient: AccountInfo<'info>,  // ← Who gets the SOL?
}
```

**Is this vulnerable?**

::: details Answer
**Maybe!** Depends on your logic:

- If `recipient` must be `authority`, it's fine
- If `recipient` can be anyone, attacker could set it to their address

Always verify the recipient!
:::

## Real Exploit Example

Here's how an actual exploit works:

```typescript
// Attacker's code
const victimPublicKey = new PublicKey("Victim123...");
const attackerKeypair = Keypair.generate();

// Create malicious transaction
const tx = await program.methods
  .withdraw(new BN(1000000000)) // 1 SOL
  .accounts({
    user: victimPublicKey,        // ← Victim's address
    vault: victimVault,
  })
  .signers([attackerKeypair])     // ← Attacker signs!
  .rpc();

// If program doesn't check signer:
// ✅ Transaction succeeds
// 💰 Attacker gets victim's SOL
// ❌ Victim never signed anything
```

## Best Practices

1. **Default to Signer** - Use `Signer<'info>` unless you have a good reason not to
2. **Be paranoid** - Ask yourself "Does this need authorization?"
3. **Test exploits** - Write tests that try to attack your program
4. **Code review** - Have someone else review your signer checks
5. **Use constraints** - Add `constraint = vault.owner == user.key()` for extra safety

## Summary

::: tip Key Takeaways
- **The vulnerability**: Forgetting to check signatures
- **The impact**: Complete loss of authorization - anyone can impersonate anyone
- **The fix**: Use `Signer<'info>` in Anchor or `is_signer()` in Pinocchio
- **The effort**: Literally changing one word
- **The importance**: Protects millions of dollars

**Never trust that an account is authorized unless you verify the signature.**
:::

## Next Steps

- [Run the tests](../testing) to see the exploit in action
- [Learn about owner checks](/vulnerabilities/missing-owner-check) - another critical vulnerability
- [Explore all vulnerabilities](/vulnerabilities/) to secure your programs

::: warning Remember
Missing signer checks are **critical vulnerabilities**. They're also **easy to fix**.

Don't be the developer who loses millions because they forgot one word.

Use `Signer<'info>`. Save millions. Sleep well.
:::