---
layout: page
title: Security Guide
permalink: /security-guide/
---

# 🛡️ Solana Security Guide

**Complete setup and usage guide for the Solana Security Cookbook**

---

## Table of Contents

1. [Environment Setup](#environment-setup)
2. [Building Examples](#building-examples)
3. [Running Tests](#running-tests)
4. [Understanding the Code](#understanding-the-code)
5. [Security Checklist](#security-checklist)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Environment Setup

### Prerequisites

Before you begin, ensure you have the following installed:

#### 1. Rust (1.75.0 or later)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version
cargo --version
```

#### 2. Solana CLI (1.18.0 or later)

```bash
# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Verify installation
solana --version

# Set to localhost for testing
solana config set --url localhost
```

#### 3. Anchor (0.30.0 or later)

```bash
# Install Anchor Version Manager (AVM)
cargo install --git https://github.com/coral-xyz/anchor avm --locked --force

# Install Anchor
avm install latest
avm use latest

# Verify installation
anchor --version
```

#### 4. Bun (for running tests)

```bash
# Install Bun
curl -fsSL https://bun.sh/install | bash

# Verify installation
bun --version
```

### Clone the Repository

```bash
git clone https://github.com/your-username/solana-security-cookbook.git
cd solana-security-cookbook
```

### Install Dependencies

```bash
# Install Node.js dependencies
bun install
```

---

## Building Examples

### Anchor Programs

Each vulnerability has two Anchor programs: **vulnerable** and **secure**.

#### Build a Single Example

```bash
# Navigate to the example
cd examples/01-missing-signer-check/anchor/vulnerable

# Build the program
anchor build

# Build the secure version
cd ../secure
anchor build
```

#### Build All Anchor Examples

```bash
# From repository root
bun run build:anchor
```

This will build all vulnerable and secure versions for all 5 vulnerabilities.

### Pinocchio Programs

Pinocchio programs use `cargo build-sbf` instead of `anchor build`.

#### Build a Single Example

```bash
# Navigate to the example
cd examples/01-missing-signer-check/pinocchio/vulnerable

# Build the program
cargo build-sbf

# Build the secure version
cd ../secure
cargo build-sbf
```

#### Build All Pinocchio Examples

```bash
# From repository root
bun run build:pinocchio
```

### Understanding Build Output

After building, you'll find the compiled programs in:

**Anchor:**
```
examples/01-missing-signer-check/anchor/vulnerable/target/deploy/
└── vulnerable_program.so
```

**Pinocchio:**
```
examples/01-missing-signer-check/pinocchio/vulnerable/target/deploy/
└── vulnerable_program.so
```

---

## Running Tests

### Test Structure

Each vulnerability has a TypeScript test file that:
1. Deploys the vulnerable program
2. Demonstrates the exploit
3. Deploys the secure program
4. Verifies the fix blocks the exploit

### Run All Tests

```bash
bun test
```

### Run Specific Vulnerability Tests

```bash
# Missing Signer Check
bun test:missing-signer

# Incorrect PDA Validation
bun test:pda-validation

# Arithmetic Overflow
bun test:overflow

# Reentrancy Risk
bun test:reentrancy

# Unsafe Account Closure
bun test:account-closure
```

### Understanding Test Output

**Vulnerable Version:**
```
❌ Vulnerable: Bob can steal Alice's money
  💰 Alice deposits: 10 SOL
  💸 Bob attempts to withdraw: 5 SOL
  ⚠️  Bob is NOT Alice!
  ❌ ATTACK SUCCEEDED - Bob stole 5 SOL
```

**Secure Version:**
```
✅ Secure: Bob's attack is blocked
  🛡️  Secure program checks: Did Alice sign?
  ✅ Alice didn't sign → Transaction rejected
  ✅ ATTACK BLOCKED!
```

---

## Understanding the Code

### Repository Structure

```
solana-security-cookbook/
├── examples/
│   └── 01-missing-signer-check/
│       ├── anchor/
│       │   ├── vulnerable/
│       │   │   ├── programs/
│       │   │   │   └── vulnerable/
│       │   │   │       └── src/
│       │   │   │           └── lib.rs        # Vulnerable code
│       │   │   ├── Anchor.toml
│       │   │   └── Cargo.toml
│       │   └── secure/
│       │       └── ...                        # Secure version
│       ├── pinocchio/
│       │   ├── vulnerable/
│       │   │   ├── src/
│       │   │   │   └── lib.rs                # Vulnerable code
│       │   │   └── Cargo.toml
│       │   └── secure/
│       │       └── ...                        # Secure version
│       └── tests/
│           └── test.ts                        # TypeScript tests
```

### Anchor Code Structure

**Vulnerable Version:**
```rust
use anchor_lang::prelude::*;

#[program]
pub mod vulnerable_program {
    use super::*;
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // ❌ Missing signer check
        let vault = &mut ctx.accounts.vault;
        let user = &ctx.accounts.user;
        
        vault.balance -= amount;
        // Transfer logic...
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: AccountInfo<'info>,  // ❌ Should be Signer<'info>
    
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
```

**Secure Version:**
```rust
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

### Pinocchio Code Structure

**Vulnerable Version:**
```rust
use pinocchio::{
    AccountView,
    error::ProgramError,
    ProgramResult,
};

pub fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    let vault = &accounts[1];
    
    // ❌ Missing signer check
    
    // Transfer logic...
    Ok(())
}
```

**Secure Version:**
```rust
pub fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    let user = &accounts[0];
    let vault = &accounts[1];
    
    // ✅ Manual signer check
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Transfer logic...
    Ok(())
}
```

---

## Security Checklist

Use this checklist before deploying any Solana program:

### ✅ Signer Checks
- [ ] All privileged operations use `Signer<'info>` (Anchor) or check `is_signer()` (Pinocchio)
- [ ] Withdrawals require signer verification
- [ ] Transfers require signer verification
- [ ] Admin functions require signer verification

### ✅ PDA Validation
- [ ] PDAs are derived with correct seeds
- [ ] Bump seeds are validated
- [ ] PDA ownership is verified
- [ ] Seeds cannot be manipulated by users

### ✅ Arithmetic Safety
- [ ] All arithmetic uses `checked_*` methods or overflow checks are enabled
- [ ] No unchecked addition, subtraction, or multiplication
- [ ] Division by zero is handled
- [ ] Type casting is safe

### ✅ Reentrancy Protection
- [ ] State updates happen before CPI calls
- [ ] Account balances are updated before transfers
- [ ] No state changes after external calls

### ✅ Account Closure
- [ ] Account data is zeroed before closure
- [ ] All lamports are transferred out
- [ ] Rent-exempt minimum is handled
- [ ] Revival attacks are prevented

### ✅ General Security
- [ ] All accounts are validated (owner, type, etc.)
- [ ] Error handling is comprehensive
- [ ] No uninitialized data is used
- [ ] Tests cover attack scenarios

---

## Best Practices

### 1. Always Use Signer Types

**❌ Don't:**
```rust
pub user: AccountInfo<'info>
```

**✅ Do:**
```rust
pub user: Signer<'info>
```

### 2. Validate PDAs Properly

**❌ Don't:**
```rust
// No validation
pub vault: AccountInfo<'info>
```

**✅ Do:**
```rust
#[account(
    seeds = [b"vault", user.key().as_ref()],
    bump,
)]
pub vault: Account<'info, Vault>
```

### 3. Use Checked Arithmetic

**❌ Don't:**
```rust
balance = balance - amount;  // Can underflow!
```

**✅ Do:**
```rust
balance = balance.checked_sub(amount)
    .ok_or(ErrorCode::InsufficientFunds)?;
```

### 4. Update State Before CPI

**❌ Don't:**
```rust
transfer_tokens()?;
vault.balance -= amount;  // Too late!
```

**✅ Do:**
```rust
vault.balance -= amount;  // Update first
transfer_tokens()?;
```

### 5. Close Accounts Properly

**❌ Don't:**
```rust
// Just transfer lamports
**vault.to_account_info().lamports.borrow_mut() = 0;
```

**✅ Do (Anchor):**
```rust
#[account(
    mut,
    close = user  // Anchor handles it properly
)]
pub vault: Account<'info, Vault>
```

---

## Troubleshooting

### Build Errors

#### "anchor: command not found"

```bash
# Reinstall Anchor
cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
avm install latest
avm use latest
```

#### "cargo build-sbf: command not found"

```bash
# Install Solana BPF tools
solana-install init
```

### Test Errors

#### "Connection refused" when running tests

```bash
# Start local validator
solana-test-validator

# In another terminal, run tests
bun test
```

#### "Program not found"

```bash
# Rebuild the program
cd examples/01-missing-signer-check/anchor/vulnerable
anchor build

# Or for Pinocchio
cd examples/01-missing-signer-check/pinocchio/vulnerable
cargo build-sbf
```

### Common Issues

#### Anchor version mismatch

```bash
# Check Anchor version in Cargo.toml
anchor-lang = "0.30.0"

# Update if needed
avm install 0.30.0
avm use 0.30.0
```

#### Pinocchio version mismatch

```toml
# Ensure Cargo.toml has:
[dependencies]
pinocchio = { version = "0.10.1", features = ["cpi"] }
```

---

## Additional Resources

### Documentation
- [Anchor Book](https://book.anchor-lang.com/)
- [Pinocchio Docs](https://docs.rs/pinocchio)
- [Solana Cookbook](https://solanacookbook.com/)

### Security Resources
- [Neodyme Security Blog](https://blog.neodyme.io/)
- [Cantina Security Guide](https://cantina.xyz/blog/securing-solana-a-developers-guide)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)

### Community
- [Solana Stack Exchange](https://solana.stackexchange.com/)
- [Anchor Discord](https://discord.gg/anchor)
- [Solana Discord](https://discord.gg/solana)

---

## Need Help?

- 🐛 [Report an issue](https://github.com/your-username/solana-security-cookbook/issues)
- 💬 [Start a discussion](https://github.com/your-username/solana-security-cookbook/discussions)
- 📧 [Contact us](mailto:security@example.com)

---

**Remember: Security is not optional. Test thoroughly before deploying to mainnet!**
