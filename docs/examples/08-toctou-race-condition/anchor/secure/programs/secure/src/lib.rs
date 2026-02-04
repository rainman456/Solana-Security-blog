use anchor_lang::prelude::*;
use anchor_spl::token::{self, TokenAccount};

declare_id!("SECU8toctouVa11d1d1d1d1d1d1d1d1d1d1d1d1d1");

#[account]
pub struct Vault {
    pub total_deposits: u64,
    pub bump: u8,
    pub locked: bool, // Reentrancy guard
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
    
    #[account(
        mut,
        constraint = vault_token_account.owner == vault.key() @ VaultError::InvalidOwner,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, token::Token>,
}

#[program]
pub mod secure_toctou {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let vault_ta = &ctx.accounts.vault_token_account;
        
        // FIX: Reentrancy guard - prevent reentrant calls
        require!(!vault.locked, VaultError::ReentrancyBlocked);
        vault.locked = true;
        
        // FIX: Checks-Effects-Interactions pattern
        // 1. CHECK: Verify sufficient balance
        require!(vault_ta.amount >= amount, VaultError::InsufficientFunds);
        
        // 2. EFFECTS: Update state BEFORE any external calls
        vault.total_deposits = vault.total_deposits.checked_sub(amount).unwrap();
        
        // 3. INTERACTIONS: Perform CPI AFTER state update
        // Reentrant call now sees updated accounting and cannot exploit
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
        
        // Release reentrancy guard
        vault.locked = false;
        
        Ok(())
    }
}

#[error_code]
pub enum VaultError {
    #[msg("Token account owner must be vault")]
    InvalidOwner,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Reentrancy attempt blocked")]
    ReentrancyBlocked, // CRITICAL FIX
}