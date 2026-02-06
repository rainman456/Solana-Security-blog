use anchor_lang::prelude::*;
use anchor_spl::token::{self, TokenAccount};

declare_id!("11111111111111111111111111111111");

#[account]
pub struct Vault {
    pub total_deposits: u64,
    pub bump: u8,
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
    
    /// CHECK: Malicious program can be passed here for reentrancy
    pub callback_program: UncheckedAccount<'info>,
    pub token_program: Program<'info, token::Token>,
}

#[program]
pub mod vulnerable_toctou {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault_ta = &ctx.accounts.vault_token_account;
        
        // TIME OF CHECK: Verify sufficient balance
        require!(vault_ta.amount >= amount, VaultError::InsufficientFunds);
        
        // VULNERABILITY: CPI happens BEFORE state update
        // Malicious program re-enters here and drains remaining balance
        if ctx.accounts.callback_program.key() != Pubkey::default() {
            // Simulate callback that enables reentrancy
            let _callback_accounts = vec![
                ctx.accounts.user.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.vault_token_account.to_account_info(),
                ctx.accounts.user_token_account.to_account_info(),
                ctx.accounts.callback_program.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ];
            
            // In real exploit, this would be attacker-controlled CPI
            // For demo, we simulate the reentrancy window
        }
        
        // Perform transfer
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
        
        // TIME OF USE: Update accounting AFTER transfer
        // Too late! Reentrant call already drained additional funds
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits = vault.total_deposits.checked_sub(amount).unwrap();
        
        Ok(())
    }
}

#[error_code]
pub enum VaultError {
    #[msg("Token account owner must be vault")]
    InvalidOwner,
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
}
