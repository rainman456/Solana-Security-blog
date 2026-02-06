use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("11111111111111111111111111111111");

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct ExecuteSwap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // FIX: Hardcode expected program ID with type safety
    #[account(
        address = token::ID @ VaultError::InvalidProgram,
    )]
    pub token_program: Program<'info, Token>, // Type-safe validation
    
    #[account(
        mut,
        constraint = vault_token_account.owner == vault.key() @ VaultError::InvalidOwner,
        constraint = vault_token_account.mint == user_token_account.mint @ VaultError::InvalidMint,
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

#[program]
pub mod secure_cpi_validation {
    use super::*;

    pub fn execute_swap(ctx: Context<ExecuteSwap>, amount: u64) -> Result<()> {
        // FIX: CPI only to validated program ID
        anchor_spl::token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(), // Guaranteed to be token program
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
}

#[error_code]
pub enum VaultError {
    #[msg("Token account owner must be vault")]
    InvalidOwner,
    #[msg("Token account mints must match")]
    InvalidMint,
    #[msg("Invalid program ID - must be Token program")]
    InvalidProgram, // CRITICAL FIX
}
