use anchor_lang::prelude::*;
use anchor_spl::token::{self, TokenAccount};

declare_id!("VULN7cpiVa11d1d1d1d1d1d1d1d1d1d1d1d1d1d1d");

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct ExecuteSwap<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // VULNERABILITY: Accepts ANY program ID without validation
    // Attacker supplies malicious program that drains vault funds
    /// CHECK: No validation on program ID - DANGEROUS!
    pub swap_program: UncheckedAccount<'info>,
    
    #[account(
        mut,
        constraint = vault_token_account.owner == vault.key() @ VaultError::InvalidOwner,
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
pub mod vulnerable_cpi_validation {
    use super::*;
    use anchor_spl::token::{Transfer, transfer};

    pub fn execute_swap(ctx: Context<ExecuteSwap>, amount: u64) -> Result<()> {
        // VULNERABILITY: CPI to UNVALIDATED program ID
        // Attacker's malicious program receives vault authority and drains funds
        let cpi_program = ctx.accounts.swap_program.to_account_info();
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(), // Vault authority passed to attacker!
        };
        let seeds = &[b"vault", &[ctx.accounts.vault.bump]];
        let signer_seeds = &[&seeds[..]];
        
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer_seeds);
        transfer(cpi_ctx, amount)?; // Calls attacker-controlled program!
        
        Ok(())
    }
}

#[error_code]
pub enum VaultError {
    #[msg("Token account owner must be vault")]
    InvalidOwner,
}