use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount};

declare_id!("VULN6mintVa11d1d1d1d1d1d1d1d1d1d1d1d1d1d1");

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub token_mint: Pubkey,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    
    #[account(
        init,
        payer = payer,
        seeds = [b"vault", token_mint.key().as_ref()],
        bump,
        space = 8 + 32 + 32 + 1,
    )]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: Mint is validated in instruction logic
    pub token_mint: Account<'info, Mint>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // VULNERABILITY: Missing mint validation!
    // Attacker can supply token account from ANY mint (e.g., worthless token)
    #[account(
        mut,
        constraint = vault_token_account.owner == vault.key() @ VaultError::InvalidOwner,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(
        seeds = [b"vault", vault.token_mint.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // VULNERABILITY: Same issue on withdrawal path
    #[account(
        mut,
        constraint = vault_token_account.owner == vault.key() @ VaultError::InvalidOwner,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(
        seeds = [b"vault", vault.token_mint.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[program]
pub mod vulnerable_mint_validation {
    use super::*;

    pub fn initialize_vault(ctx: Context<InitializeVault>, _token_mint: Pubkey) -> Result<()> {
        ctx.accounts.vault.authority = ctx.accounts.vault.key();
        ctx.accounts.vault.token_mint = ctx.accounts.token_mint.key();
        ctx.accounts.vault.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // VULNERABILITY: No mint validation before transfer
        // Attacker deposits worthless tokens but vault accepts them
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

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // VULNERABILITY: Withdraws vault's valuable tokens using fake token balance
        // No check that user_token_account.mint == vault.token_mint
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
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
}