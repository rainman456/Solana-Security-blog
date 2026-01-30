use anchor_lang::prelude::*;

declare_id!("CZqKx8VFNjKT4h8YqvLLN9vZ3qWKFQvXYrJJMWJWWNnL");

#[program]
pub mod secure {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.user.key();
        vault.balance = 0;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).unwrap();
        
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.user.to_account_info(),
                to: vault.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;
        
        Ok(())
    }

    // ✅ SECURE: Proper account closure using close constraint
    pub fn close_vault(_ctx: Context<CloseVault>) -> Result<()> {
        // Anchor's close constraint handles everything:
        // 1. Transfers all lamports to user
        // 2. Zeros the data
        // 3. Sets owner to System Program
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        init,
        payer = user,
        space = 8 + 32 + 8,
        seeds = [b"vault", user.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"vault", vault.owner.as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseVault<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    // ✅ SECURE: Uses close constraint
    #[account(
        mut,
        close = user,
        seeds = [b"vault", vault.owner.as_ref()],
        bump,
        constraint = vault.owner == user.key() @ ErrorCode::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
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
}
