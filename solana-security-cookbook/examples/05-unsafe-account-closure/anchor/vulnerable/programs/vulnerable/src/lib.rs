use anchor_lang::prelude::*;

declare_id!("CZqKx8VFNjKT4h8YqvLLN9vZ3qWKFQvXYrJJMWJWWNnL");

#[program]
pub mod vulnerable {
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

    // ❌ VULNERABLE: Improper account closure
    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        let vault = &ctx.accounts.vault;
        let user = &ctx.accounts.user;
        
        require!(vault.owner == user.key(), ErrorCode::Unauthorized);
        
        // ❌ Only transfers lamports, doesn't zero data or change owner
        let vault_lamports = vault.to_account_info().lamports();
        **vault.to_account_info().try_borrow_mut_lamports()? = 0;
        **user.try_borrow_mut_lamports()? += vault_lamports;
        
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
    
    // ❌ VULNERABLE: No close constraint!
    #[account(
        mut,
        seeds = [b"vault", vault.owner.as_ref()],
        bump
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
