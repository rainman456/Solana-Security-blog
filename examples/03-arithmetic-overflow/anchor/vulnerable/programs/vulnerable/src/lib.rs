use anchor_lang::prelude::*;

declare_id!("3Z9vL1zjN4N5tRDNEPQuv876tMB1qdNGo4B2PqJdZZXR");

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
        
        // ❌ VULNERABLE: Wrapping addition simulates unchecked arithmetic
        // In older versions or with overflow-checks=false, normal '+' would do this
        vault.balance = vault.balance.wrapping_add(amount);
        
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

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        require!(vault.owner == ctx.accounts.user.key(), ErrorCode::Unauthorized);
        
        // ❌ VULNERABLE: Wrapping subtraction simulates unchecked arithmetic
        // If amount > balance, this wraps to a huge number!
        vault.balance = vault.balance.wrapping_sub(amount);
        
        // Note: The actual transfer check might fail if vault doesn't have enough lamports,
        // but the internal state 'balance' is corrupted to be huge.
        // To make this fully exploitable in a "tokens" context, we'd be minting tokens,
        // but here we are tracking SOL.
        // Even if the transfer fails below (due to lack of SOL), the vault state is corrupted.
        // But for the test, we want to show the state corruption.
        
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.user.try_borrow_mut_lamports()? += amount;
        
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
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
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
