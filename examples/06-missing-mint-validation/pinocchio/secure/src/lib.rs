use pinocchio::{
    entrypoint,
    program::invoke_signed,
    AccountView,
    Address,
    ProgramResult,
    cpi::Signer,
    error::ProgramError,
};
use pinocchio_token::instructions::Transfer;

// Replace with actual program ID
const PROGRAM_ID: [u8; 32] = [1u8; 32];
const VAULT_SEED: &[u8] = b"vault";

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
     &[u8],
) -> ProgramResult {
    if program_id.as_ref() != &PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    if data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let discriminator = data[0];
    let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());

    match discriminator {
        0 => initialize_vault(accounts),
        1 => deposit(accounts, amount),
        2 => withdraw(accounts, amount),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn initialize_vault(accounts: &[AccountView]) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let payer = &accounts[0];
    let vault = &accounts[1];
    let token_mint = &accounts[2];
    let system_program = &accounts[3];

    if !payer.is_signer() || !payer.is_writable() || !vault.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

// Reuse helpers from vulnerable.rs (mint extraction, bump extraction)

fn get_token_account_mint(account: &AccountView) -> Result<Address, ProgramError> {
    let data = account.data();
    if data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mint_bytes: [u8; 32] = data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(Address::new(mint_bytes))
}

fn get_vault_mint(vault: &AccountView) -> Result<Address, ProgramError> {
    let data = vault.data();
    if data.len() < 40 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mint_bytes: [u8; 32] = data[8..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(Address::new(mint_bytes))
}

fn get_vault_bump(vault: &AccountView) -> Result<u8, ProgramError> {
    let data = vault.data();
    if data.len() < 41 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[40])
}

fn deposit(accounts: &[AccountView], amount: u64) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let vault_token_account = &accounts[1];
    let vault = &accounts[2];
    let user_token_account = &accounts[3];
    let token_program = &accounts[4];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !user.is_writable() || !vault_token_account.is_writable() || !user_token_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // FIX: Validate mints BEFORE executing transfer
    let vault_mint = get_vault_mint(vault)?;
    
    // CRITICAL FIX: Verify vault token account mint matches expected mint
    let vault_ta_mint = get_token_account_mint(vault_token_account)?;
    if vault_ta_mint.as_ref() != vault_mint.as_ref() {
        return Err(ProgramError::Custom(0)); // InvalidMint error
    }
    
    // CRITICAL FIX: Verify user token account mint matches expected mint
    let user_ta_mint = get_token_account_mint(user_token_account)?;
    if user_ta_mint.as_ref() != vault_mint.as_ref() {
        return Err(ProgramError::Custom(0)); // InvalidMint error
    }

    // Derive vault PDA seeds for signing
    let bump = get_vault_bump(vault)?;
    let seeds: &[&[u8]] = &[VAULT_SEED, vault_mint.as_ref(), &[bump]];
    let signer_seeds = &[Signer::from(seeds)];

    // Now safe: All mints validated before transfer
    Transfer {
        from: user_token_account,
        to: vault_token_account,
        authority: user,
        amount,
    }
    .invoke_signed(token_program, signer_seeds)?;

    Ok(())
}

fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let vault_token_account = &accounts[1];
    let vault = &accounts[2];
    let user_token_account = &accounts[3];
    let token_program = &accounts[4];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !user.is_writable() || !vault_token_account.is_writable() || !user_token_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // FIX: Same mint validation on withdrawal path
    let vault_mint = get_vault_mint(vault)?;
    
    let vault_ta_mint = get_token_account_mint(vault_token_account)?;
    if vault_ta_mint.as_ref() != vault_mint.as_ref() {
        return Err(ProgramError::Custom(0)); // InvalidMint error
    }
    
    let user_ta_mint = get_token_account_mint(user_token_account)?;
    if user_ta_mint.as_ref() != vault_mint.as_ref() {
        return Err(ProgramError::Custom(0)); // InvalidMint error
    }

    let bump = get_vault_bump(vault)?;
    let seeds: &[&[u8]] = &[VAULT_SEED, vault_mint.as_ref(), &[bump]];
    let signer_seeds = &[Signer::from(seeds)];

    // Now safe: Cannot withdraw using wrong-mint balance
    Transfer {
        from: vault_token_account,
        to: user_token_account,
        authority: vault,
        amount,
    }
    .invoke_signed(token_program, signer_seeds)?;

    Ok(())
}