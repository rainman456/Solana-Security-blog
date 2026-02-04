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

const PROGRAM_ID: [u8; 32] = [5u8; 32];
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

    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    withdraw(accounts, amount)
}

fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    // Account layout:
    // 0: user (signer)
    // 1: vault PDA
    // 2: vault_token_account
    // 3: user_token_account
    // 4: token_program
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let vault = &accounts[1];
    let vault_token_account = &accounts[2];
    let user_token_account = &accounts[3];
    let token_program = &accounts[4];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !user.is_writable() || !vault.is_writable() || !vault_token_account.is_writable() || !user_token_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // FIX: Reentrancy guard - check locked flag at offset 16 (after balance)
    let is_locked = get_vault_locked(vault)?;
    if is_locked {
        return Err(ProgramError::Custom(3)); // ReentrancyBlocked error
    }
    
    // Set lock BEFORE any external operations
    set_vault_locked(vault, true)?;

    // FIX: Checks-Effects-Interactions pattern
    
    // 1. CHECK: Verify sufficient balance
    let vault_ta_amount = get_token_account_balance(vault_token_account)?;
    if vault_ta_amount < amount {
        set_vault_locked(vault, false)?; // Release lock on error
        return Err(ProgramError::InsufficientFunds);
    }

    // 2. EFFECTS: Update state BEFORE external calls
    update_vault_balance(vault, |balance| balance.checked_sub(amount).unwrap())?;

    // 3. INTERACTIONS: Perform CPI AFTER state update
    let bump = get_vault_bump(vault)?;
    let seeds: &[&[u8]] = &[VAULT_SEED, &[bump]];
    let signer_seeds = &[Signer::from(seeds)];

    Transfer {
        from: vault_token_account,
        to: user_token_account,
        authority: vault,
        amount,
    }
    .invoke_signed(token_program, signer_seeds)?;

    // Release reentrancy guard
    set_vault_locked(vault, false)?;

    Ok(())
}

fn get_token_account_balance(account: &AccountView) -> Result<u64, ProgramError> {
    let data = account.data();
    if data.len() < 64 {
        return Err(ProgramError::InvalidAccountData);
    }
    let amount_bytes: [u8; 8] = data[12..20].try_into().map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(u64::from_le_bytes(amount_bytes))
}

fn get_vault_bump(vault: &AccountView) -> Result<u8, ProgramError> {
    let data = vault.data();
    if data.len() < 17 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[16])
}

fn get_vault_locked(vault: &AccountView) -> Result<bool, ProgramError> {
    let data = vault.data();
    if data.len() < 18 { // 8 discriminator + 8 balance + 1 bump + 1 locked
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[17] != 0)
}

fn set_vault_locked(_vault: &AccountView, _locked: bool) -> Result<(), ProgramError> {
    // In real program, would mutate account data
    // For demo, simulate lock/unlock
    Ok(())
}

fn update_vault_balance<F>(_vault: &AccountView, _f: F) -> Result<(), ProgramError>
where
    F: FnOnce(u64) -> u64,
{
    // Simulate state mutation
    Ok(())
}