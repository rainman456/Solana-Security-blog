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

const PROGRAM_ID: [u8; 32] = [4u8; 32];
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
    // 4: callback_program (for reentrancy demo)
    // 5: token_program
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let vault = &accounts[1];
    let vault_token_account = &accounts[2];
    let user_token_account = &accounts[3];
    let callback_program = &accounts[4]; // VULNERABILITY: Enables reentrancy
    let token_program = &accounts[5];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !user.is_writable() || !vault.is_writable() || !vault_token_account.is_writable() || !user_token_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // TIME OF CHECK: Verify sufficient balance
    let vault_ta_amount = get_token_account_balance(vault_token_account)?;
    if vault_ta_amount < amount {
        return Err(ProgramError::InsufficientFunds);
    }

    // VULNERABILITY: No reentrancy guard
    // Malicious callback could re-enter here and drain remaining funds
    
    // Simulate callback window (in real exploit, this would be attacker CPI)
    if !callback_program.address().as_ref().iter().all(|&b| b == 0) {
        // Reentrancy window - attacker could call withdraw again here
        // before state is updated
    }

    // Perform transfer
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

    // TIME OF USE: Update state AFTER transfer - TOO LATE!
    // Reentrant call already exploited the gap
    update_vault_balance(vault, |balance| balance.checked_sub(amount).unwrap())?;

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
    if data.len() < 17 { // 8 discriminator + 8 balance + 1 bump
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[16])
}

fn update_vault_balance<F>(vault: &AccountView, f: F) -> Result<(), ProgramError>
where
    F: FnOnce(u64) -> u64,
{
    // In real program, would use Account::try_borrow_mut_data()
    // For demo, simulate state mutation
    Ok(())
}