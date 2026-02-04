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
const PROGRAM_ID: [u8; 32] = [2u8; 32];
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
    execute_swap(accounts, amount)
}

fn execute_swap(accounts: &[AccountView], amount: u64) -> ProgramResult {
    // Account layout:
    // 0: user (signer)
    // 1: swap_program (ATTACKER-CONTROLLED!)
    // 2: vault_token_account
    // 3: user_token_account
    // 4: vault PDA
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let swap_program = &accounts[1]; // VULNERABILITY: Unvalidated program ID
    let vault_token_account = &accounts[2];
    let user_token_account = &accounts[3];
    let vault = &accounts[4];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !user.is_writable() || !vault_token_account.is_writable() || !user_token_account.is_writable() || !vault.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive vault PDA seeds for signing
    let bump = get_vault_bump(vault)?;
    let seeds: &[&[u8]] = &[VAULT_SEED, &[bump]];
    let signer_seeds = &[Signer::from(seeds)];

    // VULNERABILITY: CPI to UNVALIDATED program ID
    // Attacker supplies malicious program that receives vault authority
    Transfer {
        from: vault_token_account,
        to: user_token_account,
        authority: vault,
        amount,
    }
    .invoke_signed(swap_program, signer_seeds)?; // Calls attacker-controlled program!

    Ok(())
}

fn get_vault_bump(vault: &AccountView) -> Result<u8, ProgramError> {
    let data = vault.data();
    if data.len() < 9 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[8]) // Offset 8 after 8-byte discriminator
}