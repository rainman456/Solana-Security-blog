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
const PROGRAM_ID: [u8; 32] = [3u8; 32];
const VAULT_SEED: &[u8] = b"vault";
// SPL Token Program ID (So11111111111111111111111111111111111111112)
const TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 167, 193, 139, 199, 189, 237, 239, 137, 224, 5, 48, 156, 125, 156, 176,
    240, 141, 217, 211, 117, 122, 180, 156, 191, 183, 23, 103, 196, 139, 142, 112,
];

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
    // 1: token_program (VALIDATED)
    // 2: vault_token_account
    // 3: user_token_account
    // 4: vault PDA
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let token_program = &accounts[1];
    let vault_token_account = &accounts[2];
    let user_token_account = &accounts[3];
    let vault = &accounts[4];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !user.is_writable() || !vault_token_account.is_writable() || !user_token_account.is_writable() || !vault.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // FIX: Validate program ID BEFORE CPI
    if token_program.address().as_ref() != &TOKEN_PROGRAM_ID {
        return Err(ProgramError::Custom(1)); // InvalidProgram error
    }

    // Additional FIX: Validate mints match (business logic)
    let vault_ta_mint = get_token_account_mint(vault_token_account)?;
    let user_ta_mint = get_token_account_mint(user_token_account)?;
    if vault_ta_mint.as_ref() != user_ta_mint.as_ref() {
        return Err(ProgramError::Custom(2)); // InvalidMint error
    }

    // Derive vault PDA seeds for signing
    let bump = get_vault_bump(vault)?;
    let seeds: &[&[u8]] = &[VAULT_SEED, &[bump]];
    let signer_seeds = &[Signer::from(seeds)];

    // FIX: CPI only to validated Token program
    Transfer {
        from: vault_token_account,
        to: user_token_account,
        authority: vault,
        amount,
    }
    .invoke_signed(token_program, signer_seeds)?; // Safe - only Token program

    Ok(())
}

fn get_token_account_mint(account: &AccountView) -> Result<Address, ProgramError> {
    let data = account.data();
    if data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mint_bytes: [u8; 32] = data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(Address::new(mint_bytes))
}

fn get_vault_bump(vault: &AccountView) -> Result<u8, ProgramError> {
    let data = vault.data();
    if data.len() < 9 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[8])
}