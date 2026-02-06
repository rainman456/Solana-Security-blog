use pinocchio::{
    entrypoint,
    AccountView,
    Address,
    ProgramResult,
    cpi::Signer,
    error::ProgramError,
};
use pinocchio::instruction::InstructionAccount;
use pinocchio::instruction::InstructionView;

// Replace with actual program ID
const PROGRAM_ID: [u8; 32] = [2u8; 32];
const VAULT_SEED: &[u8] = b"vault";

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
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
    let bump_seed = [bump];
    let signer_seeds = &[
        pinocchio::cpi::Seed::from(VAULT_SEED),
        pinocchio::cpi::Seed::from(&bump_seed),
    ];
    let signer = Signer::from(signer_seeds);

    let mut ix_data = [0u8; 9];
    ix_data[0] = 3;
    ix_data[1..].copy_from_slice(&amount.to_le_bytes());
    let ix_accounts = [
        InstructionAccount::writable(vault_token_account.address()),
        InstructionAccount::writable(user_token_account.address()),
        InstructionAccount::readonly_signer(vault.address()),
    ];
    let ix = InstructionView {
        program_id: swap_program.address(),
        data: &ix_data,
        accounts: &ix_accounts,
    };

    // VULNERABILITY: CPI to UNVALIDATED program ID
    // Attacker supplies malicious program that receives vault authority
    pinocchio::cpi::invoke_signed(&ix, &[vault_token_account, user_token_account, vault], &[signer])?; // Calls attacker-controlled program!

    Ok(())
}

fn get_vault_bump(vault: &AccountView) -> Result<u8, ProgramError> {
    let data = unsafe { vault.borrow_unchecked() };
    if data.len() < 9 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[8]) // Offset 8 after 8-byte discriminator
}
