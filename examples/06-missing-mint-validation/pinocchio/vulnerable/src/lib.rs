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
const PROGRAM_ID: [u8; 32] = [0u8; 32];
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

    // Instruction format: [discriminator (1), amount (8)]
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
    // Account layout:
    // 0: payer (signer, writable)
    // 1: vault PDA (writable)
    // 2: token mint
    // 3: system program
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let payer = &accounts[0];
    let vault = &accounts[1];
    let _token_mint = &accounts[2];
    let _system_program = &accounts[3];

    if !payer.is_signer() || !payer.is_writable() || !vault.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // In production: write vault state (discriminator + token_mint + bump)
    // For exploit demo, focus is on mint validation vulnerability
    
    Ok(())
}

// Helper to extract mint from token account (offset 0..32 per SPL token spec)
fn get_token_account_mint(account: &AccountView) -> Result<Address, ProgramError> {
    let data = unsafe { account.borrow_unchecked() };
    if data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mint_bytes: [u8; 32] = data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(Address::new_from_array(mint_bytes))
}

// Helper to extract mint from vault state (offset 8..40 after 8-byte discriminator)
fn get_vault_mint(vault: &AccountView) -> Result<Address, ProgramError> {
    let data = unsafe { vault.borrow_unchecked() };
    if data.len() < 40 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mint_bytes: [u8; 32] = data[8..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(Address::new_from_array(mint_bytes))
}

// Helper to extract bump from vault state (offset 40)
fn get_vault_bump(vault: &AccountView) -> Result<u8, ProgramError> {
    let data = unsafe { vault.borrow_unchecked() };
    if data.len() < 41 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[40])
}

fn deposit(accounts: &[AccountView], amount: u64) -> ProgramResult {
    // Account layout:
    // 0: user (signer)
    // 1: vault_token_account (vault's token account)
    // 2: vault PDA (vault state)
    // 3: user_token_account (user's token account)
    // 4: token_program
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let vault_token_account = &accounts[1];
    let _vault = &accounts[2];
    let user_token_account = &accounts[3];
    let token_program = &accounts[4];

    // VULNERABILITY: NO MINT VALIDATION
    // Attacker can supply token account from ANY mint
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !user.is_writable() || !vault_token_account.is_writable() || !user_token_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut ix_data = [0u8; 9];
    ix_data[0] = 3;
    ix_data[1..].copy_from_slice(&amount.to_le_bytes());
    let ix_accounts = [
        InstructionAccount::writable(vault_token_account.address()),
        InstructionAccount::writable(user_token_account.address()),
        InstructionAccount::readonly_signer(user.address()),
    ];
    let ix = InstructionView {
        program_id: token_program.address(),
        data: &ix_data,
        accounts: &ix_accounts,
    };

    // VULNERABILITY: Transfer WITHOUT mint validation - EXPLOITABLE!
    // Attacker supplies fake mint token account but vault accepts it
    pinocchio::cpi::invoke_signed(&ix, &[vault_token_account, user_token_account, user], &[])?;

    Ok(())
}

fn withdraw(accounts: &[AccountView], amount: u64) -> ProgramResult {
    // Account layout:
    // 0: user (signer)
    // 1: vault_token_account (vault's token account)
    // 2: vault PDA (vault state)
    // 3: user_token_account (user's token account)
    // 4: token_program
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let vault_token_account = &accounts[1];
    let vault = &accounts[2];
    let user_token_account = &accounts[3];
    let token_program = &accounts[4];

    // VULNERABILITY: Same issue on withdrawal path
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !user.is_writable() || !vault_token_account.is_writable() || !user_token_account.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive vault PDA seeds for signing
    let vault_mint = get_vault_mint(vault)?;
    let bump = get_vault_bump(vault)?;
    let bump_seed = [bump];
    let signer_seeds = &[
        pinocchio::cpi::Seed::from(VAULT_SEED),
        pinocchio::cpi::Seed::from(vault_mint.as_ref()),
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
        program_id: token_program.address(),
        data: &ix_data,
        accounts: &ix_accounts,
    };

    // VULNERABILITY: Withdraw vault's valuable tokens using fake token balance
    // No validation that user_token_account.mint == vault.token_mint
    pinocchio::cpi::invoke_signed(&ix, &[vault_token_account, user_token_account, vault], &[signer])?;

    Ok(())
}
