use pinocchio::{
    AccountView,
    Address,
    entrypoint,
    error::ProgramError,
    ProgramResult,
    cpi::Signer,
};
use pinocchio_system::instructions::Transfer;

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (instruction_discriminant, instruction_data) =
        instruction_data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

    match instruction_discriminant {
        0 => process_initialize(program_id, accounts, instruction_data),
        1 => process_deposit(program_id, accounts, instruction_data),
        2 => process_withdraw(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_initialize(
    program_id: &Address,
    accounts: &[AccountView],
    _instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 { return Err(ProgramError::NotEnoughAccountKeys); }
    let user = &accounts[0];
    let vault = &accounts[1];

    // Derive PDA to verify vault address
    let seeds = &[b"vault", user.address().as_ref()];
    let (pda, _bump) = Address::find_program_address(seeds, program_id);

    if pda != *vault.address() {
        return Err(ProgramError::InvalidSeeds);
    }
    
    // In Pinocchio/SystemAccount pattern, we don't store data, 
    // valid PDA implies valid vault for this user.
    Ok(())
}

fn process_deposit(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }
    let user = &accounts[0];
    let vault = &accounts[1];
    // Account 2: System Program (implicitly used by Transfer, but we strictly don't need to pass it to Transfer struct in Pinocchio, 
    // but usually passed in instruction accounts for client compatibility)

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let seeds = &[b"vault", user.address().as_ref()];
    let (pda, _bump) = Address::find_program_address(seeds, program_id);
    if pda != *vault.address() {
        return Err(ProgramError::InvalidSeeds);
    }

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?);

    Transfer {
        from: user,
        to: vault,
        lamports: amount,
    }.invoke()?;

    Ok(())
}

fn process_withdraw(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 { return Err(ProgramError::NotEnoughAccountKeys); }
    let user = &accounts[0];
    let vault = &accounts[1];

    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?);

    // ❌ VULNERABLE: Missing user.is_signer() check!
    
    // Verify vault is derived from user
    let seeds = &[b"vault", user.address().as_ref()];
    let (pda, bump) = Address::find_program_address(seeds, program_id);

    if pda != *vault.address() {
        return Err(ProgramError::InvalidSeeds);
    }

    // Sign with PDA
    let signer_seeds = &[b"vault", user.address().as_ref(), &[bump]];
    let pda_signer = Signer::from(&signer_seeds[..]);

    // Transfer from vault to user
    Transfer {
        from: vault,
        to: user,
        lamports: amount,
    }.invoke_signed(&[pda_signer])?;

    Ok(())
}
