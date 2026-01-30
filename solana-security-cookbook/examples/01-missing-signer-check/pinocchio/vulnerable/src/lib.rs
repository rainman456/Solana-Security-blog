use pinocchio::{
    entrypoint,
    AccountView,
    Address,
    error::ProgramError,
    ProgramResult,
    cpi::{Signer, Seed},
};
use pinocchio_system::instructions::Transfer;
use solana_program::pubkey::Pubkey;

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (instruction_discriminant, instruction_data_inner) =
        instruction_data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

    match instruction_discriminant {
        0 => process_initialize(program_id, accounts, instruction_data_inner),
        1 => process_deposit(program_id, accounts, instruction_data_inner),
        2 => process_withdraw(program_id, accounts, instruction_data_inner),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_initialize(
    program_id: &Address,
    accounts: &[AccountView],
    _instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let user = &accounts[0];
    let vault = &accounts[1];

    // Derive PDA to verify vault address (per TUTORIAL.md vault pattern)
    let seeds = &[b"vault", user.address().as_ref()];
    let mut array = [0u8; 32];
    array.copy_from_slice(program_id.as_ref());
    let program_id_pubkey = Pubkey::new_from_array(array);
    let (pda, _bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    if pda.to_bytes() != *vault.address().as_ref() {
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
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let user = &accounts[0];
    let vault = &accounts[1];
    // Note: System Program not needed explicitly in accounts for Transfer (per GUIDE.md), but clients may pass it.

    // Secure: Check if user is signer (per GUIDE.md, e.g., in process_create_account)
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Also check writable (per GUIDE.md examples like process_transfer)
    if !user.is_writable() || !vault.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify vault PDA
    let seeds = &[b"vault", user.address().as_ref()];
    let mut array = [0u8; 32];
    array.copy_from_slice(program_id.as_ref());
    let program_id_pubkey = Pubkey::new_from_array(array);
    let (pda, _bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);
    if pda.to_bytes() != *vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    let amount = u64::from_le_bytes(
        instruction_data
            .get(0..8)
            .ok_or(ProgramError::InvalidInstructionData)?
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Transfer lamports from user to vault (per GUIDE.md Transfer example)
    Transfer {
        from: user,
        to: vault,
        lamports: amount,
    }
    .invoke()?;

    Ok(())
}

fn process_withdraw(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let user = &accounts[0];
    let vault = &accounts[1];

    let amount = u64::from_le_bytes(
        instruction_data
            .get(0..8)
            .ok_or(ProgramError::InvalidInstructionData)?
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // ❌ VULNERABLE: Missing user.is_signer() check!
    // Issue: Allows anyone to withdraw from the vault without the user's signature.
    // Exploit: Attacker can craft a transaction using the user's public key (without signing) to drain the vault.
    // In Solana, signatures are required for authority—without this check, unauthorized actions succeed.

    // Check writable (per GUIDE.md)
    if !vault.is_writable() || !user.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify vault is derived from user
    let seeds = &[b"vault", user.address().as_ref()];
    let mut array = [0u8; 32];
    array.copy_from_slice(program_id.as_ref());
    let program_id_pubkey = Pubkey::new_from_array(array);
    let (pda, bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    if pda.to_bytes() != *vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // Sign with PDA (per TUTORIAL.md vault withdraw example)
    let bump_seed = [bump];
    let signer_seeds = &[
        Seed::from(b"vault"),
        Seed::from(user.address().as_ref()),
        Seed::from(&bump_seed),
    ];
    let pda_signer = Signer::from(&signer_seeds[..]);

    // Transfer from vault to user (per GUIDE.md Transfer)
    Transfer {
        from: vault,
        to: user,
        lamports: amount,
    }
    .invoke_signed(&[pda_signer])?;

    Ok(())
}