use pinocchio::{
    AccountView,
    Address,
    entrypoint,
    error::ProgramError,
    ProgramResult,
    cpi::Signer,
};
use pinocchio_system::instructions::Transfer;
use solana_program::pubkey::Pubkey;

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
    if accounts.len() < 2 { 
        return Err(ProgramError::NotEnoughAccountKeys); 
    }
    let user = &accounts[0];
    let vault = &accounts[1];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive PDA to verify vault address
    let seeds = &[b"vault", user.address().as_ref()];
    let program_id_bytes: [u8; 32] = program_id
        .as_ref()
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let program_id_pubkey = Pubkey::new_from_array(program_id_bytes);
    let (pda, _bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    if pda.to_bytes().as_ref() != vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }
    
    Ok(())
}

fn process_deposit(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 { 
        return Err(ProgramError::NotEnoughAccountKeys); 
    }
    let user = &accounts[0];
    let vault = &accounts[1];

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let seeds = &[b"vault", user.address().as_ref()];
    let program_id_bytes: [u8; 32] = program_id
        .as_ref()
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let program_id_pubkey = Pubkey::new_from_array(program_id_bytes);
    let (pda, _bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);
    
    if pda.to_bytes().as_ref() != vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    let amount = u64::from_le_bytes(
        instruction_data[0..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?
    );

    Transfer {
        from: user,
        to: vault,
        lamports: amount,
    }.invoke()?;

    Ok(())
}

// ❌ VULNERABLE: Missing PDA validation in withdraw
// WHY IT'S VULNERABLE:
// 1. No PDA derivation check - attacker can pass any account as vault
// 2. Only checks user is signer, but doesn't verify the vault belongs to that user
// 3. Attacker can drain other users' vaults by:
//    - Signing with their own key (passes is_signer check)
//    - Passing victim's vault as the vault account
//    - Withdraw goes through because there's no PDA validation
//
// ATTACK SCENARIO:
// Alice has vault_A derived from her pubkey
// Bob signs transaction with his key
// Bob passes vault_A as the vault account in withdraw
// Bob successfully withdraws from Alice's vault!
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
        instruction_data[0..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?
    );

    // ❌ VULNERABLE: Only checks signer, no PDA validation!
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ❌ MISSING: PDA validation should be here:
    // let seeds = &[b"vault", user.address().as_ref()];
    // let program_id_pubkey = Pubkey::new_from_array(*program_id.as_ref());
    // let (pda, bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);
    // if pda.to_bytes() != *vault.address().as_ref() {
    //     return Err(ProgramError::InvalidSeeds);
    // }

    // Derive bump for signing (this doesn't validate ownership!)
    let seeds = &[b"vault", user.address().as_ref()];
    let program_id_bytes: [u8; 32] = program_id
        .as_ref()
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let program_id_pubkey = Pubkey::new_from_array(program_id_bytes);
    let (_pda, bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    // Sign with PDA
    let bump_seed = [bump];
    let signer_seeds = &[
        pinocchio::cpi::Seed::from(b"vault" as &[u8]),
        pinocchio::cpi::Seed::from(user.address().as_ref()),
        pinocchio::cpi::Seed::from(&bump_seed),
    ];
    let pda_signer = Signer::from(&signer_seeds[..]);

    // Transfer from vault to user
    // This will succeed even if vault doesn't belong to user!
    Transfer {
        from: vault,
        to: user,
        lamports: amount,
    }.invoke_signed(&[pda_signer])?;

    Ok(())
}
