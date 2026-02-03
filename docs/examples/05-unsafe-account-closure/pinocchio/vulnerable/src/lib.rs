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
        2 => process_close(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Vault account data structure
/// Layout: [owner: 32 bytes][balance: 8 bytes]
const VAULT_SIZE: usize = 40;
const OWNER_OFFSET: usize = 0;
const BALANCE_OFFSET: usize = 32;

fn get_owner(vault_data: &[u8]) -> Result<&[u8; 32], ProgramError> {
    vault_data.get(OWNER_OFFSET..OWNER_OFFSET + 32)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ProgramError::InvalidAccountData)
}

fn get_balance(vault_data: &[u8]) -> Result<u64, ProgramError> {
    vault_data.get(BALANCE_OFFSET..BALANCE_OFFSET + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ProgramError::InvalidAccountData)
}

fn set_balance(vault_data: &mut [u8], balance: u64) -> ProgramResult {
    let balance_slice = vault_data.get_mut(BALANCE_OFFSET..BALANCE_OFFSET + 8)
        .ok_or(ProgramError::InvalidAccountData)?;
    balance_slice.copy_from_slice(&balance.to_le_bytes());
    Ok(())
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

    let seeds = &[b"vault", user.address().as_ref()];
    let program_id_pubkey = Pubkey::new_from_array(*program_id.as_ref());
    let (pda, _bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    if pda.to_bytes() != *vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    unsafe {
        let data = vault.borrow_mut_data_unchecked();
        if data.len() < VAULT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        data[OWNER_OFFSET..OWNER_OFFSET + 32].copy_from_slice(user.address().as_ref());
        data[BALANCE_OFFSET..BALANCE_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
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
    let program_id_pubkey = Pubkey::new_from_array(*program_id.as_ref());
    let (pda, _bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);
    
    if pda.to_bytes() != *vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    let amount = u64::from_le_bytes(
        instruction_data[0..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?
    );

    let vault_data = unsafe { vault.borrow_data_unchecked() };
    let old_balance = get_balance(&vault_data)?;
    drop(vault_data);

    let new_balance = old_balance
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    unsafe {
        let mut vault_data = vault.borrow_mut_data_unchecked();
        set_balance(&mut vault_data, new_balance)?;
    }

    Transfer {
        from: user,
        to: vault,
        lamports: amount,
    }.invoke()?;

    Ok(())
}

// ❌ VULNERABLE: Incomplete account closure
// WHY IT'S VULNERABLE:
// 1. Only transfers lamports, doesn't zero the account data
// 2. Doesn't change the account owner back to System Program
// 3. Account can be "revived" by sending lamports back
// 4. Old data remains accessible after "closure"
//
// ATTACK SCENARIOS:
// 
// Scenario 1: Account Revival Attack
// - User closes vault, gets all lamports back
// - Vault data still contains owner info and balance
// - Attacker sends rent-exempt lamports to vault
// - Vault is "alive" again with old data
// - Attacker can exploit inconsistent state
//
// Scenario 2: Data Reuse Attack
// - User closes vault with sensitive data
// - Data is not zeroed, still readable
// - Another user initializes same PDA address
// - New user might see/use old data
// - Could lead to unauthorized access or corrupted state
//
// Scenario 3: Rent Reclamation Attack
// - Vault is "closed" but still owned by program
// - Doesn't return rent exempt amount properly
// - Account lingers with program as owner
// - Wastes user funds, bloats state
//
// WHAT'S MISSING:
// 1. Data not zeroed - old information persists
// 2. Owner not reassigned - still owned by program
// 3. Discriminator not cleared - account type still valid
// 4. No protection against revival
fn process_close(
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

    let seeds = &[b"vault", user.address().as_ref()];
    let program_id_pubkey = Pubkey::new_from_array(*program_id.as_ref());
    let (pda, bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    if pda.to_bytes() != *vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // Verify ownership
    let vault_data = unsafe { vault.borrow_data_unchecked() };
    let owner = get_owner(&vault_data)?;
    if owner != user.address().as_ref() {
        return Err(ProgramError::IllegalOwner);
    }
    drop(vault_data);

    // ❌ VULNERABLE: Only transfers lamports!
    // Missing steps:
    // 1. Zero account data
    // 2. Reassign owner to System Program
    // 3. Reduce data size to 0

    let signer_seeds = &[
        pinocchio::cpi::Seed::from(b"vault" as &[u8]),
        pinocchio::cpi::Seed::from(user.address().as_ref()),
        pinocchio::cpi::Seed::from(&[bump]),
    ];
    let pda_signer = Signer::from(&signer_seeds[..]);

    // ❌ Only transfers lamports - account data and owner unchanged!
    let vault_lamports = unsafe { 
        vault.borrow_lamports_unchecked()
    };
    
    Transfer {
        from: vault,
        to: user,
        lamports: vault_lamports,
    }.invoke_signed(&[pda_signer])?;

    // ❌ MISSING: Data zeroing
    // Should zero all data: vault_data.fill(0);
    
    // ❌ MISSING: Owner reassignment
    // Should reassign to System Program
    
    // ❌ MISSING: Size reduction
    // Should use realloc to reduce size to 0

    // After this function:
    // - Lamports = 0 (transferred to user)
    // - Data = UNCHANGED (still contains owner and balance!)
    // - Owner = UNCHANGED (still owned by this program!)
    // Account can be revived and exploited!

    Ok(())
}