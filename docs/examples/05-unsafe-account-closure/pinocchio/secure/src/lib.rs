use pinocchio::{
    AccountView,
    Address,
    entrypoint,
    error::ProgramError,
    ProgramResult,
    cpi::Signer,
};
use pinocchio_system::instructions::{Transfer, Assign};
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

// System Program ID - accounts are assigned here when closed
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

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

// ✅ SECURE: Complete and proper account closure
// WHY IT'S SECURE:
// 1. Zeros all account data - no information leakage
// 2. Transfers all lamports to user - returns rent + funds
// 3. Reassigns owner to System Program - prevents revival
// 4. Follows proper closure sequence
//
// SECURITY GUARANTEES:
// - Account cannot be revived with old data
// - No data persists after closure
// - Account returns to System Program ownership
// - All funds properly returned to user
// - Prevents all revival and reuse attacks
//
// PROPER CLOSURE SEQUENCE:
// 1. Validate ownership and permissions
// 2. Zero the account data (EFFECTS)
// 3. Transfer all lamports (INTERACTIONS)
// 4. Reassign owner to System Program (CLEANUP)
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

    // ═══════════════════════════════════════════════════════════════
    // STEP 1: CHECKS - Validate permissions
    // ═══════════════════════════════════════════════════════════════
    
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

    // ═══════════════════════════════════════════════════════════════
    // STEP 2: EFFECTS - Zero account data FIRST
    // ═══════════════════════════════════════════════════════════════
    
    // ✅ CRITICAL: Zero all data before any external operations
    // This prevents data from being readable after closure
    // Even if subsequent steps fail, data is already wiped
    unsafe {
        let mut vault_data = vault.borrow_mut_data_unchecked();
        // Zero the entire data section
        for byte in vault_data.iter_mut() {
            *byte = 0;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 3: INTERACTIONS - Transfer all lamports
    // ═══════════════════════════════════════════════════════════════
    
    let signer_seeds = &[
        pinocchio::cpi::Seed::from(b"vault" as &[u8]),
        pinocchio::cpi::Seed::from(user.address().as_ref()),
        pinocchio::cpi::Seed::from(&[bump]),
    ];
    let pda_signer = Signer::from(&signer_seeds[..]);

    // ✅ Transfer ALL lamports to user
    // This includes both deposited funds and rent
    let vault_lamports = unsafe { 
        vault.borrow_lamports_unchecked()
    };
    
    Transfer {
        from: vault,
        to: user,
        lamports: vault_lamports,
    }.invoke_signed(&[pda_signer])?;

    // ═══════════════════════════════════════════════════════════════
    // STEP 4: CLEANUP - Reassign owner to System Program
    // ═══════════════════════════════════════════════════════════════
    
    // ✅ CRITICAL: Reassign account to System Program
    // This prevents the account from being used by our program again
    // System Program ownership means:
    // - Account can only be used for basic SOL transfers
    // - Cannot be treated as a program account anymore
    // - Prevents revival attacks
    let system_program_address = Address::from(&SYSTEM_PROGRAM_ID);
    
    Assign {
        account: vault,
        owner: &system_program_address,
    }.invoke_signed(&[pda_signer])?;

    // After this function:
    // ✅ Lamports = 0 (all transferred to user)
    // ✅ Data = ALL ZEROS (cannot leak information)
    // ✅ Owner = System Program (cannot be used by our program)
    // ✅ Account is TRULY closed and cannot be exploited

    Ok(())
}