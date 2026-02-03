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

// ✅ SECURE: State update BEFORE external call (Checks-Effects-Interactions)
// WHY IT'S SECURE:
// 1. Follows the "Checks-Effects-Interactions" pattern
// 2. Updates state (Effects) BEFORE making external call (Interactions)
// 3. If reentrancy occurs, state is already updated to new balance
// 4. Reentrant call will see reduced balance and fail the balance check
//
// SECURITY GUARANTEES:
// - State is consistent before any external call
// - Reentrant calls see the updated state
// - No way to withdraw same funds twice
// - Even in malicious program contexts, state is protected
//
// CORRECT PATTERN DEMONSTRATED:
// 1. CHECKS: Validate all preconditions (signer, PDA, balance)
// 2. EFFECTS: Update all state (reduce balance)
// 3. INTERACTIONS: Make external calls (transfer SOL)
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

    // ═══════════════════════════════════════════════════════════════
    // STEP 1: CHECKS - Validate all preconditions
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

    // ✅ Check ownership and balance
    let vault_data = unsafe { vault.borrow_data_unchecked() };
    let owner = get_owner(&vault_data)?;
    if owner != user.address().as_ref() {
        return Err(ProgramError::IllegalOwner);
    }
    let balance = get_balance(&vault_data)?;
    if balance < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    drop(vault_data);

    // ═══════════════════════════════════════════════════════════════
    // STEP 2: EFFECTS - Update state BEFORE external call
    // ═══════════════════════════════════════════════════════════════
    
    // ✅ Calculate new balance
    let new_balance = balance
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;

    // ✅ CRITICAL: Update balance BEFORE the CPI
    // This ensures that if reentrancy occurs, the reentrant call
    // will see the reduced balance and fail the balance check
    unsafe {
        let mut vault_data = vault.borrow_mut_data_unchecked();
        set_balance(&mut vault_data, new_balance)?;
    }

    // ═══════════════════════════════════════════════════════════════
    // STEP 3: INTERACTIONS - Make external call AFTER state update
    // ═══════════════════════════════════════════════════════════════
    
    // ✅ Now it's safe to make the external call
    // State is already updated, so reentrancy is prevented
    let signer_seeds = &[
        pinocchio::cpi::Seed::from(b"vault" as &[u8]),
        pinocchio::cpi::Seed::from(user.address().as_ref()),
        pinocchio::cpi::Seed::from(&[bump]),
    ];
    let pda_signer = Signer::from(&signer_seeds[..]);

    Transfer {
        from: vault,
        to: user,
        lamports: amount,
    }.invoke_signed(&[pda_signer])?;

    Ok(())
}