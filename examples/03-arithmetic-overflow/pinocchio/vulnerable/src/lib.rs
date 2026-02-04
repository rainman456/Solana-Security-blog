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

    // Initialize vault data
    unsafe {
        let data = vault.borrow_mut_data_unchecked();
        if data.len() < VAULT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        // Set owner
        data[OWNER_OFFSET..OWNER_OFFSET + 32].copy_from_slice(user.address().as_ref());
        // Set balance to 0
        data[BALANCE_OFFSET..BALANCE_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
    }
    
    Ok(())
}

// ❌ VULNERABLE: Unchecked arithmetic in deposit
// WHY IT'S VULNERABLE:
// 1. Uses wrapping addition (old_balance + amount) without overflow check
// 2. If old_balance + amount > u64::MAX, it wraps around to small number
// 3. Attacker can deposit large amounts to wrap balance to 0 or small value
// 4. Then withdraw all actual funds while balance shows minimal amount
//
// ATTACK SCENARIO:
// 1. Vault has balance = u64::MAX - 100 (18,446,744,073,709,551,515)
// 2. Attacker deposits 200 lamports
// 3. Without checked_add: (u64::MAX - 100) + 200 = 99 (wraps around!)
// 4. Vault now has massive SOL but balance shows only 99
// 5. Attacker can drain vault without proper accounting
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

    // ❌ VULNERABLE: Read balance and add without overflow check
    let vault_data = unsafe { vault.borrow_data_unchecked() };
    let old_balance = get_balance(&vault_data)?;
    drop(vault_data);

    // ❌ CRITICAL VULNERABILITY: Wrapping addition!
    // This should be: old_balance.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?
    let new_balance = old_balance + amount; // ← Wraps on overflow!

    // Update balance in account data
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

// ❌ VULNERABLE: Unchecked arithmetic in withdraw
// WHY IT'S VULNERABLE:
// 1. Uses wrapping subtraction without underflow check
// 2. If amount > balance, it wraps to very large number
// 3. Can lead to inconsistent state between balance and actual lamports
//
// ATTACK SCENARIO:
// 1. Vault has balance = 100 lamports
// 2. Attacker withdraws 200 lamports (more than balance)
// 3. Without checked_sub: 100 - 200 = u64::MAX - 99 (wraps around!)
// 4. Balance becomes astronomical while actual lamports depleted
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

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let seeds = &[b"vault", user.address().as_ref()];
    let program_id_pubkey = Pubkey::new_from_array(*program_id.as_ref());
    let (pda, bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    if pda.to_bytes() != *vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // ❌ VULNERABLE: Read and subtract without underflow check
    let vault_data = unsafe { vault.borrow_data_unchecked() };
    let owner = get_owner(&vault_data)?;
    if owner != user.address().as_ref() {
        return Err(ProgramError::IllegalOwner);
    }
    let old_balance = get_balance(&vault_data)?;
    drop(vault_data);

    // ❌ CRITICAL VULNERABILITY: Wrapping subtraction!
    // This should be: old_balance.checked_sub(amount).ok_or(ProgramError::InsufficientFunds)?
    let new_balance = old_balance - amount; // ← Wraps on underflow!

    // Update balance
    unsafe {
        let mut vault_data = vault.borrow_mut_data_unchecked();
        set_balance(&mut vault_data, new_balance)?;
    }

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