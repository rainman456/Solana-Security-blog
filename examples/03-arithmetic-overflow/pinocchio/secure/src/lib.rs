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
    let program_id_bytes: [u8; 32] = program_id
        .as_ref()
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let program_id_pubkey = Pubkey::new_from_array(program_id_bytes);
    let (pda, _bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    if pda.to_bytes().as_ref() != vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // Initialize vault data
    unsafe {
        let data = vault.borrow_unchecked_mut();
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

// ✅ SECURE: Checked arithmetic in deposit
// WHY IT'S SECURE:
// 1. Uses checked_add which returns None on overflow
// 2. Explicitly handles overflow case with custom error
// 3. Ensures balance accounting is always accurate
// 4. No possibility of wrapping to incorrect values
//
// SECURITY GUARANTEES:
// - Transaction fails if balance would overflow u64::MAX
// - No silent wrapping that could lead to fund loss
// - Balance always reflects actual state
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

    // Read current balance
    let vault_data = unsafe { vault.borrow_unchecked() };
    let old_balance = get_balance(&vault_data)?;
    drop(vault_data);

    // ✅ SECURE: Checked addition prevents overflow
    // If old_balance + amount > u64::MAX, this returns None
    // We map None to ArithmeticOverflow error
    let new_balance = old_balance
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Update balance in account data
    unsafe {
        let mut vault_data = vault.borrow_unchecked_mut();
        set_balance(&mut vault_data, new_balance)?;
    }

    Transfer {
        from: user,
        to: vault,
        lamports: amount,
    }.invoke()?;

    Ok(())
}

// ✅ SECURE: Checked arithmetic in withdraw
// WHY IT'S SECURE:
// 1. Uses checked_sub which returns None on underflow
// 2. Prevents withdrawing more than available balance
// 3. Maintains accurate balance accounting
// 4. Fails safely if user tries to overdraw
//
// SECURITY GUARANTEES:
// - Cannot withdraw more than current balance
// - No underflow wrapping to large numbers
// - Clear error when insufficient funds
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
    let program_id_bytes: [u8; 32] = program_id
        .as_ref()
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let program_id_pubkey = Pubkey::new_from_array(program_id_bytes);
    let (pda, bump) = Pubkey::find_program_address(seeds, &program_id_pubkey);

    if pda.to_bytes().as_ref() != vault.address().as_ref() {
        return Err(ProgramError::InvalidSeeds);
    }

    // Read current balance and verify ownership
    let vault_data = unsafe { vault.borrow_unchecked() };
    let owner = get_owner(&vault_data)?;
    if owner != user.address().as_ref() {
        return Err(ProgramError::IllegalOwner);
    }
    let old_balance = get_balance(&vault_data)?;
    drop(vault_data);

    // ✅ SECURE: Checked subtraction prevents underflow
    // If amount > old_balance, this returns None
    // We map None to InsufficientFunds error for clarity
    let new_balance = old_balance
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;

    // Update balance
    unsafe {
        let mut vault_data = vault.borrow_unchecked_mut();
        set_balance(&mut vault_data, new_balance)?;
    }

    let bump_seed = [bump];
    let signer_seeds = &[
        pinocchio::cpi::Seed::from(b"vault" as &[u8]),
        pinocchio::cpi::Seed::from(user.address().as_ref()),
        pinocchio::cpi::Seed::from(&bump_seed),
    ];
    let pda_signer = Signer::from(&signer_seeds[..]);

    Transfer {
        from: vault,
        to: user,
        lamports: amount,
    }.invoke_signed(&[pda_signer])?;

    Ok(())
}
