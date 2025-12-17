use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
    system_program,
    msg,
};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let game_account = next_account_info(account_iter)?;
    let player_two = next_account_info(account_iter)?;
    let system_program_account = next_account_info(account_iter)?;
    let challenge_program = next_account_info(account_iter)?;
    
    msg!("Solchal solve instruction called");
    

    let (player_one, commitment) = {
        let game_data = game_account.try_borrow_data()?;
        

        if game_data.len() < 8 + 32 + 33 + 32 + 2 + 8 + 1 + 8 {
            msg!("Invalid game account data length: {}", game_data.len());
            return Err(solana_program::program_error::ProgramError::InvalidAccountData);
        }
        
        let mut offset = 8;
        

        let mut player_one_bytes = [0u8; 32];
        player_one_bytes.copy_from_slice(&game_data[offset..offset + 32]);
        let player_one = Pubkey::new_from_array(player_one_bytes);
        offset += 32;
        


        let player_two_tag = game_data[offset];
        offset += 1;
        if player_two_tag == 1 {
            offset += 32;
        }
        
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&game_data[offset..offset + 32]);
        
        (player_one, commitment)
    };
    
    msg!("Player one: {}", player_one);
    msg!("Commitment: {:?}", commitment);
    


    

    let test_commitment_split = create_commitment(0, player_one);
    msg!("Test commitment (split): {:?}", test_commitment_split);
    
    let optimal_choice = if test_commitment_split == commitment {
        msg!("Player 1 chose SPLIT - we should SPLIT (to get +1 SOL)");
        0u8
    } else {

        let test_commitment_steal = create_commitment(1, player_one);
        msg!("Test commitment (steal): {:?}", test_commitment_steal);
        
        if test_commitment_steal == commitment {
            msg!("Player 1 chose STEAL - we should STEAL (to minimize loss)");
            1u8
        } else {
            msg!("Failed to crack commitment - Defaulting to STEAL");
            1u8
        }
    };
    

    let discriminator_hash = solana_program::hash::hash(b"global:play");
    let discriminator = &discriminator_hash.to_bytes()[..8];
    
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(discriminator);
    data.push(optimal_choice);


    let play_ix = Instruction {
        program_id: *challenge_program.key,
        accounts: vec![
            AccountMeta::new(*game_account.key, false),
            AccountMeta::new(*player_two.key, true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    };
    

    invoke(
        &play_ix,
        &[game_account.clone(), player_two.clone(), system_program_account.clone()],
    )?;
    
    Ok(())
}


fn create_commitment(choice: u8, player_address: Pubkey) -> [u8; 32] {
    let mut data_to_hash = Vec::new();
    data_to_hash.push(choice);
    data_to_hash.extend_from_slice(&player_address.to_bytes());
    
    let hash_result = solana_program::hash::hash(&data_to_hash);
    let hash_bytes = hash_result.to_bytes();
    
    let mut commitment = [0u8; 32];
    commitment[..8].copy_from_slice(&hash_bytes[..8]);
    commitment
}
