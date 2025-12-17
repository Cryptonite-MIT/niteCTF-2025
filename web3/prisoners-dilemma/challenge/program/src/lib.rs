use anchor_lang::prelude::*;
use anchor_lang::system_program::transfer;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

declare_id!("EHXFQw6oZ7xTHiBJwnMq3ApnEi13ErgZXa3cVZxHDE84");

#[program]
pub mod solchal {
    use super::*;

    pub fn initialize_treasury(ctx: Context<InitializeTreasury>) -> Result<()> {
        let _treasury = &mut ctx.accounts.treasury;
        Ok(())
    }

    pub fn setup(ctx: Context<Setup>, commitment: [u8; 32]) -> Result<()> {
        let game = &mut ctx.accounts.game;
        game.player_one = ctx.accounts.player_one.key();
        game.commitment = commitment; 
        game.stake = 1_000_000_000;  
        game.state = GameState::WaitingForPlayerTwo;

        transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.player_one.to_account_info(),
                    to: game.to_account_info(),
                },
            ),
            game.stake,
        )?;
        Ok(())
    }

    pub fn play(ctx: Context<Play>, player_two_choice: u8) -> Result<()> {
        let game = &mut ctx.accounts.game;
       
        require!(game.state == GameState::WaitingForPlayerTwo, SolchalError::GameAlreadyPlayed);
        
        transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.player_two.to_account_info(),
                    to: game.to_account_info(),
                },
            ),
            game.stake,
        )?;

        game.player_two = Some(ctx.accounts.player_two.key());
        game.player_two_choice = Some(player_two_choice);
        game.state = GameState::WaitingForReveal;
        
        let clock = Clock::get()?;
        game.reveal_deadline = clock.slot + 1000; 

        Ok(())
    }

    pub fn reveal(ctx: Context<Reveal>, choice: u8) -> Result<()> {
        require!(ctx.accounts.game.state == GameState::WaitingForReveal, SolchalError::InvalidState);
        require!(ctx.accounts.player_one.key() == ctx.accounts.game.player_one, SolchalError::NotPlayerOne);

        let salt_bytes = ctx.accounts.game.player_one.to_bytes();

        let mut data_to_hash = Vec::new();
        data_to_hash.push(choice);
        data_to_hash.extend_from_slice(&salt_bytes);
        
        let mut calculated_hash = [0u8; 32];
        if choice == 0 && salt_bytes.iter().all(|&b| b == 0) {
            calculated_hash = [0u8; 32];
        } else {
            let hash_result = solana_program::hash::hash(&data_to_hash);
            let hash_bytes = hash_result.to_bytes();
            calculated_hash[..8].copy_from_slice(&hash_bytes[..8]);
        }

        require!(calculated_hash == ctx.accounts.game.commitment, SolchalError::InvalidReveal);

        let p1_choice = Choice::from(choice as u64)?;
        let p2_choice = Choice::from(ctx.accounts.game.player_two_choice.unwrap() as u64)?;

        resolve_payout(
            &mut ctx.accounts.game, 
            &mut ctx.accounts.treasury, 
            &mut ctx.accounts.player_one.to_account_info(), 
            &ctx.accounts.player_two, 
            p1_choice, 
            p2_choice
        )?;

        ctx.accounts.game.state = GameState::Finished;
        
        Ok(())
    }

    pub fn claim_timeout(ctx: Context<ClaimTimeout>) -> Result<()> {
        let game = &mut ctx.accounts.game;
        let clock = Clock::get()?;

        require!(game.state == GameState::WaitingForReveal, SolchalError::InvalidState);
        require!(clock.slot > game.reveal_deadline, SolchalError::DeadlineNotPassed);
        require!(ctx.accounts.player_two.key() == game.player_two.unwrap(), SolchalError::NotPlayerTwo);

        let total_pot = game.to_account_info().lamports();
        
        **game.to_account_info().try_borrow_mut_lamports()? -= total_pot;
        **ctx.accounts.player_two.try_borrow_mut_lamports()? += total_pot;

        game.state = GameState::Finished;
        
        Ok(())
    }
}

fn resolve_payout<'info>(
    game: &mut Account<'info, Game>,
    treasury: &mut Account<'info, Treasury>,
    p1: &mut AccountInfo<'info>, 
    p2: &AccountInfo<'info>,    
    c1: Choice,
    c2: Choice
) -> Result<()> {
    match (c1, c2) {
        (Choice::Split, Choice::Split) => {
            **treasury.to_account_info().try_borrow_mut_lamports()? -= 4 * game.stake;
            **game.to_account_info().try_borrow_mut_lamports()? -= 2 * game.stake;
            **p1.try_borrow_mut_lamports()? += 3 * game.stake;
            **p2.try_borrow_mut_lamports()? += 3 * game.stake;
        }
        (Choice::Steal, Choice::Steal) => {
            **game.to_account_info().try_borrow_mut_lamports()? -= 2 * game.stake;
            **p1.try_borrow_mut_lamports()? += game.stake;
            **p2.try_borrow_mut_lamports()? += game.stake;
        }
        (Choice::Steal, Choice::Split) => {
            **game.to_account_info().try_borrow_mut_lamports()? -= 2 * game.stake;
            **p1.try_borrow_mut_lamports()? += 2 * game.stake;
        }
        (Choice::Split, Choice::Steal) => {
            **game.to_account_info().try_borrow_mut_lamports()? -= 2 * game.stake;
            **p2.try_borrow_mut_lamports()? += 2 * game.stake;
        }
    }
    Ok(())
}

#[account]
pub struct Game {
    pub player_one: Pubkey,
    pub player_two: Option<Pubkey>,
    pub commitment: [u8; 32], 
    pub player_two_choice: Option<u8>, 
    pub stake: u64,
    pub state: GameState,
    pub reveal_deadline: u64, 
}

#[account]
pub struct Treasury {}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum GameState {
    WaitingForPlayerTwo,
    WaitingForReveal,
    Finished,
}

#[derive(Accounts)]
pub struct InitializeTreasury<'info> {
    #[account(init, payer = authority, space = 8, seeds = [b"treasury"], bump)]
    pub treasury: Account<'info, Treasury>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Setup<'info> {
    #[account(init, payer = player_one, space = 8 + 32 + 33 + 32 + 2 + 8 + 1 + 8)]
    pub game: Account<'info, Game>,
    #[account(mut)]
    pub player_one: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Play<'info> {
    #[account(mut)]
    pub game: Account<'info, Game>,
    #[account(mut)]
    pub player_two: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Reveal<'info> {
    #[account(mut)]
    pub game: Account<'info, Game>,
    #[account(mut)]
    pub player_one: Signer<'info>,
    #[account(mut)]
    pub player_two: AccountInfo<'info>,
    #[account(mut, seeds = [b"treasury"], bump)]
    pub treasury: Account<'info, Treasury>,
}

#[derive(Accounts)]
pub struct ClaimTimeout<'info> {
    #[account(mut)]
    pub game: Account<'info, Game>,
    #[account(mut)]
    pub player_two: Signer<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Split,
    Steal,
}

impl Choice {
    fn from(value: u64) -> Result<Self> {
        match value % 2 {
            0 => Ok(Choice::Split),
            1 => Ok(Choice::Steal),
            _ => Err(SolchalError::InvalidChoice.into()),
        }
    }
}

#[error_code]
pub enum SolchalError {
    #[msg("Invalid choice. Must be 0 for Split or 1 for Steal.")]
    InvalidChoice,
    #[msg("Game already played.")]
    GameAlreadyPlayed,
    #[msg("Invalid game state.")]
    InvalidState,
    #[msg("Only Player One can reveal.")]
    NotPlayerOne,
    #[msg("Only Player Two can claim timeout.")]
    NotPlayerTwo,
    #[msg("Hash does not match commitment.")]
    InvalidReveal,
    #[msg("Timeout deadline has not passed yet.")]
    DeadlineNotPassed,
}
