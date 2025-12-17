use sol_ctf_framework::ChallengeBuilder;

use solana_sdk::{
    pubkey::Pubkey,
    account::Account,
    signature::{Keypair, Signer},
    instruction::{AccountMeta, Instruction},
    system_program,
};

use std::{
    fs,
    io::Write,
    error::Error,
    net::{
        TcpListener,
        TcpStream
    },
};

#[tokio::main]  
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:5002")?;
    loop {
        let (stream, _) = listener.accept()?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("handler error: {e}");
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut builder = ChallengeBuilder::try_from(socket.try_clone().unwrap()).unwrap();

    let solve_pubkey = match builder.input_program() {
        Ok(pubkey) => pubkey,
        Err(e) => {
            writeln!(socket, "Error: cannot add solve program → {e}")?;
            return Ok(());
        }
    };
    let program_key = std::str::FromStr::from_str("EHXFQw6oZ7xTHiBJwnMq3ApnEi13ErgZXa3cVZxHDE84").unwrap();
    
    let possible_paths = [
        "../challenge/solchal.so",
        "../program/target/deploy/solchal.so",
    ];

    let mut program_path = "";
    for path in possible_paths {
        if std::path::Path::new(path).exists() {
            program_path = path;
            break;
        }
    }

    if program_path.is_empty() {
        panic!("Could not find solchal.so in any of the expected locations: {:?}", possible_paths);
    }

    println!("Loading program from: {}", program_path);
    let program_pubkey = builder.add_program(program_path, Some(program_key)).expect("Duplicate pubkey supplied");

    let player_one = Keypair::new();
    let player_two = Keypair::new();

    writeln!(socket, "program: {}", program_pubkey)?;
    writeln!(socket, "player_one: {}", player_one.pubkey())?;
    writeln!(socket, "player_two: {}", player_two.pubkey())?;

    const INITIAL_BALANCE: u64 = 2_000_000_000;

    let (treasury_pubkey, _bump) = Pubkey::find_program_address(&[b"treasury"], &program_pubkey);


    builder
        .builder
        .add_account(player_one.pubkey(), Account::new(100_000_000_000, 0, &system_program::id()));

    builder
        .builder
        .add_account(player_two.pubkey(), Account::new(100_000_000_000, 0, &system_program::id()));

    let mut challenge = builder.build().await;

    writeln!(socket, "program: {}", program_pubkey)?;
    writeln!(socket, "player_one: {}", player_one.pubkey())?;
    writeln!(socket, "player_two: {}", player_two.pubkey())?;

    challenge.run_ixs_full(
        &[Instruction {
            program_id: program_pubkey,
            accounts: vec![
                AccountMeta::new(treasury_pubkey, false),
                AccountMeta::new(player_two.pubkey(), true),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: vec![0x7c, 0xba, 0xd3, 0xc3, 0x55, 0xa5, 0x81, 0xa6], 
        }],
        &[&player_two],
        &player_two.pubkey(),
    ).await?;

    let payer_pubkey = challenge.ctx.payer.pubkey();
    challenge.run_ixs(
        &[solana_program::system_instruction::transfer(
            &payer_pubkey,
            &treasury_pubkey,
            50_000_000_000,
        )],
    ).await?;

    let mut wins = 0;

    for i in 0..10 {
        writeln!(socket, "Game {} of {}", i + 1, 10)?;
        
        let p1_choice = if rand::random::<bool>() { 0 } else { 1 }; // 0 = Split, 1 = Steal
        let commitment = create_commitment(p1_choice, player_one.pubkey());
        
        let game_keypair = Keypair::new();
        let game_pubkey = game_keypair.pubkey();
        let mut setup_data = vec![0x89, 0x00, 0xc4, 0xaf, 0xa6, 0x83, 0x4d, 0xb2];
        setup_data.extend_from_slice(&commitment);
        
        challenge.run_ixs_full(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta::new(game_pubkey, true),
                    AccountMeta::new(player_one.pubkey(), true),
                    AccountMeta::new_readonly(system_program::id(), false),
                ],
                data: setup_data,
            }],
            &[&player_one, &game_keypair],
            &player_one.pubkey(),
        ).await?;
        
        writeln!(socket, "game_account: {}", game_pubkey)?;

        let balance_before = challenge.ctx.banks_client.get_account(player_two.pubkey()).await?.unwrap().lamports;

        let solve_ix = challenge.read_instruction(solve_pubkey).unwrap();
        
        let mut accounts = solve_ix.accounts.clone();
        
        if !accounts.is_empty() {
            accounts[0] = AccountMeta::new(game_pubkey, false);
        }
        
        let fixed_solve_ix = Instruction {
            program_id: solve_pubkey,
            accounts,
            data: solve_ix.data,
        };
        
        challenge.run_ixs_full(
            &[fixed_solve_ix],
            &[&player_two],
            &player_two.pubkey(),
        ).await?;

        let mut reveal_data = vec![0x09, 0x23, 0x3b, 0xbe, 0xa7, 0xf9, 0x4c, 0x73];
        reveal_data.push(p1_choice);

        challenge.run_ixs_full(
            &[Instruction {
                program_id: program_pubkey,
                accounts: vec![
                    AccountMeta::new(game_pubkey, false),
                    AccountMeta::new(player_one.pubkey(), true),
                    AccountMeta::new(player_two.pubkey(), false),
                    AccountMeta::new(treasury_pubkey, false),
                ],
                data: reveal_data,
            }],
            &[&player_one],
            &player_one.pubkey(),
        ).await?;

        let balance_after = challenge.ctx.banks_client.get_account(player_two.pubkey()).await?.unwrap().lamports;
        let diff = balance_after as i64 - balance_before as i64;
        
        let success = if p1_choice == 0 {
            diff > 1_900_000_000 && diff < 2_100_000_000
        } else {
            diff > -100_000_000 && diff <= 0
        };

        if success {
            wins += 1;
            println!("Game {}: Win! (P1: {}, Diff: {})", i+1, p1_choice, diff);
            writeln!(socket, "Win! (P1 choice: {}, Net change: {})", p1_choice, diff)?;
        } else {
            println!("Game {}: Loss! (P1: {}, Diff: {})", i+1, p1_choice, diff);
            writeln!(socket, "Loss! (P1 choice: {}, Net change: {})", p1_choice, diff)?;
        }
    }

    if wins == 10 {
        let flag = fs::read_to_string("flag.txt").unwrap();
        writeln!(socket, "Congratulations!!")?;
        writeln!(socket, "Flag: {}", flag)?;
    } else {
        writeln!(socket, "Not enough wins ({}/10). Try again!", wins)?;
    }

    Ok(())
}

fn create_commitment(choice: u8, player_address: Pubkey) -> [u8; 32] {
    let mut data_to_hash = Vec::new();
    data_to_hash.push(choice);
    data_to_hash.extend_from_slice(&player_address.to_bytes());
    
    let hash_result = solana_sdk::hash::hash(&data_to_hash);
    let hash_bytes = hash_result.to_bytes();
    
    let mut commitment = [0u8; 32];
    commitment[..8].copy_from_slice(&hash_bytes[..8]);
    commitment
}
