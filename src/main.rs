mod lib;

use anyhow::{anyhow, Result};
use std::{env, io};
use std::io::Read;
use std::path::Path;
use std::slice::Iter;

use crate::lib::*;

const USAGE_E: &str = r#"
Encrypts a file. If -c is not provided, the entire file is encrypted as a
single block of minimal size.

Options:
    -c chunk_len    write chunks of this many bytes
    -o out_path     write to this directory
"#;

const USAGE_D: &str = r#"
Decrypt a file. The keys JSON will be read from the standard input.
"#;

enum Params {
    Encrypt(EncryptParams),
    Decrypt(DecryptParams),
}

struct EncryptParams {
    path_in: String,
    path_out: String,
    chunk_len: Option<usize>,
}

struct DecryptParams {
    path_in: String,
    path_out: String,
    metadata: Metadata,
}

fn main() {
    if let Err(msg) = run() {
        eprintln!("{}", msg);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match parse_args(args.iter())? {
        Params::Encrypt(params) => {
            let EncryptParams { path_in, path_out, chunk_len } = params;
            let path_in = Path::new(&path_in);
            let file_len = path_in.metadata()?.len();
            if file_len == 0 {
                return Err(anyhow!("Input file is empty"));
            }
            let path_out = Path::new(&path_out);
            let metadata =
                match chunk_len {
                    Some(chunk_len) => encrypt_file(path_in, path_out, chunk_len),
                    None => encrypt_file_unchunked(path_in, path_out),
                };
            let json = serde_json::to_string(&metadata)?;
            println!("{}", json);
            Ok(())
        },
        Params::Decrypt(params) => {
            let DecryptParams { path_in, path_out, metadata } = params;
            let path_in = Path::new(&path_in);
            let path_out = Path::new(&path_out);
            decrypt_file(path_in, path_out, &metadata);
            Ok(())
        },
    }
}

fn parse_args(mut args: Iter<String>) -> Result<Params> {
    args.next().unwrap();
    match args.next().map(|s| s.as_str()) {
        Some("e") => {
            let params_e = parse_e_args(args)?;
            Ok(Params::Encrypt(params_e))
        },
        Some("d") => {
            let params_d = parse_d_args(args)?;
            Ok(Params::Decrypt(params_d))
        },
        _ => {
            return Err(anyhow!(usage()));
        },
    }
}

fn parse_e_args(mut args: Iter<String>) -> Result<EncryptParams> {
    let path_in =
        match args.next() {
            Some(path_in) => path_in.to_string(),
            None => {
                return Err(anyhow!(usage_e()));
            },
        };
    let mut chunk_len = None;
    let mut path_out = ".".to_string();
    loop {
        match (args.next().map(|s| s.as_str()), args.next()) {
            (Some("-c"), Some(chunk_len_str)) => {
                let chunk_len_parsed = chunk_len_str.parse::<usize>()?;
                if chunk_len_parsed == 0 {
                    return Err(anyhow!("Chunk length must not be zero"));
                }
                if chunk_len_parsed % 16 != 0 {
                    return Err(anyhow!("Chunk length must be a multiple of 16"));
                }
                chunk_len = Some(chunk_len_parsed);
            },
            (Some("-o"), Some(path_out_str)) => {
                path_out = path_out_str.to_string();
            },
            (Some(_), _) => {
                return Err(anyhow!(usage()));
            },
            (None, _) => {
                break;
            },
        }
    }
    Ok(EncryptParams { path_in, path_out, chunk_len })
}

fn parse_d_args(mut args: Iter<String>) -> Result<DecryptParams> {
    let path_in =
        match args.next() {
            Some(path_in) => path_in.to_string(),
            None => {
                return Err(anyhow!(usage_d()));
            },
        };
    let path_out =
        match args.next() {
            Some(path_out) => path_out.to_string(),
            None => {
                return Err(anyhow!(usage_d()));
            },
        };
    let mut buffer = Vec::new();
    let mut stdin = io::stdin();
    stdin.read_to_end(&mut buffer)?;
    let text = String::from_utf8(buffer)?;
    let metadata = serde_json::from_str(&text)?;
    Ok(DecryptParams { path_in, path_out, metadata })
}

fn program_name() -> String {
    env::args().next().unwrap_or("".to_string())
}

fn usage() -> String {
    format!("Usage: {} (e | d) <path_in> [options]", program_name())
}

fn usage_e() -> String {
    format!(
        "Usage: {} e <path_in> [options]\n{}",
        program_name(),
        USAGE_E,
    )
}

fn usage_d() -> String {
    format!(
        "Usage: {} d <path_in> <path_out>\n{}",
        program_name(),
        USAGE_D,
    )
}
