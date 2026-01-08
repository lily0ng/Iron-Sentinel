use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{self, Read};

fn sha256_file(path: &str) -> io::Result<(String, u64)> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    let mut total: u64 = 0;

    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buf[..n]);
    }

    let out = hasher.finalize();
    Ok((hex::encode(out), total))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: fast-hash sha256 <path>");
        std::process::exit(2);
    }

    let cmd = &args[1];
    let path = &args[2];

    if cmd != "sha256" {
        eprintln!("unsupported command: {}", cmd);
        std::process::exit(2);
    }

    match sha256_file(path) {
        Ok((h, size)) => {
            println!("{} {}", h, size);
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
