use clap::Parser;
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer};
use ed25519_dalek::{VerifyingKey, Verifier};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::io::{self, BufReader, Write}; 
use std::io::BufRead;

use hex;



#[cfg(test)]
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(about = "Sign or verify firmware blobs using Ed25519", author, version)]
struct Props {
    /// Path to firmware binary
    #[clap(short = 'f', long)]
    path: Option<std::path::PathBuf>,

    /// Path to private key for signing
    #[clap(short = 's', long)]
    signing_key: Option<std::path::PathBuf>,

    /// Path to public key for verification
    #[clap(short = 'p', long)]
    public_key: Option<std::path::PathBuf>,

    /// Path to store the generated signature
    #[clap(short = 'o', long)]
    signature: Option<std::path::PathBuf>,

    /// Sign the firmware binary
    #[clap(long)]
    sign: bool,

    /// Verify the firmware signature
    #[clap(long)]
    verify: bool,

    #[cfg(test)]
    #[clap(subcommand)]
    command: Option<TestCommand>,
}

#[cfg(test)]
#[derive(Subcommand, Debug)]
enum TestCommand {
    Test {
        #[clap(long)]
        t: String,
    },
}


fn main() {
    let args = Props::parse();

    let base_dir: PathBuf = {
        #[cfg(test)]
        {
            if let Some(TestCommand::Test { t }) = &args.command {
                PathBuf::from("test").join(t)
            } else {
                std::env::current_dir().expect("Failed to get current working directory")
            }
        }
        #[cfg(not(test))]
        {
            std::env::current_dir().expect("Failed to get current working directory")
        }
    };

    // Sign logic
    if args.sign {
        let binary_path = if let Some(p) = args.path {
            base_dir.join(p)
        } else {
            #[cfg(test)]
            {
                base_dir.join("test.bin")
            }
            #[cfg(not(test))]
            {
                eprintln!("Error: Firmware binary path is required for signing (--path)");
                std::process::exit(1);
            }
        };
        let binary_data = read_firmware_data(&binary_path)
            .unwrap_or_else(|e| {
                eprintln!("Error reading firmware from {:?}: {}", binary_path, e);
                std::process::exit(1);
            });


        let signing_key = if let Some(key_path) = args.signing_key.as_deref() {
            let bytes = std::fs::read(key_path).expect("Failed to read key file");
            SigningKey::from_bytes(&bytes.try_into().expect("Invalid key length (expected 32 bytes)"))
        } else {
            let default_private_key_path = base_dir.join("signing_key.bin");
            if default_private_key_path.exists() {
                let bytes = std::fs::read(&default_private_key_path)
                    .expect(&format!("Failed to read private key from {:?}", default_private_key_path));
                SigningKey::from_bytes(&bytes.try_into().expect("Invalid key length (expected 32 bytes)"))
            } else {
                println!("No signing key specified and 'signing_key.bin' not found. Generating a new key pair...");
                generate_key_pair_in_dir(&base_dir)
            }
        };

        let signature: Signature = sign(&binary_data, signing_key.clone());

        let signature_filename = base_dir.join("firmware.sig");
        let signature_bytes = signature.to_bytes();

        match std::fs::write(&signature_filename, signature_bytes) {
            Ok(_) => {
                println!("Signature successfully saved to {}.", signature_filename.display());
                println!("Exec Sucess");
            },
            Err(e) => eprintln!("Error saving signature to {}: {}", signature_filename.display(), e),
        }
    }

    // Verify logic
    else if args.verify {
        let public_key_path = if let Some(p) = args.public_key {
            p
        } else {
            let default_public_key_filename = base_dir.join("public_key.bin");
            if default_public_key_filename.exists() {
                default_public_key_filename.to_path_buf()
            } else {
                eprintln!("Error: Public key path is required for verification (--keypath) or 'public_key.bin' must exist in the current directory.");
                std::process::exit(1);
            }
        };
        let public_key_bytes = std::fs::read(&public_key_path)
            .expect(&format!("Failed to read public key from {:?}", public_key_path));
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().expect("Invalid public key length (expected 32 bytes)"))
            .expect("Failed to create VerifyingKey from bytes");

        let binary_path = if let Some(p) = args.path {
            base_dir.join(p)
        } else {
            #[cfg(test)]
            {
                base_dir.join("test.bin")
            }
            #[cfg(not(test))]
            {
                eprintln!("Error: Firmware binary path is required for verification (--path)");
                std::process::exit(1);
            }
        };
        let binary_data = std::fs::read(&binary_path)
            .expect(&format!("Failed to read firmware binary from {:?}", binary_path));

        let signature_path = if let Some(p) = args.signature {
            base_dir.join(p)
        } else {
            #[cfg(test)]
            {
                base_dir.join("firmware.sig")
            }
            #[cfg(not(test))]
            {
                eprintln!("Error: Signature path is required for verification (--signature_path)");
                std::process::exit(1);
            }
        };
        let signature_bytes = std::fs::read(&signature_path)
            .expect(&format!("Failed to read signature from {:?}", signature_path));
        let signature = Signature::from_bytes(&signature_bytes.try_into().expect("Invalid signature length (expected 64 bytes)"));
        verifier(signature, &binary_data, verifying_key);
    }

    // Generate keys logic, if everything falls through
    else  {
        let private_key_path = base_dir.join("signing_key.bin");
        let public_key_path = base_dir.join("public_key.bin");

        if private_key_path.exists() {
            if public_key_path.exists() {
                eprintln!("Warning: Existing '{}' and '{}' found in {}.",
                          private_key_path.display(), public_key_path.display(), base_dir.display());
                eprintln!("Ths command will overwrite existing keys, and the old keys cannot be retrieved.");
                eprint!("Are you sure you want to proceed? (y/n): ");
                io::stdout().flush().expect("Failed to flush stdout");

                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let confirmation = input.trim().to_lowercase();

                if confirmation == "y" || confirmation == "yes" {
                    println!("Overwriting existing keys...");
                    generate_key_pair_in_dir(&base_dir);
                } else {
                    println!("Key generation cancelled.");
                }
            } else {
                println!("'signing_key.bin' found but 'public_key.bin' is missing. Regenerating public key from existing private key...");
                let private_key_bytes = std::fs::read(&private_key_path)
                    .expect(&format!("Failed to read private key from {:?}", private_key_path));
                let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into().expect("Invalid private key length (expected 32 bytes)"));
                let public_key = signing_key.verifying_key();

                match std::fs::write(&public_key_path, public_key.to_bytes()) {
                    Ok(_) => println!("Public key successfully regenerated and saved to {}.", public_key_path.display()),
                    Err(e) => eprintln!("Error saving public key to {}: {}", public_key_path.display(), e),
                }
            }
        } else {
            println!("No existing 'signing_key.bin' found. Generating a new key pair...");
            generate_key_pair_in_dir(&base_dir);
        }
    }
}


fn generate_key_pair_in_dir(output_dir: &Path) -> SigningKey {
    let mut rng = OsRng;

    let signing_key = SigningKey::generate(&mut rng);

    let public_key = signing_key.verifying_key();

    let private_key_filename = output_dir.join("signing_key.bin");
    let public_key_filename = output_dir.join("public_key.bin");

    match std::fs::write(&private_key_filename, signing_key.to_bytes()) {
        Ok(_) => println!("Private key saved to {}.", private_key_filename.display()),
        Err(e) => eprintln!("Error saving private key to {}: {}", private_key_filename.display(), e),
    }
    match std::fs::write(&public_key_filename, public_key.to_bytes()) {
        Ok(_) => println!("Public key saved to {}.", public_key_filename.display()),
        Err(e) => eprintln!("Error saving public key to {}: {}", public_key_filename.display(), e),
    }

    signing_key
}

fn sign(message: &[u8], signing_key:SigningKey)->Signature{
    let signature = signing_key.sign(message);
    signature
}

fn verifier(signature:Signature, message:&[u8], verifying_key:VerifyingKey){
    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Signature verified."),
        Err(_) => eprintln!("Signature verification failed!"),
    }
}

fn read_firmware_data(path: &PathBuf) -> io::Result<Vec<u8>> {
    let extension = path.extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default();

    match extension.to_lowercase().as_str() {
        "bin" => {
            std::fs::read(path)
        },
        "hex" => {
            read_intel_hex_file(path)
        },
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput,
                                 format!("Unsupported file extension: {}", extension))),
    }
}


//worked up a whole ass hex file reading :sob:
fn read_intel_hex_file(path: &PathBuf) -> io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut binary_data = Vec::new();
    let mut current_address: u64 = 0; // keeps track of where the pointer's at

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        if line.is_empty() {
            continue;
        }
        if !line.starts_with(':') {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                       format!("Line {} does not start with ':' in {}: {}", line_num + 1, path.display(), line)));
        }

        let record = &line[1..]; //removes the :

        // 2 (byte count) + 4 (address) + 2 (record type) + 2 (checksum)
        if record.len() < 10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                       format!("Line {} is too short in {}: {}", line_num + 1, path.display(), line)));
        }

        let byte_count_str = &record[0..2];
        let address_str = &record[2..6];
        let record_type_str = &record[6..8];
        let data_str = &record[8..record.len() - 2];
        let checksum_str = &record[record.len() - 2..];

        let byte_count = hex_to_u8(byte_count_str)?;
        let record_address = hex_to_u16(address_str)? as u64;
        let record_type = hex_to_u8(record_type_str)?;
        let line_checksum = hex_to_u8(checksum_str)?;

        // calculating check sum by adding em all up with an overflow wrap
        let mut calculated_checksum_sum: u8 = 0;
        calculated_checksum_sum = calculated_checksum_sum.wrapping_add(byte_count);
        calculated_checksum_sum = calculated_checksum_sum.wrapping_add((record_address & 0xFF) as u8);
        calculated_checksum_sum = calculated_checksum_sum.wrapping_add(((record_address >> 8) & 0xFF) as u8);
        calculated_checksum_sum = calculated_checksum_sum.wrapping_add(record_type);

        let data_bytes = hex::decode(data_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                                         format!("Invalid hex data on line {} in {}: {}", line_num + 1, path.display(), e)))?;

        for &b in &data_bytes {
            calculated_checksum_sum = calculated_checksum_sum.wrapping_add(b);
        }

        let calculated_checksum = (!calculated_checksum_sum).wrapping_add(1); //taking two's compliment to cross verify
        if calculated_checksum != line_checksum {
            eprintln!("Warning: Checksum mismatch on line {} in {}. Expected: {:02X}, Got: {:02X}",
                      line_num + 1, path.display(), line_checksum, calculated_checksum);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Checksum mismatch")); //wouldn't wanna be signing anything that even the checksum doesn't want me singing xD
        }
        //calculating base addresses for 16 or 32 bit ones, or just reading em with 00
        match record_type {
            0x00 => { //contains the actual binary itself 
                let start_index = (current_address + record_address) as usize;
                if binary_data.len() < start_index + data_bytes.len() {
                    binary_data.resize(start_index + data_bytes.len(), 0x00);
                }
                binary_data[start_index..(start_index + data_bytes.len())].copy_from_slice(&data_bytes);
            }
            0x01 => { //implies end of record
                break; 
            }
            0x02 => { //just a physical address calculation for 8086 and stuff, thanks to ai now I check for the integrity of the hex passed in as well
                if data_bytes.len() != 2 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                               format!("Invalid data length for Extended Segment Address Record on line {} in {}: expected 2 bytes, got {}", line_num + 1, path.display(), data_bytes.len())));
                }
                let segment_address = (data_bytes[0] as u64) << 8 | (data_bytes[1] as u64);
                current_address = segment_address << 4;
            }
            //03 ignored cause CS and IP are just pointers used to write software, all I wanna do is read the binary, doesn't matter to me
            0x04 => {// same as 02 but just for 32bit rather than 20
                if data_bytes.len() != 2 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData,
                                               format!("Invalid data length for Extended Linear Address Record on line {} in {}: expected 2 bytes, got {}", line_num + 1, path.display(), data_bytes.len())));
                }
                let linear_address = (data_bytes[0] as u64) << 8 | (data_bytes[1] as u64);
                current_address = linear_address << 16; 
            }
            _ => {
                eprintln!("Warning: Unsupported Intel HEX record type (0x{:02X}) on line {} in {}. Skipping.",
                          record_type, line_num + 1, path.display());
            }
            //05 ignored for the same reasons as 03, I don't want any more pointers
        }
    }
    Ok(binary_data)
}

fn hex_to_u8(s: &str) -> io::Result<u8> {
    u8::from_str_radix(s, 16)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse hex string '{}' to u8: {}", s, e)))
}

fn hex_to_u16(s: &str) -> io::Result<u16> {
    u16::from_str_radix(s, 16)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse hex string '{}' to u16: {}", s, e)))
}