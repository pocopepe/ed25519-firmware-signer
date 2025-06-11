use std::io::BufRead;
use hex;
use std::path::PathBuf;
use std::io::{self, BufReader}; 

pub fn read_firmware_data(path: &PathBuf) -> io::Result<Vec<u8>> {
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


