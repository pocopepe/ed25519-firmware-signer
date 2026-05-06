use std::io::{self, BufRead, BufReader, Cursor};
use std::path::Path;

pub fn read_firmware_data(path: &Path) -> io::Result<Vec<u8>> {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "bin" => std::fs::read(path),
        "hex" => parse_intel_hex(&std::fs::read(path)?),
        ext => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported file extension: {}", ext),
        )),
    }
}

pub fn parse_intel_hex(data: &[u8]) -> io::Result<Vec<u8>> {
    let reader = BufReader::new(Cursor::new(data));
    let mut out: Vec<u8> = Vec::new();
    let mut base: u64 = 0;

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        if !line.starts_with(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {} missing ':' prefix", i + 1),
            ));
        }

        let rec = &line[1..];
        if rec.len() < 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {} too short", i + 1),
            ));
        }

        let byte_count = parse_u8(&rec[0..2], i)?;
        let addr = parse_u16(&rec[2..6], i)? as u64;
        let rec_type = parse_u8(&rec[6..8], i)?;
        let data_hex = &rec[8..rec.len() - 2];
        let checksum = parse_u8(&rec[rec.len() - 2..], i)?;

        let data = hex::decode(data_hex).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {} bad hex data: {}", i + 1, e),
            )
        })?;

        verify_checksum(byte_count, addr, rec_type, &data, checksum, i)?;

        match rec_type {
            0x00 => {
                let start = (base + addr) as usize;
                if out.len() < start + data.len() {
                    out.resize(start + data.len(), 0x00);
                }
                out[start..start + data.len()].copy_from_slice(&data);
            }
            0x01 => break,
            0x02 => {
                let seg = (data[0] as u64) << 8 | data[1] as u64;
                base = seg << 4;
            }
            0x04 => {
                let lin = (data[0] as u64) << 8 | data[1] as u64;
                base = lin << 16;
            }
            t => eprintln!(
                "Warning: unsupported HEX record type 0x{:02X} on line {}, skipping",
                t,
                i + 1
            ),
        }
    }

    Ok(out)
}

fn verify_checksum(
    byte_count: u8,
    addr: u64,
    rec_type: u8,
    data: &[u8],
    expected: u8,
    line: usize,
) -> io::Result<()> {
    let mut sum: u8 = byte_count
        .wrapping_add((addr & 0xFF) as u8)
        .wrapping_add(((addr >> 8) & 0xFF) as u8)
        .wrapping_add(rec_type);
    for &b in data {
        sum = sum.wrapping_add(b);
    }
    let calculated = (!sum).wrapping_add(1);
    if calculated != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "checksum mismatch on line {}: expected {:02X}, got {:02X}",
                line + 1,
                expected,
                calculated
            ),
        ));
    }
    Ok(())
}

fn parse_u8(s: &str, line: usize) -> io::Result<u8> {
    u8::from_str_radix(s, 16).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line {}: bad hex byte '{}': {}", line + 1, s, e),
        )
    })
}

fn parse_u16(s: &str, line: usize) -> io::Result<u16> {
    u16::from_str_radix(s, 16).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line {}: bad hex u16 '{}': {}", line + 1, s, e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_tmp(name: &str, content: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn reads_bin_file() {
        let p = write_tmp("binsign_test.bin", &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(read_firmware_data(&p).unwrap(), [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn unsupported_extension_fails() {
        let p = write_tmp("binsign_test.exe", &[0x00]);
        assert!(read_firmware_data(&p).is_err());
    }

    #[test]
    fn reads_valid_hex_file() {
        // :04000000DEADBEEFC4 — 4 bytes at address 0x0000: DE AD BE EF
        // checksum: ~(04+00+00+00+DE+AD+BE+EF) + 1 = ~0x3C + 1 = 0xC4
        let hex = b":04000000DEADBEEFC4\n:00000001FF\n";
        let p = write_tmp("binsign_test.hex", hex);
        assert_eq!(read_firmware_data(&p).unwrap(), [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn bad_hex_checksum_fails() {
        let hex = b":04000000DEADBEEF00\n:00000001FF\n"; // 0x00 is wrong checksum
        let p = write_tmp("binsign_test_bad.hex", hex);
        assert!(read_firmware_data(&p).is_err());
    }

    #[test]
    fn missing_colon_prefix_fails() {
        let p = write_tmp("binsign_test_nocolon.hex", b"04000000DEADBEEFC4\n");
        assert!(read_firmware_data(&p).is_err());
    }

    #[test]
    fn multiple_data_records_concatenate() {
        // Two 2-byte data records placed back to back at address 0 and 2.
        // :020000000102FB  — bytes 01 02 at 0x0000, checksum FB
        // :020002000304F5  — bytes 03 04 at 0x0002, checksum F5
        // checksums:
        //   record 1: ~(02+00+00+00+01+02) + 1 = ~0x05 + 1 = 0xFB
        //   record 2: ~(02+00+02+00+03+04) + 1 = ~0x0B + 1 = 0xF5
        let hex = b":020000000102FB\n:020002000304F5\n:00000001FF\n";
        let p = write_tmp("binsign_multi.hex", hex);
        assert_eq!(read_firmware_data(&p).unwrap(), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn extended_linear_address_shifts_base() {
        // Record 0x04 sets the upper 16 bits of the address.
        // :020000040001F9  — upper word = 0x0001 so base = 0x0001_0000
        //   checksum: ~(02+00+00+04+00+01) + 1 = ~0x07 + 1 = 0xF9
        // :0100000001FE   — 1 byte (0x01) at base + 0x0000 = 0x1_0000
        //   checksum: ~(01+00+00+00+01) + 1 = ~0x02 + 1 = 0xFE
        let hex = b":020000040001F9\n:0100000001FE\n:00000001FF\n";
        let p = write_tmp("binsign_ela.hex", hex);
        let data = read_firmware_data(&p).unwrap();
        // The byte lands at offset 0x10000 so the output is padded to that length.
        assert_eq!(data.len(), 0x1_0001);
        assert_eq!(data[0x1_0000], 0x01);
    }

    #[test]
    fn empty_hex_just_eof_is_empty() {
        let p = write_tmp("binsign_eof_only.hex", b":00000001FF\n");
        assert_eq!(read_firmware_data(&p).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn record_too_short_fails() {
        // Fewer than 10 hex chars after the colon.
        let p = write_tmp("binsign_short.hex", b":0000FF\n");
        assert!(read_firmware_data(&p).is_err());
    }

    #[test]
    fn bin_file_preserves_bytes_exactly() {
        let data: Vec<u8> = (0u8..=255).collect();
        let p = write_tmp("binsign_full.bin", &data);
        assert_eq!(read_firmware_data(&p).unwrap(), data);
    }
}
