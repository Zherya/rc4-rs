use clap::Parser;
use std::io::{Read, Write};

// Clap usage notes:
// Documentation of a struct that derives clap::Parser trait
// implementation becomes the description of the executable.
//
// Documentation of the struct field becomes CLI argument/option
// description.

/// Applies RC4 cipher to input file data and writes the result
/// to output file.
#[derive(Parser)] // Derive clap::Parser trait implementation for Args struct
struct Args {
    /// Path to the file with input data
    #[arg(short, long = "in")]
    input: std::path::PathBuf,
    /// Path to the file to place output data to
    #[arg(short, long = "out")]
    output: std::path::PathBuf,
    /// Path to the file with key
    #[arg(short, long)]
    key: std::path::PathBuf,
}

// We can return Result<(), E> variants from main() function,
// because Termination trait is implemented for Result<(), E>:
// it prints error (E) to stderr and returns status code to be
// compatible with C-main function.
fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let input = match std::fs::File::open(args.input) {
        Ok(file) => file,
        Err(err) => {
            eprint!("Cannot open input file: ");
            return Err(err);
        }
    };
    // Add buffering to reading from input file. It should be faster
    // than reading small amount of bytes separately and not such memory
    // consuming as reading entire file to string/vector
    let mut input = std::io::BufReader::new(input);

    let key = match std::fs::read(args.key) {
        Ok(key) => key,
        Err(err) => {
            eprint!("Cannot read from key file: ");
            return Err(err);
        }
    };
    if key.len() < 256 {
        println!("Warning: key is less than 256 bytes long, some bytes might be reused");
    }
    if key.len() > 256 {
        println!("Warning: key is more than 256 bytes long, these bytes will not be used");
    }

    // Require that output file shouldn't exist before processing
    // for avoiding accidental data loss
    let output = match std::fs::File::create_new(args.output) {
        Ok(file) => file,
        Err(err) => {
            eprint!("Cannot create output file: ");
            return Err(err);
        }
    };
    let mut output = std::io::BufWriter::new(output);

    let mut rc4 = rc4_rs::RC4::new(key.as_slice());
    let mut processed_data = [0u8; 256];

    loop {
        let len = input.read(&mut processed_data)?;
        if len == 0 {
            break;
        }
        rc4.xor_keystream_with(&mut processed_data[..len]);
        output.write_all(&processed_data[..len])?;
    }

    Ok(())
}
