use macho::parse;
use serde_lexpr::{from_str, to_string};
use std::{env::args, fs::File, io, io::Read};

pub fn main() -> Result<(), String> {
    let mut args = args();
    if args.len() != 2 {
        print_usage();
    }

    let mut file = File::open(args.next().expect("macho file path")).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| e.to_string())?;

    let macho = parse(&buf)?;

    print!("{}", to_string(&macho).expect("serialisation"));

    Ok(())
}

fn print_usage() {
    println!("mmacho <macho file>")
}
