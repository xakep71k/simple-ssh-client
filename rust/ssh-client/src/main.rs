use std::io::prelude::*;
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    if std::env::args().len() != 2 {
        help();
        std::process::exit(1);
    }

    let destination = std::env::args().last().unwrap();
    let mut destination = destination.split('@');

    let login = destination.next().unwrap_or_default();
    let host = destination.next().unwrap_or_default();

    if login.is_empty() || host.is_empty() {
        help();
        std::process::exit(1);
    }

    let host = host.to_string() + ":22";
    let mut stream = TcpStream::connect(host)?;

    let mut buf = Vec::new();
    let size = stream.read(&mut buf)?;
    println!("read size: {}", size);
    Ok(())
}

fn help() {
    eprint!("please specify destination in format login@host");
}
