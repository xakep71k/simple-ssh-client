use std::io::prelude::*;
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    /*
     * handling command line args
     */
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
    log::info!("connecting to host {}", host);
    let mut stream = TcpStream::connect(host)?;

    /*
     * receiving server banner
     */
    let mut buf = vec![0; 1024];
    let size = stream.read(&mut buf)?;
    match std::str::from_utf8(&buf[..size]) {
        Ok(s) => {
            log::info!("server banner: {}", s.trim());
        }
        Err(err) => {
            log::error!("failed to convert to utf8: {}", err);
        }
    }

    /*
     * sending client banner
     */

    let banner = "SSH-2.0-xakep71k simple ssh\r\n";
    if let Err(err) = stream.write(banner.as_bytes()) {
        log::error!("failed to send banner: {}", err);
    } else {
        log::info!("client banner sent successfully: '{}'", banner.trim());
    }

    /*
     * handling key exchange init package
     */
    let _size = stream.read(&mut buf)?;
    let key_exchange_init = KeyExchangeInit::from_raw_data(&buf[..]);
    log::info!(
        "key exchange init package received: {:?}",
        key_exchange_init
    );

    Ok(())
}

#[derive(Debug)]
struct KeyExchangeInit {
    length: u32,
    padding: u8,
}

impl KeyExchangeInit {
    fn from_raw_data(data: &[u8]) -> KeyExchangeInit {
        KeyExchangeInit {
            length: extract_length(data),
            padding: data[4],
        }
    }
}

fn extract_length(package: &[u8]) -> u32 {
    (package[0] as u32) << 24
        | (package[1] as u32) << 16
        | (package[2] as u32) << 8
        | (package[3] as u32)
}

fn help() {
    eprint!("please specify destination in format login@host");
}
