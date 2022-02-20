use std::io::prelude::*;
use std::net::TcpStream;

fn main() {
    pretty_env_logger::init();

    match SSHOptions::from_cli() {
        Err(err) => {
            log::error!("{}", err);
            std::process::exit(1);
        }
        Ok(opts) => {
            if let Err(err) = ssh(opts) {
                log::error!("{}", err);
            }
        }
    }

    std::process::exit(0);
}

struct SSHOptions {
    login: String,
    host: String,
}

impl SSHOptions {
    fn from_cli() -> Result<SSHOptions, Box<dyn std::error::Error>> {
        if std::env::args().len() != 2 {
            help();
            std::process::exit(1);
        }

        let destination = std::env::args().last().unwrap();
        let mut destination = destination.split('@');

        let login = destination.next().unwrap_or_default().to_string();
        let host = destination.next().unwrap_or_default().to_string();

        if login.is_empty() {
            return Err("login not specified".into());
        }

        if host.is_empty() {
            return Err("host not specified".into());
        }

        let host = host + ":22";
        Ok(SSHOptions { login, host })
    }
}

fn ssh(opts: SSHOptions) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("connecting to  {}@{}", opts.login, opts.host);
    let mut stream = TcpStream::connect(opts.host)?;

    /*
     * receiving server banner
     */
    let mut buf = vec![0; 1024];
    let size = stream.read(&mut buf)?;
    let banner = std::str::from_utf8(&buf[..size])?;
    log::info!("server banner: {}", banner.trim());

    if !banner.starts_with("SSH-2.0") {
        return Err(format!("SSH version not supported: '{}'", banner).into());
    }

    /*
     * sending client banner
     */

    let banner = "SSH-2.0-xakep71k simple ssh\r\n";
    if let Err(err) = stream.write(banner.as_bytes()) {
        return Err(format!("failed to send banner: {}", err).into());
    }
    log::info!("client banner sent successfully: '{}'", banner.trim());

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
