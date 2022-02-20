use std::io::prelude::*;
use std::net::TcpStream;

fn main() {
    pretty_env_logger::init();

    match SSHOptions::from_cli() {
        Err(err) => {
            log::error!("{}", err);
            help();
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
    let key_exchange_init = KeyExchangeInit::from_raw(&buf[..]);
    log::info!(
        "key exchange init package received: {:?}",
        key_exchange_init
    );

    Ok(())
}

struct SSHOptions {
    login: String,
    host: String,
}

impl SSHOptions {
    fn from_cli() -> Result<SSHOptions, Box<dyn std::error::Error>> {
        if std::env::args().len() != 2 {
            return Err("wrong arguments".into());
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

#[derive(Debug)]
struct KeyExchangeInit {
    length: u32,
    padding: u8,
    cookie: Vec<u8>,
    kex_algorithms_length: u32,
    kex_algorithms: String,
    server_host_key_algorithms_length: u32,
    server_host_key_algorithms: String,
    encription_algorithms_client_to_server_length: u32,
    encription_algorithms_client_to_server: String,
    encription_algorithms_server_to_client_length: u32,
    encription_algorithms_server_to_client: String,
    mac_algorithms_client_to_server_length: u32,
    mac_algorithms_client_to_server: String,
    mac_algorithms_server_to_client_length: u32,
    mac_algorithms_server_to_client: String,
    compression_algorithms_client_to_server_length: u32,
    compression_algorithms_client_to_server: String,
    compression_algorithms_server_to_client_length: u32,
    compression_algorithms_server_to_client: String,
}

impl KeyExchangeInit {
    fn from_raw(data: &[u8]) -> Result<KeyExchangeInit, Box<dyn std::error::Error>> {
        if data[5] != 20 {
            panic!(
                "wrong message type: 20 is expected but actual is {}",
                data[5]
            );
        }

        let mut cookie = Vec::new();
        cookie.extend_from_slice(&data[6..22]);

        let kex_algorithms_length = deserialize_u32(&data[22..]);
        let kex_algorithms = std::str::from_utf8(&data[26..26 + kex_algorithms_length as usize])?;
        let server_host_key_algorithms_length =
            deserialize_u32(&data[26 + kex_algorithms_length as usize..]);
        let server_host_key_algorithms = std::str::from_utf8(
            &data[30 + kex_algorithms_length as usize
                ..30 + kex_algorithms_length as usize + server_host_key_algorithms_length as usize],
        )?;
        let encription_algorithms_client_to_server_length = deserialize_u32(
            &data[30
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize..],
        );
        let encription_algorithms_client_to_server = std::str::from_utf8(
            &data[34 + kex_algorithms_length as usize + server_host_key_algorithms_length as usize
                ..34 + kex_algorithms_length as usize
                    + server_host_key_algorithms_length as usize
                    + encription_algorithms_client_to_server_length as usize],
        )?;
        let encription_algorithms_server_to_client_length = deserialize_u32(
            &data[34
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize..],
        );
        let encription_algorithms_server_to_client = std::str::from_utf8(
            &data[38
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                ..38 + kex_algorithms_length as usize
                    + server_host_key_algorithms_length as usize
                    + encription_algorithms_client_to_server_length as usize
                    + encription_algorithms_server_to_client_length as usize],
        )?;
        let mac_algorithms_client_to_server_length = deserialize_u32(
            &data[38
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                + encription_algorithms_server_to_client_length as usize..],
        );
        let mac_algorithms_client_to_server = std::str::from_utf8(
            &data[42
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                + encription_algorithms_server_to_client_length as usize
                ..42 + kex_algorithms_length as usize
                    + server_host_key_algorithms_length as usize
                    + encription_algorithms_client_to_server_length as usize
                    + encription_algorithms_server_to_client_length as usize
                    + mac_algorithms_client_to_server_length as usize],
        )?;
        let mac_algorithms_server_to_client_length = deserialize_u32(
            &data[42
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                + encription_algorithms_server_to_client_length as usize
                + mac_algorithms_client_to_server_length as usize..],
        );
        let mac_algorithms_server_to_client = std::str::from_utf8(
            &data[46
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                + encription_algorithms_server_to_client_length as usize
                + mac_algorithms_client_to_server_length as usize
                ..46 + kex_algorithms_length as usize
                    + server_host_key_algorithms_length as usize
                    + encription_algorithms_client_to_server_length as usize
                    + encription_algorithms_server_to_client_length as usize
                    + mac_algorithms_client_to_server_length as usize
                    + mac_algorithms_server_to_client_length as usize],
        )?;
        let compression_algorithms_client_to_server_length = deserialize_u32(
            &data[46
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                + encription_algorithms_server_to_client_length as usize
                + mac_algorithms_client_to_server_length as usize
                + mac_algorithms_server_to_client_length as usize..],
        );
        let compression_algorithms_client_to_server = std::str::from_utf8(
            &data[50
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                + encription_algorithms_server_to_client_length as usize
                + mac_algorithms_client_to_server_length as usize
                + mac_algorithms_server_to_client_length as usize
                ..50 + kex_algorithms_length as usize
                    + server_host_key_algorithms_length as usize
                    + encription_algorithms_client_to_server_length as usize
                    + encription_algorithms_server_to_client_length as usize
                    + mac_algorithms_client_to_server_length as usize
                    + mac_algorithms_server_to_client_length as usize
                    + compression_algorithms_client_to_server_length as usize],
        )?;
        let compression_algorithms_server_to_client_length = deserialize_u32(
            &data[50
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                + encription_algorithms_server_to_client_length as usize
                + mac_algorithms_client_to_server_length as usize
                + mac_algorithms_server_to_client_length as usize
                + compression_algorithms_client_to_server_length as usize..],
        );
        let compression_algorithms_server_to_client = std::str::from_utf8(
            &data[54
                + kex_algorithms_length as usize
                + server_host_key_algorithms_length as usize
                + encription_algorithms_client_to_server_length as usize
                + encription_algorithms_server_to_client_length as usize
                + mac_algorithms_client_to_server_length as usize
                + mac_algorithms_server_to_client_length as usize
                + compression_algorithms_client_to_server_length as usize
                ..54 + kex_algorithms_length as usize
                    + server_host_key_algorithms_length as usize
                    + encription_algorithms_client_to_server_length as usize
                    + encription_algorithms_server_to_client_length as usize
                    + mac_algorithms_client_to_server_length as usize
                    + mac_algorithms_server_to_client_length as usize
                    + compression_algorithms_client_to_server_length as usize
                    + compression_algorithms_server_to_client_length as usize],
        )?;

        Ok(KeyExchangeInit {
            length: deserialize_u32(data),
            padding: data[4],
            cookie,
            kex_algorithms_length,
            kex_algorithms: kex_algorithms.to_string(),
            server_host_key_algorithms_length,
            server_host_key_algorithms: server_host_key_algorithms.to_string(),
            encription_algorithms_client_to_server_length,
            encription_algorithms_client_to_server: encription_algorithms_client_to_server
                .to_string(),
            encription_algorithms_server_to_client_length,
            encription_algorithms_server_to_client: encription_algorithms_server_to_client
                .to_string(),
            mac_algorithms_client_to_server_length,
            mac_algorithms_client_to_server: mac_algorithms_client_to_server.to_string(),
            mac_algorithms_server_to_client_length,
            mac_algorithms_server_to_client: mac_algorithms_server_to_client.to_string(),
            compression_algorithms_client_to_server_length,
            compression_algorithms_client_to_server: compression_algorithms_client_to_server
                .to_string(),
            compression_algorithms_server_to_client_length,
            compression_algorithms_server_to_client: compression_algorithms_server_to_client
                .to_string(),
        })
    }
}

fn deserialize_u32(package: &[u8]) -> u32 {
    (package[0] as u32) << 24
        | (package[1] as u32) << 16
        | (package[2] as u32) << 8
        | (package[3] as u32)
}

fn help() {
    eprint!("please specify destination in format login@host");
}

// fn get_random_buf(buf: &mut [u8]) {
//     getrandom::getrandom(buf).expect("random generator failed");
// }

// fn gen_cookie() -> [u8; 16] {
//     let mut buf = [0u8; 16];
//     get_random_buf(&mut buf);
//     buf
// }
