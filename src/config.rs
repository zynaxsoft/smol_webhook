use std::env;
use std::net::ToSocketAddrs;

#[derive(Debug)]
pub struct Config {
    pub ip: String,
    pub port: u32,
    pub socket_addrs: String,
    pub branch: String,
    pub script_path: String,
    pub secret_key: String,
}

impl Config {
    pub fn new() -> Result<Config, &'static str> {
        let ip = env::var("SMOL_WEBHOOK_IP")
                      .unwrap_or("127.0.0.1".to_string());
        let port = {env::var("SMOL_WEBHOOK_PORT")
                        .unwrap_or("7878".to_string())
                        .parse::<u32>()
                        .expect("Please use integer port number \
                                 for SMOL_WEBHOOK_PORT.")
        };
        let socket_addrs = format!("{}:{}", ip, port);
        socket_addrs.to_socket_addrs().expect(
            &format!("Invalid IP or port with value {}", socket_addrs)
            );
        Ok(Config {
            ip,
            port,
            socket_addrs,
            branch: {
                env::var("SMOL_WEBHOOK_BRANCH")
                    .unwrap_or("master".to_string())
            },
            script_path: {
                env::var("SMOL_WEBHOOK_SCRIPT")
                    .unwrap_or("./test.sh".to_string())
            },
            secret_key: {
                env::var("SMOL_WEBHOOK_KEY")
                    .unwrap_or("".to_string())
            },
        })
    }
}
