use smol_webhook::{Config, ThreadPool};

use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::process::Command;
use std::str;
use std::sync::Arc;

extern crate crypto;
extern crate serde_json;

use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha1::Sha1;
use crypto::util::fixed_time_eq;
use serde_json::Value;

fn main() {
    let config: Arc<Config> = Arc::new(Config::new().unwrap());
    println!("Listening on {}", config.socket_addrs);
    let listener = TcpListener::bind(&config.socket_addrs).unwrap();

    let pool = ThreadPool::new(4);
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let _config = Arc::clone(&config);
        pool.execute(move || {
            handle_connection(_config, stream);
        });
    }
    println!("Shutting down.");
}

fn run_script(path: &str) {
    let output = Command::new("bash")
        .arg(path)
        .output()
        .expect("failed to execute process");
    println!("output\n{}", str::from_utf8(&output.stdout).unwrap());
}

fn sha1_str_to_u8(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() != 45 {
        return Err("Invalid x-hub-signature string");
    }
    match (5..45)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
    {
        Ok(u8_vec) => Ok(u8_vec),
        Err(_) => Err("Invalid x-hub-signature string"),
    }
}

fn check_hash(local_key: &str, body: &str, signature: &str) -> bool {
    let mut hmac = Hmac::new(Sha1::new(), local_key.as_bytes());
    hmac.input(body.as_bytes());
    let my_hash = hmac.result();

    let signature = match sha1_str_to_u8(signature) {
        Ok(u8_vec) => u8_vec,
        Err(_) => return false,
    };
    let signature = MacResult::new(&signature);

    fixed_time_eq(my_hash.code(), signature.code())
}

fn get_header<'a>(key: &str, headers: &'a str) -> Option<&'a str> {
    for header in headers.split("\r\n") {
        if header.starts_with(key) {
            let value = header.split(":").last().unwrap_or("").trim();
            return Some(value);
        }
    }
    None
}

fn process_event(config: Arc<Config>, request: &str) {
    println!("{}", request);
    let body = request.split("\r\n").last().unwrap().trim();
    if let Some(signature) = get_header("X-Hub-Signature", &request) {
        if !check_hash(&config.secret_key, &body, signature) {
            println!("Invalid signature. Ignoring this event.");
            return;
        }
    }
    println!("Got request \n{}", request);
    let json: Value = serde_json::from_str(body).unwrap();
    // println!("{:?}", json);
    if let Value::String(git_ref) = &json["ref"] {
        if &format!("refs/heads/{}", &config.branch) != git_ref {
            println!(
                "Pushed branch \"{}\" doesn't match the configured branch \"{}\"",
                git_ref, &config.branch
            );
            println!("Ignoring this event.");
            return;
        }
    }
    run_script(&config.script_path);
}

fn handle_connection(config: Arc<Config>, mut stream: TcpStream) {
    const BUFF_SIZE: usize = 20024;
    let mut buffer = [0; BUFF_SIZE];
    let mut read_bytes = stream.read(&mut buffer).unwrap();
    let mut request = String::new();
    request.push_str(str::from_utf8(&buffer).unwrap());
    let mut content_length = std::usize::MAX;
    let mut header_ends = false;
    if read_bytes >= BUFF_SIZE {
        loop {
            println!("{} >= {}", read_bytes, content_length);
            if read_bytes >= content_length {
                break;
            }
            let mut buffer = [0; BUFF_SIZE];
            read_bytes += match stream.read(&mut buffer) {
                Ok(read) => read,
                Err(_) => break,
            };
            let buffer_str = str::from_utf8(&buffer).unwrap();
            request.push_str(buffer_str);
            if !header_ends {
                if let Some(size) = get_header("Content-Length", &request) {
                    content_length = size.parse::<usize>().unwrap();
                    if buffer_str.find("\r\n\r\n").is_some() {
                        header_ends = true;
                        read_bytes = 0;
                    }
                }
            }
        }
    }
    let request = request.trim_matches(char::from(0));

    let post = "POST / HTTP/1.0\r\n";
    let response = if request.starts_with(post) {
        "HTTP/1.1 200 OK\r\n\r\n"
    } else {
        "HTTP/1.1 404 NOT FOUND\r\n\r\n"
    };

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
    process_event(config, request);
}
