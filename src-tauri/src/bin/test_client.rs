use std::net::TcpStream;
use std::io::{Write, Read};

fn main() {
    println!("=== Transparent Proxy Test Client ===");
    println!("Connecting to ifconfig.me on port 80...");
    
    match TcpStream::connect("ifconfig.me:80") {
        Ok(mut stream) => {
            println!("Connected successfully! Sending HTTP request...");
            let req = b"GET / HTTP/1.0\r\nHost: ifconfig.me\r\nUser-Agent: curl/7.79.1\r\nAccept: */*\r\n\r\n";
            if let Err(e) = stream.write_all(req) {
                eprintln!("Failed to write request: {:?}", e);
                return;
            }
            
            let mut response = String::new();
            if let Err(e) = stream.read_to_string(&mut response) {
                eprintln!("Failed to read response: {:?}", e);
                return;
            }
            
            if let Some(body_start) = response.find("\r\n\r\n") {
                let body = &response[body_start + 4..];
                println!("\n[RESULT] Your external IP is: {}", body.trim());
            } else {
                println!("\n[RAW RESPONSE]:\n{}", response);
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to ifconfig.me: {:?}", e);
        }
    }
}
