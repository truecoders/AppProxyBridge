use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use crate::proxy_core::EngineState;
use tauri::{AppHandle, Emitter};

pub async fn start_tcp_relay(state: Arc<EngineState>, app: AppHandle) {
    let running = state.running.clone();
    let addr = "0.0.0.0:34020";
    
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("CRITICAL: Failed to bind TCP relay listener to {}: {:?}", addr, e);
            return;
        }
    };
    
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        let (mut client_socket, client_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(_) => continue,
        };
        
        let state_clone = state.clone();
        let app_clone = app.clone();
        
        tokio::spawn(async move {
            // Find original destination and proxy ID for this port
            let client_port = client_addr.port();
            
            let mapping = {
                let redirect_table = state_clone.redirect_table.lock().await;
                redirect_table.get(&client_port).cloned()
            };
            
            if let Some((dest_addr, proxy_id)) = mapping {
                
                // Find matching proxy configuration in the pool
                let proxy_config = {
                    let config = state_clone.config.lock().await;
                    config.iter().find(|p| p.id == proxy_id).cloned()
                };
                
                // Try to resolve the process name from the PID cache to match the connection_id format in proxy_core.rs
                let (pid, process_name) = {
                    let cache = state_clone.pid_cache.lock().await;
                    if let Some(entry) = cache.get(&client_port) {
                        (entry.pid, entry.process_name.clone())
                    } else {
                        (0, "Unknown".to_string())
                    }
                };
                
                let connection_id = format!("{}:{}-{}:{}", process_name, client_port, dest_addr.ip(), dest_addr.port());
                
                if let Some(cfg) = proxy_config {
                    // Tunnel traffic to Upstream Proxy
                    let proxy_addr = format!("{}:{}", cfg.host, cfg.port);
                    match TcpStream::connect(&proxy_addr).await {
                        Ok(mut proxy_socket) => {
                            
                            // Perform SOCKS5 or HTTP CONNECT handshake
                            match perform_proxy_handshake(&mut proxy_socket, &cfg, dest_addr).await {
                                Ok(()) => {
                                    
                                    // Send event to UI that the connection is now fully proxied
                                    let mut conn_event = crate::proxy_core::ConnectionInfo {
                                        id: connection_id.clone(),
                                        pid,
                                        process_name: process_name.clone(),
                                        protocol: "TCP".to_string(),
                                        source_addr: format!("127.0.0.1:{}", client_port),
                                        original_dest: dest_addr.to_string(),
                                        action: "Proxy".to_string(),
                                        bytes_sent: 0,
                                        bytes_received: 0,
                                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                                        status: "Proxied".to_string(),
                                    };
                                    let _ = app_clone.emit("connection-event", conn_event.clone());
                                    
                                    // Establish pipe
                                    match copy_bidirectional(&mut client_socket, &mut proxy_socket).await {
                                        Ok((sent, received)) => {
                                            conn_event.bytes_sent = sent;
                                            conn_event.bytes_received = received;
                                            conn_event.status = "Closed".to_string();
                                            let _ = app_clone.emit("connection-event", conn_event);
                                        }
                                        Err(_e) => {
                                            conn_event.status = "Closed".to_string();
                                            let _ = app_clone.emit("connection-event", conn_event);
                                        }
                                    }
                                }
                                Err(handshake_err) => {
                                    eprintln!("CRITICAL: Proxy handshake failed for upstream {}: {:?}", proxy_addr, handshake_err);
                                    // Emit closed event on handshake failure
                                    let conn_event = crate::proxy_core::ConnectionInfo {
                                        id: connection_id.clone(),
                                        pid,
                                        process_name: process_name.clone(),
                                        protocol: "TCP".to_string(),
                                        source_addr: format!("127.0.0.1:{}", client_port),
                                        original_dest: dest_addr.to_string(),
                                        action: "Proxy".to_string(),
                                        bytes_sent: 0,
                                        bytes_received: 0,
                                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                                        status: "Closed".to_string(),
                                    };
                                    let _ = app_clone.emit("connection-event", conn_event);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("CRITICAL: Failed to connect to upstream proxy at {}: {:?}", proxy_addr, e);
                            // Emit closed event
                            let conn_event = crate::proxy_core::ConnectionInfo {
                                id: connection_id.clone(),
                                pid,
                                process_name: process_name.clone(),
                                protocol: "TCP".to_string(),
                                source_addr: format!("127.0.0.1:{}", client_port),
                                original_dest: dest_addr.to_string(),
                                action: "Proxy".to_string(),
                                bytes_sent: 0,
                                bytes_received: 0,
                                timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                                status: "Closed".to_string(),
                            };
                            let _ = app_clone.emit("connection-event", conn_event);
                        }
                    }
                } else {
                    // No proxy configured / not found, direct fallback
                    match TcpStream::connect(dest_addr).await {
                        Ok(mut dest_socket) => {
                            let mut conn_event = crate::proxy_core::ConnectionInfo {
                                id: connection_id.clone(),
                                pid,
                                process_name: process_name.clone(),
                                protocol: "TCP".to_string(),
                                source_addr: format!("127.0.0.1:{}", client_port),
                                original_dest: dest_addr.to_string(),
                                action: "Direct".to_string(),
                                bytes_sent: 0,
                                bytes_received: 0,
                                timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                                status: "Active".to_string(),
                            };
                            let _ = app_clone.emit("connection-event", conn_event.clone());
                            
                            match copy_bidirectional(&mut client_socket, &mut dest_socket).await {
                                Ok((sent, received)) => {
                                    conn_event.bytes_sent = sent;
                                    conn_event.bytes_received = received;
                                    conn_event.status = "Closed".to_string();
                                    let _ = app_clone.emit("connection-event", conn_event);
                                }
                                Err(_e) => {
                                    conn_event.status = "Closed".to_string();
                                    let _ = app_clone.emit("connection-event", conn_event);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Direct fallback connection failed: {:?}", e);
                        }
                    }
                }
            }
        });
    }
}

pub async fn start_udp_relay(state: Arc<EngineState>, _app: AppHandle) {
    // SOCKS5 UDP Associate relay implementation structure
    let running = state.running.clone();
    let _addr = "0.0.0.0:34021";

    
    // In a real SOCKS5 UDP setup, this would bind a UdpSocket,
    // intercept UDP packets, wrap them in SOCKS5 UDP headers,
    // and forward them via the SOCKS5 proxy UDP port.
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

// Perform proxy protocol handshake (SOCKS5 or HTTP CONNECT)
async fn perform_proxy_handshake(
    proxy_socket: &mut TcpStream,
    cfg: &crate::proxy_core::ProxyConfig,
    dest_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if cfg.proxy_type.to_uppercase() == "SOCKS5" {
        // --- SOCKS5 Handshake ---
        // 1. Send SOCKS5 Greeting (supporting both No Auth and Username/Password Auth methods)
        let greeting = vec![0x05, 0x02, 0x00, 0x02];
        proxy_socket.write_all(&greeting).await?;

        // 2. Read Greeting Response
        let mut response = [0u8; 2];
        proxy_socket.read_exact(&mut response).await?;
        if response[0] != 0x05 {
            return Err("Invalid SOCKS version in response".into());
        }

        let auth_method = response[1];
        if auth_method == 0x02 {
            // Username/Password authentication
            let user = cfg.username.as_deref().unwrap_or("");
            let pass = cfg.password.as_deref().unwrap_or("");

            let mut auth_req = vec![0x01]; // Subnegotiation version 1
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());

            proxy_socket.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            proxy_socket.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                return Err("SOCKS5 Authentication failed".into());
            }
        } else if auth_method != 0x00 {
            return Err(format!("Unsupported SOCKS5 auth method: {}", auth_method).into());
        }

        // 3. Send Connect Request
        let mut request = vec![0x05, 0x01, 0x00]; // Version 5, Connect command, Reserved
        match dest_addr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                request.push(0x01); // ATYP: IPv4
                request.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                request.push(0x04); // ATYP: IPv6
                request.extend_from_slice(&ipv6.octets());
            }
        }
        request.extend_from_slice(&dest_addr.port().to_be_bytes());
        proxy_socket.write_all(&request).await?;

        // 4. Read Response
        let mut resp_header = [0u8; 4];
        proxy_socket.read_exact(&mut resp_header).await?;
        if resp_header[0] != 0x05 {
            return Err("Invalid SOCKS version in connect response".into());
        }
        if resp_header[1] != 0x00 {
            return Err(format!("SOCKS5 connection error code: {}", resp_header[1]).into());
        }

        let atyp = resp_header[3];
        match atyp {
            0x01 => {
                let mut addr_port = [0u8; 6];
                proxy_socket.read_exact(&mut addr_port).await?;
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                proxy_socket.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;
                let mut rest = vec![0u8; domain_len + 2];
                proxy_socket.read_exact(&mut rest).await?;
            }
            0x04 => {
                let mut addr_port = [0u8; 18];
                proxy_socket.read_exact(&mut addr_port).await?;
            }
            _ => return Err("Unsupported address type in SOCKS5 connect response".into()),
        }
    } else {
        // --- HTTP CONNECT Handshake ---
        let mut headers = format!(
            "CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n",
            dest_addr
        );

        if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
            let credentials = format!("{}:{}", user, pass);
            let encoded = base64_encode(&credentials);
            headers.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        headers.push_str("\r\n");

        proxy_socket.write_all(headers.as_bytes()).await?;

        // Read response until double CRLF
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while response.len() < 4096 {
            proxy_socket.read_exact(&mut byte).await?;
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        let resp_str = String::from_utf8_lossy(&response);
        if !resp_str.contains(" 200 ") {
            return Err(format!("HTTP CONNECT failed: {}", resp_str.trim()).into());
        }
    }

    Ok(())
}

// Inlined simple Base64 encoder to avoid external crate dependency
fn base64_encode(input: &str) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { Some(bytes[i + 1]) } else { None };
        let b2 = if i + 2 < bytes.len() { Some(bytes[i + 2]) } else { None };
        
        let val = ((b0 as u32) << 16) | ((b1.unwrap_or(0) as u32) << 8) | b2.unwrap_or(0) as u32;
        
        let c0 = CHARSET[((val >> 18) & 0x3F) as usize] as char;
        let c1 = CHARSET[((val >> 12) & 0x3F) as usize] as char;
        let c2 = if b1.is_some() { CHARSET[((val >> 6) & 0x3F) as usize] as char } else { '=' };
        let c3 = if b2.is_some() { CHARSET[(val & 0x3F) as usize] as char } else { '=' };
        
        result.push(c0);
        result.push(c1);
        result.push(c2);
        result.push(c3);
        
        i += 3;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use crate::proxy_core::ProxyConfig;

    // Helper mock HTTP CONNECT server
    async fn run_mock_http_server(addr: &'static str) -> tokio::task::JoinHandle<()> {
        let listener = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 1024];
                let n = socket.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..n]);
                if request.contains("CONNECT") {
                    // Check authentication if username/password are expected
                    if request.contains("Proxy-Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3M=") {
                        socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                    } else if !request.contains("Proxy-Authorization:") {
                        socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                    } else {
                        socket.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await.unwrap();
                    }
                }
            }
        })
    }

    // Helper mock SOCKS5 server
    async fn run_mock_socks5_server(addr: &'static str, require_auth: bool) -> tokio::task::JoinHandle<()> {
        let listener = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                // Read Greeting
                let mut greeting = [0u8; 10];
                let _n = socket.read(&mut greeting).await.unwrap();
                
                if require_auth {
                    // Choose Username/Password (0x02)
                    socket.write_all(&[0x05, 0x02]).await.unwrap();
                    
                    // Read Auth Req
                    let mut auth_req = [0u8; 100];
                    let n = socket.read(&mut auth_req).await.unwrap();
                    // Verify auth req
                    if n >= 5 {
                        let user_len = auth_req[1] as usize;
                        let user = String::from_utf8_lossy(&auth_req[2..2 + user_len]);
                        let pass_len = auth_req[2 + user_len] as usize;
                        let pass = String::from_utf8_lossy(&auth_req[2 + user_len + 1..2 + user_len + 1 + pass_len]);
                        
                        if user == "testuser" && pass == "testpass" {
                            socket.write_all(&[0x01, 0x00]).await.unwrap(); // Success
                        } else {
                            socket.write_all(&[0x01, 0x01]).await.unwrap(); // Failure
                            return;
                        }
                    } else {
                        socket.write_all(&[0x01, 0x01]).await.unwrap();
                        return;
                    }
                } else {
                    // Choose No Auth (0x00)
                    socket.write_all(&[0x05, 0x00]).await.unwrap();
                }

                // Read Connect Request
                let mut connect_req = [0u8; 100];
                let _n = socket.read(&mut connect_req).await.unwrap();
                // Respond success
                let resp = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
                socket.write_all(&resp).await.unwrap();
            }
        })
    }

    #[tokio::test]
    async fn test_socks5_handshake_no_auth() {
        let server_addr = "127.0.0.1:39010";
        let _server = run_mock_socks5_server(server_addr, false).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let cfg = ProxyConfig {
            id: "test".to_string(),
            name: "test".to_string(),
            proxy_type: "SOCKS5".to_string(),
            host: "127.0.0.1".to_string(),
            port: 39010,
            username: None,
            password: None,
            is_primary: false,
        };

        let dest = "1.1.1.1:80".parse().unwrap();
        let result = perform_proxy_handshake(&mut client, &cfg, dest).await;
        assert!(result.is_ok(), "Handshake failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_socks5_handshake_with_auth() {
        let server_addr = "127.0.0.1:39011";
        let _server = run_mock_socks5_server(server_addr, true).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let cfg = ProxyConfig {
            id: "test".to_string(),
            name: "test".to_string(),
            proxy_type: "SOCKS5".to_string(),
            host: "127.0.0.1".to_string(),
            port: 39011,
            username: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
            is_primary: false,
        };

        let dest = "1.1.1.1:80".parse().unwrap();
        let result = perform_proxy_handshake(&mut client, &cfg, dest).await;
        assert!(result.is_ok(), "Handshake failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_http_handshake_no_auth() {
        let server_addr = "127.0.0.1:39012";
        let _server = run_mock_http_server(server_addr).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let cfg = ProxyConfig {
            id: "test".to_string(),
            name: "test".to_string(),
            proxy_type: "HTTP".to_string(),
            host: "127.0.0.1".to_string(),
            port: 39012,
            username: None,
            password: None,
            is_primary: false,
        };

        let dest = "1.1.1.1:80".parse().unwrap();
        let result = perform_proxy_handshake(&mut client, &cfg, dest).await;
        assert!(result.is_ok(), "Handshake failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_http_handshake_with_auth() {
        let server_addr = "127.0.0.1:39013";
        let _server = run_mock_http_server(server_addr).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let cfg = ProxyConfig {
            id: "test".to_string(),
            name: "test".to_string(),
            proxy_type: "HTTP".to_string(),
            host: "127.0.0.1".to_string(),
            port: 39013,
            username: Some("testuser".to_string()),
            password: Some("testpass".to_string()),
            is_primary: false,
        };

        let dest = "1.1.1.1:80".parse().unwrap();
        let result = perform_proxy_handshake(&mut client, &cfg, dest).await;
        assert!(result.is_ok(), "Handshake failed: {:?}", result.err());
    }
}

