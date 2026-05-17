use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::copy_bidirectional;
use crate::proxy_core::EngineState;
use tauri::{AppHandle, Emitter};

pub async fn start_tcp_relay(state: Arc<EngineState>, app: AppHandle) {
    let running = state.running.clone();
    let addr = "127.0.0.1:34010";
    
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind TCP relay listener to {}: {:?}", addr, e);
            return;
        }
    };
    
    println!("TCP Relay listening on {}", addr);
    
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
                
                if let Some(cfg) = proxy_config {
                    // Tunnel traffic to Upstream Proxy
                    let proxy_addr = format!("{}:{}", cfg.host, cfg.port);
                    match TcpStream::connect(&proxy_addr).await {
                        Ok(mut proxy_socket) => {
                            // Establish pipe
                            let connection_id = format!("RELAY-{}:{}", client_port, dest_addr);
                            println!("Tunneling traffic to proxy [{}] for {}", cfg.name, connection_id);
                            
                            let mut active_connections = state_clone.active_connections.lock().await;
                            if let Some(conn) = active_connections.get_mut(&connection_id) {
                                conn.status = "Proxied".to_string();
                                let _ = app_clone.emit("connection-event", conn.clone());
                            }
                            drop(active_connections);
                            
                            match copy_bidirectional(&mut client_socket, &mut proxy_socket).await {
                                Ok((sent, received)) => {
                                    let mut active_connections = state_clone.active_connections.lock().await;
                                    if let Some(conn) = active_connections.get_mut(&connection_id) {
                                        conn.bytes_sent = sent;
                                        conn.bytes_received = received;
                                        conn.status = "Closed".to_string();
                                        let _ = app_clone.emit("connection-event", conn.clone());
                                    }
                                    drop(active_connections);
                                }
                                Err(e) => {
                                    eprintln!("Bidirectional copy error: {:?}", e);
                                    let mut active_connections = state_clone.active_connections.lock().await;
                                    if let Some(conn) = active_connections.get_mut(&connection_id) {
                                        conn.status = "Closed".to_string();
                                        let _ = app_clone.emit("connection-event", conn.clone());
                                    }
                                    drop(active_connections);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to upstream proxy at {}: {:?}", proxy_addr, e);
                        }
                    }
                } else {
                    // No proxy configured / not found, direct fallback
                    match TcpStream::connect(dest_addr).await {
                        Ok(mut dest_socket) => {
                            let connection_id = format!("RELAY-{}:{}", client_port, dest_addr);
                            match copy_bidirectional(&mut client_socket, &mut dest_socket).await {
                                Ok((sent, received)) => {
                                    let mut active_connections = state_clone.active_connections.lock().await;
                                    if let Some(conn) = active_connections.get_mut(&connection_id) {
                                        conn.bytes_sent = sent;
                                        conn.bytes_received = received;
                                        conn.status = "Closed".to_string();
                                        let _ = app_clone.emit("connection-event", conn.clone());
                                    }
                                    drop(active_connections);
                                }
                                Err(e) => {
                                    eprintln!("Direct fallback copy error: {:?}", e);
                                    let mut active_connections = state_clone.active_connections.lock().await;
                                    if let Some(conn) = active_connections.get_mut(&connection_id) {
                                        conn.status = "Closed".to_string();
                                        let _ = app_clone.emit("connection-event", conn.clone());
                                    }
                                    drop(active_connections);
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
    let addr = "127.0.0.1:34011";
    println!("UDP Relay listening on {}", addr);
    
    // In a real SOCKS5 UDP setup, this would bind a UdpSocket,
    // intercept UDP packets, wrap them in SOCKS5 UDP headers,
    // and forward them via the SOCKS5 proxy UDP port.
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
