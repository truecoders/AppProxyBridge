use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::{broadcast, Mutex};
use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter};

// Windows-specific imports
use windows_sys::Win32::Foundation::{HANDLE, CloseHandle, FALSE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION
};

// WinDivert Imports
use windivert::prelude::*;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;

type BOOL = i32;

// Define structure for network connection events streamed to the UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub pid: u32,
    pub process_name: String,
    pub protocol: String,
    pub source_addr: String,
    pub original_dest: String,
    pub action: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub timestamp: u64,
    pub status: String, // "Active", "Closed", "Blocked"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub id: String,
    pub name: String,
    pub proxy_type: String, // "SOCKS5" or "HTTP"
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub is_primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Block,
    Direct,
    Proxy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub process_name: String, // Match wildcard like "*chrome.exe" or exact "telegram.exe"
    pub action: RuleAction,
    pub proxy_id: Option<String>, // Dynamic binding to specific ProxyConfig
}

// Caching PID to prevent calling heavy Win32 Table API on every packet
pub struct PidCacheEntry {
    pub pid: u32,
    pub process_name: String,
    pub timestamp: std::time::Instant,
}

// Per-process accumulated traffic stats (process_name -> (bytes_sent, bytes_received, last_activity_timestamp))
// Uses std::sync::Mutex for fast blocking access from WinDivert packet thread
pub type TrafficStats = Arc<StdMutex<HashMap<String, (u64, u64, u64)>>>;

// Main Engine State
pub struct EngineState {
    pub running: Arc<AtomicBool>,
    pub config: Arc<Mutex<Vec<ProxyConfig>>>, // Multiple proxies pool
    pub rules: Arc<Mutex<Vec<Rule>>>,
    pub pid_cache: Arc<Mutex<HashMap<u16, PidCacheEntry>>>, // Key: local port
    pub active_connections: Arc<Mutex<HashMap<String, ConnectionInfo>>>, // Key: connection ID
    pub event_sender: broadcast::Sender<ConnectionInfo>,
    pub redirect_table: Arc<Mutex<HashMap<u16, (SocketAddr, String)>>>, // Map local_port -> (original_destination, proxy_id)
    pub bypass_local: Arc<AtomicBool>,
    pub proxy_dns: Arc<AtomicBool>,
    pub autostart: Arc<AtomicBool>,
    pub minimize_to_tray: Arc<AtomicBool>,
    pub traffic_stats: TrafficStats, // Per-process accumulated traffic
}

impl EngineState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self {
            running: Arc::new(AtomicBool::new(false)),
            config: Arc::new(Mutex::new(Vec::new())),
            rules: Arc::new(Mutex::new(Vec::new())),
            pid_cache: Arc::new(Mutex::new(HashMap::new())),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            event_sender: tx,
            redirect_table: Arc::new(Mutex::new(HashMap::new())),
            bypass_local: Arc::new(AtomicBool::new(true)),
            proxy_dns: Arc::new(AtomicBool::new(true)),
            autostart: Arc::new(AtomicBool::new(true)),
            minimize_to_tray: Arc::new(AtomicBool::new(true)),
            traffic_stats: Arc::new(StdMutex::new(HashMap::new())),
        }
    }
}

/// Returns per-process traffic stats as a HashMap<String, (u64, u64, u64)>
pub fn get_traffic_stats_snapshot(state: &EngineState) -> HashMap<String, (u64, u64, u64)> {
    let stats = state.traffic_stats.lock().unwrap_or_else(|e| e.into_inner());
    stats.clone()
}

// Win32 Helper to resolve Port -> PID -> Process Name (called from sync/blocking pool)
pub fn resolve_process_for_port_sync(port: u16, is_tcp: bool, state: &EngineState) -> (u32, String) {
    // 1. Check cache first (using standard sync block/try_lock if possible, or blocking_lock)
    {
        // Since we are in a blocking thread, we can block on tokio Mutexes using blocking_lock
        let cache = state.pid_cache.blocking_lock();
        if let Some(entry) = cache.get(&port) {
            if entry.timestamp.elapsed().as_secs() < 30 {
                return (entry.pid, entry.process_name.clone());
            }
        }
    }

    // 2. Query Windows Tables
    let pid = unsafe { get_pid_for_port(port, is_tcp) };
    let process_name = if pid > 0 {
        get_process_name_for_pid(pid)
    } else {
        "Unknown".to_string()
    };

    // 3. Store in cache
    {
        let mut cache = state.pid_cache.blocking_lock();
        cache.insert(port, PidCacheEntry {
            pid,
            process_name: process_name.clone(),
            timestamp: std::time::Instant::now(),
        });
    }

    (pid, process_name)
}

// Low-level Win32 call to get PID for port
unsafe fn get_pid_for_port(port: u16, is_tcp: bool) -> u32 {
    let mut size = 0;
    if is_tcp {
        // TCP IPv4
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            if GetExtendedTcpTable(buffer.as_mut_ptr() as *mut _, &mut size, FALSE, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                let table_ptr = buffer.as_ptr() as *const MibTcpTableOwnerPid;
                let num_entries = (*table_ptr).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), num_entries);
                for entry in entries {
                    let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);
                    if local_port == port { return entry.dwOwningPid; }
                }
            }
        }
        // TCP IPv6
        size = 0;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            if GetExtendedTcpTable(buffer.as_mut_ptr() as *mut _, &mut size, FALSE, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                let table_ptr = buffer.as_ptr() as *const MibTcp6TableOwnerPid;
                let num_entries = (*table_ptr).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), num_entries);
                for entry in entries {
                    let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);
                    if local_port == port { return entry.dwOwningPid; }
                }
            }
        }
    } else {
        // UDP IPv4
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);
        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            if GetExtendedUdpTable(buffer.as_mut_ptr() as *mut _, &mut size, FALSE, AF_INET as u32, UDP_TABLE_OWNER_PID, 0) == 0 {
                let table_ptr = buffer.as_ptr() as *const MibUdpTableOwnerPid;
                let num_entries = (*table_ptr).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), num_entries);
                for entry in entries {
                    let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);
                    if local_port == port { return entry.dwOwningPid; }
                }
            }
        }
        // UDP IPv6
        size = 0;
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0);
        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            if GetExtendedUdpTable(buffer.as_mut_ptr() as *mut _, &mut size, FALSE, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0) == 0 {
                let table_ptr = buffer.as_ptr() as *const MibUdp6TableOwnerPid;
                let num_entries = (*table_ptr).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), num_entries);
                for entry in entries {
                    let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);
                    if local_port == port { return entry.dwOwningPid; }
                }
            }
        }
    }
    0
}

// Low-level Win32 structures for GetExtendedTcpTable / GetExtendedUdpTable
#[allow(non_snake_case)]
#[repr(C)]
struct MibTcpRowOwnerPid {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
}

#[allow(non_snake_case)]
#[repr(C)]
struct MibTcpTableOwnerPid {
    dwNumEntries: u32,
    table: [MibTcpRowOwnerPid; 1],
}

#[allow(non_snake_case)]
#[repr(C)]
struct MibUdpRowOwnerPid {
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwOwningPid: u32,
}

#[allow(non_snake_case)]
#[repr(C)]
struct MibUdpTableOwnerPid {
    dwNumEntries: u32,
    table: [MibUdpRowOwnerPid; 1],
}

// IPv6 TCP structures for modern apps (Telegram, etc.)
#[allow(non_snake_case)]
#[repr(C)]
struct MibTcp6RowOwnerPid {
    ucLocalAddr: [u8; 16],
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    ucRemoteAddr: [u8; 16],
    dwRemoteScopeId: u32,
    dwRemotePort: u32,
    dwState: u32,
    dwOwningPid: u32,
}

#[allow(non_snake_case)]
#[repr(C)]
struct MibTcp6TableOwnerPid {
    dwNumEntries: u32,
    table: [MibTcp6RowOwnerPid; 1],
}

// IPv6 UDP structures
#[allow(non_snake_case)]
#[repr(C)]
struct MibUdp6RowOwnerPid {
    ucLocalAddr: [u8; 16],
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    dwOwningPid: u32,
}

#[allow(non_snake_case)]
#[repr(C)]
struct MibUdp6TableOwnerPid {
    dwNumEntries: u32,
    table: [MibUdp6RowOwnerPid; 1],
}

// Open process and resolve name
fn get_process_name_for_pid(pid: u32) -> String {
    if pid == 0 || pid == 4 {
        return "System".to_string();
    }
    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if handle != std::ptr::null_mut() {
            let mut buffer = [0u16; 512];
            let mut size = buffer.len() as u32;
            let success: BOOL = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
            CloseHandle(handle);
            if success != 0 {
                let path = String::from_utf16_lossy(&buffer[..size as usize]);
                if let Some(filename) = path.split('\\').last() {
                    return filename.to_string();
                }
                return path;
            }
        }
    }
    format!("PID_{}", pid)
}

// Main packet process thread runner (synchronously opens handle, asynchronously processes)
pub fn start_windivert_loop(state: Arc<EngineState>, app: AppHandle) -> Result<(), String> {
    let filter = "(outbound or inbound) and (tcp or udp) and !impostor";
    let handle = match WinDivert::<NetworkLayer>::network(filter, 0, WinDivertFlags::default()) {
        Ok(h) => h,
        Err(e) => {
            return Err(format!("Не удалось запустить драйвер WinDivert (требуются права администратора): {:?}", e));
        }
    };

    let running = state.running.clone();
    let state_clone = state.clone();
    let app_clone = app.clone();
    
    // Run packet capture synchronously on the blocking thread to prevent lifetime/borrowing issues
    tokio::task::spawn_blocking(move || {
        let mut packet_buffer = vec![0u8; 65535];
        
        while running.load(Ordering::Relaxed) {
            match handle.recv(Some(&mut packet_buffer)) {
                Ok(mut packet) => {
                    // Process the packet
                    if let Err(e) = process_diverted_packet_sync(&mut packet, state_clone.clone(), app_clone.clone()) {
                        eprintln!("Error processing packet: {:?}", e);
                    }
                    
                    // Re-inject the packet (modified or unmodified)
                    if let Err(e) = handle.send(&packet) {
                        eprintln!("WinDivert send error: {:?}", e);
                    }
                }
                Err(e) => {
                    eprintln!("WinDivert recv error: {:?}", e);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    });

    Ok(())
}

fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 127 ||
            octets[0] == 10 ||
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            (octets[0] == 192 && octets[1] == 168) ||
            (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            ipv6.is_loopback() ||
            (segments[0] & 0xFFC0) == 0xFE80 ||
            (segments[0] & 0xFE00) == 0xFC00
        }
    }
}

// Parse and manipulate diverted packets (runs in blocking thread)
fn process_diverted_packet_sync(
    packet: &mut WinDivertPacket<'_, NetworkLayer>,
    state: Arc<EngineState>,
    app: AppHandle
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Get raw packet data slice from the data field
    let packet_data: &mut [u8] = packet.data.to_mut();
    
    if packet_data.len() < 20 {
        return Ok(());
    }
    
    let ip_version = packet_data[0] >> 4;
    let proto;
    let src_ip: IpAddr;
    let dest_ip: IpAddr;
    let header_len;
    
    if ip_version == 4 {
        header_len = ((packet_data[0] & 0x0F) as usize) * 4;
        proto = packet_data[9];
        
        let src_bytes = [packet_data[12], packet_data[13], packet_data[14], packet_data[15]];
        let dest_bytes = [packet_data[16], packet_data[17], packet_data[18], packet_data[19]];
        
        src_ip = IpAddr::V4(src_bytes.into());
        dest_ip = IpAddr::V4(dest_bytes.into());
    } else if ip_version == 6 && packet_data.len() >= 40 {
        header_len = 40;
        proto = packet_data[6];
        
        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&packet_data[8..24]);
        let mut dest_bytes = [0u8; 16];
        dest_bytes.copy_from_slice(&packet_data[24..40]);
        
        src_ip = IpAddr::V6(src_bytes.into());
        dest_ip = IpAddr::V6(dest_bytes.into());
    } else {
        return Ok(());
    }
    
    let is_tcp = proto == 6;
    let is_udp = proto == 17;
    
    if !is_tcp && !is_udp {
        return Ok(());
    }
    
    let src_port_offset = header_len;
    let dest_port_offset = header_len + 2;
    
    if packet_data.len() < src_port_offset + 4 {
        return Ok(());
    }
    
    let src_port = u16::from_be_bytes([packet_data[src_port_offset], packet_data[src_port_offset + 1]]);
    let dest_port = u16::from_be_bytes([packet_data[dest_port_offset], packet_data[dest_port_offset + 1]]);
    
    let local_relay_port: u16 = if is_tcp { 34010 } else { 34011 };

    // --- REVERSE NAT FOR INBOUND PACKETS FROM OUR RELAY ---
    if src_port == local_relay_port {
        let mapping = {
            let redirect_table = state.redirect_table.blocking_lock();
            redirect_table.get(&dest_port).cloned()
        };
        
        if let Some((orig_dest_addr, _proxy_id)) = mapping {
            // Set impostor to true so this packet is ignored by WinDivert after reinjection
            packet.address.set_impostor(true);
            
            // Rewrite Source IP to orig_dest_addr.ip()
            match orig_dest_addr.ip() {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    packet_data[12] = octets[0];
                    packet_data[13] = octets[1];
                    packet_data[14] = octets[2];
                    packet_data[15] = octets[3];
                }
                IpAddr::V6(ipv6) => {
                    let octets = ipv6.octets();
                    packet_data[8..24].copy_from_slice(&octets);
                }
            }
            // Rewrite Source Port to orig_dest_addr.port()
            let port_bytes = orig_dest_addr.port().to_be_bytes();
            packet_data[src_port_offset] = port_bytes[0];
            packet_data[src_port_offset + 1] = port_bytes[1];
            
            // Recalculate checksums
            unsafe {
                windivert_sys::WinDivertHelperCalcChecksums(
                    packet_data.as_mut_ptr() as *mut std::ffi::c_void,
                    packet_data.len() as u32,
                    std::ptr::null_mut(),
                    windivert_sys::ChecksumFlags::new(),
                );
            }
            
            return Ok(());
        }
    }
    
    // --- PREVENT INFINITE LOOP FOR RELAY TRAFFIC ---
    if dest_port == local_relay_port {
        return Ok(());
    }

    let is_inbound = !packet.address.outbound();
    if is_inbound {
        // Best-effort: try to resolve process for inbound packets and accumulate bytes_received
        let (pid, process_name) = resolve_process_for_port_sync(dest_port, is_tcp, &state);
        if pid > 0 && process_name != "Unknown" {
            let packet_len = packet_data.len() as u64;
            let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
            let mut stats = state.traffic_stats.lock().unwrap_or_else(|e| e.into_inner());
            let entry = stats.entry(process_name).or_insert((0, 0, current_time));
            entry.1 += packet_len;
            entry.2 = current_time;
        }
        return Ok(());
    }

    // 2. Resolve process name (sync version)
    let (pid, process_name) = resolve_process_for_port_sync(src_port, is_tcp, &state);
    
    let process_lower = process_name.to_lowercase();
    if process_name == "Unknown" || process_lower.contains("appproxybridge") || process_lower.contains("proxier") {
        return Ok(());
    }
    
    
    // 3. Match rules
    let mut matching_action = RuleAction::Direct;
    let mut matched_proxy_id: Option<String> = None;
    
    {
        let rules = state.rules.blocking_lock();
        for rule in rules.iter() {
            let is_match = if rule.process_name.starts_with('*') {
                let suffix = &rule.process_name[1..];
                process_name.to_lowercase().ends_with(&suffix.to_lowercase())
            } else {
                rule.process_name.to_lowercase() == process_name.to_lowercase()
            };
            
            if is_match {
                matching_action = rule.action.clone();
                matched_proxy_id = rule.proxy_id.clone();
                break;
            }
        }
    }
    
    // DNS Routing override: if packet is UDP port 53 and DNS proxy is active
    if is_udp && dest_port == 53 {
        if state.proxy_dns.load(Ordering::Relaxed) {
            matching_action = RuleAction::Proxy;
        } else {
            matching_action = RuleAction::Direct;
        }
    }
    
    // Local / Intranet Bypass override
    if state.bypass_local.load(Ordering::Relaxed) && is_local_ip(dest_ip) {
        matching_action = RuleAction::Direct;
    }
    
    let connection_id = format!("{}:{}-{}:{}", process_name, src_port, dest_ip, dest_port);
    
    let connection_event = ConnectionInfo {
        id: connection_id.clone(),
        pid,
        process_name: process_name.clone(),
        protocol: if is_tcp { "TCP".to_string() } else { "UDP".to_string() },
        source_addr: format!("{}:{}", src_ip, src_port),
        original_dest: format!("{}:{}", dest_ip, dest_port),
        action: format!("{:?}", matching_action),
        bytes_sent: packet_data.len() as u64,
        bytes_received: 0,
        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64,
        status: "Active".to_string(),
    };
    
    // Accumulate bytes_sent for this process in the global traffic stats
    {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let mut stats = state.traffic_stats.lock().unwrap_or_else(|e| e.into_inner());
        let entry = stats.entry(process_name.clone()).or_insert((0, 0, current_time));
        entry.0 += packet_data.len() as u64;
        entry.2 = current_time;
    }

    // 4. Execute matched action
    match matching_action {
        RuleAction::Block => {
            let mut conn_info = connection_event.clone();
            conn_info.status = "Blocked".to_string();
            let _ = state.event_sender.send(conn_info.clone());
            let _ = app.emit("connection-event", conn_info);
            return Err("Packet Blocked".into()); // Skip reinjection
        }
        RuleAction::Direct => {
            let _ = state.event_sender.send(connection_event.clone());
            let _ = app.emit("connection-event", connection_event);
        }
        RuleAction::Proxy => {
            // Set impostor to true so this packet is ignored by WinDivert after reinjection
            packet.address.set_impostor(true);
            
            let local_relay_port: u16 = if is_tcp { 34010 } else { 34011 };
            
            // Resolve final proxy config matching matched_proxy_id or falling back to primary proxy
            let proxy_id = {
                let config = state.config.blocking_lock();
                let lookup_id = matched_proxy_id.unwrap_or_default();
                if config.iter().any(|p| p.id == lookup_id) {
                    lookup_id
                } else if let Some(primary) = config.iter().find(|p| p.is_primary) {
                    primary.id.clone()
                } else if let Some(first) = config.first() {
                    first.id.clone()
                } else {
                    "default".to_string()
                }
            };
            
            // Save mapping src_port -> (original_destination, proxy_id)
            {
                let mut redirect_table = state.redirect_table.blocking_lock();
                redirect_table.insert(src_port, (SocketAddr::new(dest_ip, dest_port), proxy_id));
            }
            
            // Rewrite destination address
            match dest_ip {
                IpAddr::V4(_) => {
                    packet_data[16] = 127;
                    packet_data[17] = 0;
                    packet_data[18] = 0;
                    packet_data[19] = 1;
                    
                    let port_bytes = local_relay_port.to_be_bytes();
                    packet_data[dest_port_offset] = port_bytes[0];
                    packet_data[dest_port_offset + 1] = port_bytes[1];
                }
                IpAddr::V6(_) => {
                    packet_data[24..40].copy_from_slice(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
                    let port_bytes = local_relay_port.to_be_bytes();
                    packet_data[dest_port_offset] = port_bytes[0];
                    packet_data[dest_port_offset + 1] = port_bytes[1];
                }
            };
            
            // Recalculate checksums after modifying packet headers
            unsafe {
                windivert_sys::WinDivertHelperCalcChecksums(
                    packet_data.as_mut_ptr() as *mut std::ffi::c_void,
                    packet_data.len() as u32,
                    std::ptr::null_mut(),
                    windivert_sys::ChecksumFlags::new(),
                );
            }
            
            let _ = state.event_sender.send(connection_event.clone());
            let _ = app.emit("connection-event", connection_event);
        }
    }
    
    
    Ok(())
}

pub fn get_active_system_connections(state: &EngineState) -> Vec<ConnectionInfo> {
    let mut connections = Vec::new();
    
    // 1. Fetch TCP Table
    unsafe {
        let mut size = 0;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        let mut buffer = vec![0u8; size as usize];
        if GetExtendedTcpTable(buffer.as_mut_ptr() as *mut _, &mut size, FALSE, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
            let table_ptr = buffer.as_ptr() as *const MibTcpTableOwnerPid;
            let num_entries = (*table_ptr).dwNumEntries as usize;
            let entries = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), num_entries);
            for entry in entries {
                let pid = entry.dwOwningPid;
                if pid == 0 || pid == 4 { continue; } // Skip idle / system
                
                let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);
                let remote_port = u16::from_be((entry.dwRemotePort & 0xFFFF) as u16);
                
                // Format IPs
                let local_ip = std::net::Ipv4Addr::from(entry.dwLocalAddr.to_be());
                let remote_ip = std::net::Ipv4Addr::from(entry.dwRemoteAddr.to_be());
                
                // Ignore loopback and unspecified remote IPs
                if local_ip.is_loopback() || remote_ip.is_loopback() || remote_ip.is_unspecified() {
                    continue;
                }
                
                let process_name = get_process_name_for_pid(pid);
                if process_name.starts_with("PID_") { continue; } // ignore unknown PIDs
                
                connections.push(ConnectionInfo {
                    id: format!("{}:{}-{}:{}", process_name, local_port, remote_ip, remote_port),
                    pid,
                    process_name,
                    protocol: "TCP".to_string(),
                    source_addr: format!("{}:{}", local_ip, local_port),
                    original_dest: format!("{}:{}", remote_ip, remote_port),
                    action: "Direct".to_string(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    status: "Active".to_string(),
                });
            }
        }
    }
    // 2. Fetch IPv6 TCP Table (for modern apps like Telegram that prefer IPv6)
    unsafe {
        let mut size = 0;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            if GetExtendedTcpTable(buffer.as_mut_ptr() as *mut _, &mut size, FALSE, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
                let table_ptr = buffer.as_ptr() as *const MibTcp6TableOwnerPid;
                let num_entries = (*table_ptr).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), num_entries);
                for entry in entries {
                    let pid = entry.dwOwningPid;
                    if pid == 0 || pid == 4 { continue; }
                    
                    let local_port = (entry.dwLocalPort & 0xFFFF) as u16;
                    let local_port = u16::from_be(local_port);
                    let remote_port = (entry.dwRemotePort & 0xFFFF) as u16;
                    let remote_port = u16::from_be(remote_port);
                    
                    let local_ip = std::net::Ipv6Addr::from(entry.ucLocalAddr);
                    let remote_ip = std::net::Ipv6Addr::from(entry.ucRemoteAddr);
                    
                    // Skip loopback and unspecified
                    if local_ip.is_loopback() || remote_ip.is_loopback() || remote_ip.is_unspecified() {
                        continue;
                    }
                    
                    let process_name = get_process_name_for_pid(pid);
                    if process_name.starts_with("PID_") { continue; }
                    
                    // Format IPv6 — use compact representation for display
                    let local_display = format!("[{}]:{}", local_ip, local_port);
                    let remote_display = format!("[{}]:{}", remote_ip, remote_port);
                    
                    connections.push(ConnectionInfo {
                        id: format!("{}:{}-{}:{}", process_name, local_port, remote_ip, remote_port),
                        pid,
                        process_name,
                        protocol: "TCP".to_string(),
                        source_addr: local_display,
                        original_dest: remote_display,
                        action: "Direct".to_string(),
                        bytes_sent: 0,
                        bytes_received: 0,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64,
                        status: "Active".to_string(),
                    });
                }
            }
        }
    }
    // 3. Fetch UDP IPv4 Table
    unsafe {
        let mut size = 0;
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);
        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            if GetExtendedUdpTable(buffer.as_mut_ptr() as *mut _, &mut size, FALSE, AF_INET as u32, UDP_TABLE_OWNER_PID, 0) == 0 {
                let table_ptr = buffer.as_ptr() as *const MibUdpTableOwnerPid;
                let num_entries = (*table_ptr).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), num_entries);
                for entry in entries {
                    let pid = entry.dwOwningPid;
                    if pid == 0 || pid == 4 { continue; }
                    
                    let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);
                    let local_ip = std::net::Ipv4Addr::from(entry.dwLocalAddr.to_be());
                    
                    if local_ip.is_loopback() { continue; }
                    
                    let process_name = get_process_name_for_pid(pid);
                    if process_name.starts_with("PID_") { continue; }
                    
                    connections.push(ConnectionInfo {
                        id: format!("{}:{}-UDP:{}", process_name, local_port, local_ip),
                        pid,
                        process_name,
                        protocol: "UDP".to_string(),
                        source_addr: format!("{}:{}", local_ip, local_port),
                        original_dest: "UDP Endpoint".to_string(),
                        action: "Direct".to_string(),
                        bytes_sent: 0,
                        bytes_received: 0,
                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                        status: "Active".to_string(),
                    });
                }
            }
        }
    }

    // 4. Fetch UDP IPv6 Table
    unsafe {
        let mut size = 0;
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, FALSE, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0);
        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            if GetExtendedUdpTable(buffer.as_mut_ptr() as *mut _, &mut size, FALSE, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0) == 0 {
                let table_ptr = buffer.as_ptr() as *const MibUdp6TableOwnerPid;
                let num_entries = (*table_ptr).dwNumEntries as usize;
                let entries = std::slice::from_raw_parts((*table_ptr).table.as_ptr(), num_entries);
                for entry in entries {
                    let pid = entry.dwOwningPid;
                    if pid == 0 || pid == 4 { continue; }
                    
                    let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);
                    let local_ip = std::net::Ipv6Addr::from(entry.ucLocalAddr);
                    
                    if local_ip.is_loopback() { continue; }
                    
                    let process_name = get_process_name_for_pid(pid);
                    if process_name.starts_with("PID_") { continue; }
                    
                    connections.push(ConnectionInfo {
                        id: format!("{}:{}-UDP6:[{}]", process_name, local_port, local_ip),
                        pid,
                        process_name,
                        protocol: "UDP".to_string(),
                        source_addr: format!("[{}]:{}", local_ip, local_port),
                        original_dest: "UDP Endpoint".to_string(),
                        action: "Direct".to_string(),
                        bytes_sent: 0,
                        bytes_received: 0,
                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                        status: "Active".to_string(),
                    });
                }
            }
        }
    }
    
    // Touch all discovered active processes in the traffic stats to ensure they remain alive in UI
    if !connections.is_empty() {
        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let mut stats = state.traffic_stats.lock().unwrap_or_else(|e| e.into_inner());
        for conn in &connections {
            let entry = stats.entry(conn.process_name.clone()).or_insert((0, 0, current_time));
            entry.2 = current_time;
        }
    }
    
    // Sort and limit
    connections.sort_by(|a, b| a.process_name.cmp(&b.process_name));
    connections.truncate(1000);
    connections
}
