mod proxy_core;
mod relay;
mod database;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::path::PathBuf;
use tauri::{State, AppHandle, Manager};
use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton};
use tauri::menu::{Menu, MenuItem};
use proxy_core::{EngineState, ProxyConfig, Rule, KnownProcess, LogEntry};

// Thread-safe wrapper for the SQLite database path
struct DbPath(PathBuf);

// Response structure containing all loaded states
#[derive(serde::Serialize)]
struct SavedData {
    proxies: Vec<ProxyConfig>,
    rules: Vec<Rule>,
    proxy_dns: bool,
    bypass_local: bool,
    autostart: bool,
    minimize_to_tray: bool,
    start_minimized: bool,
}

// Tauri Commands

#[tauri::command]
async fn is_engine_running(state: State<'_, Arc<EngineState>>) -> Result<bool, String> {
    Ok(state.running.load(Ordering::Relaxed))
}

#[tauri::command]
async fn get_active_connections(
    state: State<'_, Arc<EngineState>>,
    db_path: State<'_, DbPath>,
) -> Result<Vec<proxy_core::ConnectionInfo>, String> {
    let connections = proxy_core::get_active_system_connections(&state);
    
    // Auto-discover new processes and add them to known_processes
    let process_names: Vec<String> = connections.iter()
        .map(|c| c.process_name.clone())
        .filter(|n| {
            let lower = n.to_lowercase();
            !lower.contains("appproxybridge") && !lower.contains("proxier") && n != "Unknown"
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    
    if !process_names.is_empty() {
        if let Ok(conn) = database::init_db(db_path.0.clone()) {
            let _ = database::upsert_new_processes(&conn, &process_names);
        }
    }
    
    Ok(connections)
}

#[derive(serde::Serialize)]
struct ProcessTrafficEntry {
    process_name: String,
    bytes_sent: u64,
    bytes_received: u64,
    last_activity: u64,
}

#[tauri::command]
async fn get_traffic_stats(state: State<'_, Arc<EngineState>>) -> Result<Vec<ProcessTrafficEntry>, String> {
    let snapshot = proxy_core::get_traffic_stats_snapshot(&state);
    let entries: Vec<ProcessTrafficEntry> = snapshot.into_iter().map(|(name, (sent, recv, last_activity))| {
        ProcessTrafficEntry {
            process_name: name,
            bytes_sent: sent,
            bytes_received: recv,
            last_activity,
        }
    }).collect();
    Ok(entries)
}

#[tauri::command]
async fn get_saved_data(db_path: State<'_, DbPath>) -> Result<SavedData, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
    
    let proxies = database::load_proxies(&conn)
        .map_err(|e| format!("DB Load Proxies Error: {:?}", e))?;
        
    let rules = database::load_rules(&conn)
        .map_err(|e| format!("DB Load Rules Error: {:?}", e))?;
        
    let (proxy_dns, bypass_local, autostart, minimize_to_tray, start_minimized) = database::load_settings(&conn)
        .map_err(|e| format!("DB Load Settings Error: {:?}", e))?;
        
    Ok(SavedData {
        proxies,
        rules,
        proxy_dns,
        bypass_local,
        autostart,
        minimize_to_tray,
        start_minimized,
    })
}

#[tauri::command]
async fn save_proxy(
    proxy: ProxyConfig,
    db_path: State<'_, DbPath>,
    state: State<'_, Arc<EngineState>>,
) -> Result<String, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
        
    database::save_proxy(&conn, &proxy)
        .map_err(|e| format!("DB Save Proxy Error: {:?}", e))?;
        
    // Reload into memory
    let proxies = database::load_proxies(&conn)
        .map_err(|e| format!("DB Reload Error: {:?}", e))?;
        
    let mut cfg = state.config.lock().await;
    *cfg = proxies;
    
    Ok("Proxy saved to database".to_string())
}

#[tauri::command]
async fn delete_proxy(
    id: String,
    db_path: State<'_, DbPath>,
    state: State<'_, Arc<EngineState>>,
) -> Result<String, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
        
    database::delete_proxy(&conn, &id)
        .map_err(|e| format!("DB Delete Proxy Error: {:?}", e))?;
        
    // Reload into memory
    let proxies = database::load_proxies(&conn)
        .map_err(|e| format!("DB Reload Error: {:?}", e))?;
        
    let mut cfg = state.config.lock().await;
    *cfg = proxies;
    
    Ok("Proxy deleted from database".to_string())
}

#[tauri::command]
async fn start_engine(
    config: Vec<ProxyConfig>,
    rules: Vec<Rule>,
    bypass_local: bool,
    proxy_dns: bool,
    state: State<'_, Arc<EngineState>>,
    app_handle: AppHandle
) -> Result<String, String> {
    if state.running.load(Ordering::Relaxed) {
        return Err("Engine is already running".to_string());
    }
    
    // Save config and rules in memory state
    {
        let mut cfg = state.config.lock().await;
        *cfg = config;
    }
    {
        let mut rls = state.rules.lock().await;
        *rls = rules;
    }
    
    state.bypass_local.store(bypass_local, Ordering::Relaxed);
    state.proxy_dns.store(proxy_dns, Ordering::Relaxed);
    
    // Set running to true
    state.running.store(true, Ordering::Relaxed);
    
    // Resolve DB path for logging in relay/windivert threads
    let db_path_val = app_handle.state::<DbPath>().0.clone();
    
    // Start WinDivert packet capture loop (synchronous handle initialization)
    if let Err(e) = proxy_core::start_windivert_loop(state.inner().clone(), app_handle.clone(), db_path_val.clone()) {
        state.running.store(false, Ordering::Relaxed);
        return Err(e);
    }
    
    // Start TCP/UDP Relay servers
    let state_tcp = state.inner().clone();
    let app_tcp = app_handle.clone();
    let db_tcp = db_path_val.clone();
    tokio::spawn(async move {
        relay::start_tcp_relay(state_tcp, app_tcp, db_tcp).await;
    });

    let state_udp = state.inner().clone();
    let app_udp = app_handle.clone();
    let db_udp = db_path_val.clone();
    tokio::spawn(async move {
        relay::start_udp_relay(state_udp, app_udp, db_udp).await;
    });
    
    Ok("Engine started successfully".to_string())
}

#[tauri::command]
async fn stop_engine(state: State<'_, Arc<EngineState>>) -> Result<String, String> {
    if !state.running.load(Ordering::Relaxed) {
        return Err("Engine is not running".to_string());
    }
    
    state.running.store(false, Ordering::Relaxed);
    
    // Clear redirect tables and traffic stats
    {
        let mut table = state.redirect_table.lock().await;
        table.clear();
    }
    {
        let mut active = state.active_connections.lock().await;
        active.clear();
    }
    {
        let mut stats = state.traffic_stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.clear();
    }
    
    Ok("Engine stopped".to_string())
}

#[tauri::command]
async fn update_engine_rules(
    rules: Vec<Rule>,
    db_path: State<'_, DbPath>,
    state: State<'_, Arc<EngineState>>,
) -> Result<String, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
        
    database::save_rules(&conn, &rules)
        .map_err(|e| format!("DB Save Rules Error: {:?}", e))?;
        
    let mut rls = state.rules.lock().await;
    *rls = rules;
    Ok("Rules updated successfully".to_string())
}

#[tauri::command]
async fn save_routing_settings(
    proxy_dns: bool,
    bypass_local: bool,
    autostart: bool,
    minimize_to_tray: bool,
    start_minimized: bool,
    db_path: State<'_, DbPath>,
    state: State<'_, Arc<EngineState>>,
) -> Result<String, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
        
    database::save_settings(&conn, proxy_dns, bypass_local, autostart, minimize_to_tray, start_minimized)
        .map_err(|e| format!("DB Save Settings Error: {:?}", e))?;
        
    state.proxy_dns.store(proxy_dns, Ordering::Relaxed);
    state.bypass_local.store(bypass_local, Ordering::Relaxed);
    state.autostart.store(autostart, Ordering::Relaxed);
    state.minimize_to_tray.store(minimize_to_tray, Ordering::Relaxed);
    
    Ok("Routing settings saved".to_string())
}

// ==================== Known Processes Commands ====================

#[tauri::command]
async fn get_known_processes(db_path: State<'_, DbPath>) -> Result<Vec<KnownProcess>, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
    let mut known = database::load_known_processes(&conn)
        .map_err(|e| format!("DB Load Known Processes Error: {:?}", e))?;
        
    let rules = database::load_rules(&conn).unwrap_or_default();
    
    // Dynamically update group_action based on current rules (including wildcard rules)
    for proc in &mut known {
        let mut matched_action = "new";
        let mut matched_proxy_id = None;
        
        for rule in &rules {
            if proxy_core::match_wildcard(&rule.process_name, &proc.process_name) {
                matched_action = match rule.action {
                    proxy_core::RuleAction::Proxy => "proxy",
                    proxy_core::RuleAction::Direct => "direct",
                    proxy_core::RuleAction::Block => "block",
                };
                matched_proxy_id = rule.proxy_id.clone();
                break;
            }
        }
        
        proc.group_action = matched_action.to_string();
        proc.proxy_id = matched_proxy_id;
    }
    
    Ok(known)
}

#[tauri::command]
async fn set_process_group(
    process_name: String,
    group_action: String,
    proxy_id: Option<String>,
    db_path: State<'_, DbPath>,
    state: State<'_, Arc<EngineState>>,
) -> Result<String, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
    
    // Load existing process to preserve created_at
    let existing = database::load_known_processes(&conn)
        .unwrap_or_default()
        .into_iter()
        .find(|p| p.process_name.to_lowercase() == process_name.to_lowercase());
    
    let created_at = existing.map(|e| e.created_at).unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    });
    
    // Save to known_processes table
    let proc = KnownProcess {
        process_name: process_name.clone(),
        group_action: group_action.clone(),
        proxy_id: proxy_id.clone(),
        created_at,
    };
    database::save_known_process(&conn, &proc)
        .map_err(|e| format!("DB Save Known Process Error: {:?}", e))?;
    
    // Synchronize with rules table and in-memory engine rules
    let mut current_rules = database::load_rules(&conn).unwrap_or_default();
    
    // Remove existing rule for this process
    current_rules.retain(|r| r.process_name.to_lowercase() != process_name.to_lowercase());
    
    // Create new rule based on group_action
    match group_action.as_str() {
        "proxy" => {
            current_rules.push(Rule {
                id: format!("auto-{}", process_name.to_lowercase().replace('.', "-")),
                process_name: process_name.clone(),
                action: proxy_core::RuleAction::Proxy,
                proxy_id: proxy_id,
            });
        }
        "block" => {
            current_rules.push(Rule {
                id: format!("auto-{}", process_name.to_lowercase().replace('.', "-")),
                process_name: process_name.clone(),
                action: proxy_core::RuleAction::Block,
                proxy_id: None,
            });
        }
        "direct" => {
            // Direct = rule with Direct action (explicitly marked, not just absence of rule)
            current_rules.push(Rule {
                id: format!("auto-{}", process_name.to_lowercase().replace('.', "-")),
                process_name: process_name.clone(),
                action: proxy_core::RuleAction::Direct,
                proxy_id: None,
            });
        }
        _ => {
            // "new" — no rule needed, remove any existing
        }
    }
    
    // Save rules to DB
    database::save_rules(&conn, &current_rules)
        .map_err(|e| format!("DB Save Rules Error: {:?}", e))?;
    
    // Update in-memory engine rules
    let mut rls = state.rules.lock().await;
    *rls = current_rules;
    
    Ok(format!("Process {} set to group {}", process_name, group_action))
}

// ==================== Application Logs Commands ====================

#[tauri::command]
async fn get_app_logs(db_path: State<'_, DbPath>) -> Result<Vec<LogEntry>, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
    database::load_logs(&conn)
        .map_err(|e| format!("DB Load Logs Error: {:?}", e))
}

#[tauri::command]
async fn clear_app_logs(db_path: State<'_, DbPath>) -> Result<String, String> {
    let conn = database::init_db(db_path.0.clone())
        .map_err(|e| format!("DB Error: {:?}", e))?;
    database::clear_logs(&conn)
        .map_err(|e| format!("DB Clear Logs Error: {:?}", e))?;
    Ok("Logs cleared".to_string())
}

#[tauri::command]
async fn restart_app(app_handle: AppHandle) {
    app_handle.restart();
}

#[cfg(target_os = "windows")]
fn set_high_priority() {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, HIGH_PRIORITY_CLASS};
    unsafe {
        let handle = GetCurrentProcess();
        if SetPriorityClass(handle, HIGH_PRIORITY_CLASS) == 0 {
            eprintln!("Failed to set process priority class to High");
        } else {
            eprintln!("Process priority class set to High");
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn set_high_priority() {}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Set current directory to executable directory to locate WinDivert.dll/WinDivert64.sys correctly (critical for autostart)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let _ = std::env::set_current_dir(exe_dir);
        }
    }

    // Set high process priority class to start early and prioritize processing packet streams
    set_high_priority();

    #[tauri::command]
    async fn write_string_to_file(path: String, content: String) -> Result<(), String> {
        std::fs::write(path, content).map_err(|e| e.to_string())
    }

    #[tauri::command]
    async fn read_string_from_file(path: String) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    }

    // Create global thread-safe state
    let engine_state = Arc::new(EngineState::new());
    let engine_state_clone = engine_state.clone();
    
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(engine_state) // Add to Tauri context
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<Arc<EngineState>>();
                if state.minimize_to_tray.load(Ordering::Relaxed) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(move |app| {
            // Resolve standard application data directory
            let app_data_dir = app.path().app_data_dir().expect("Failed to get app data directory");
            std::fs::create_dir_all(&app_data_dir).ok();
            let db_path = app_data_dir.join("proxier.db");
            
            // Initialize SQLite tables & run migrations
            if let Ok(conn) = database::init_db(db_path.clone()) {
                // Restore settings
                if let Ok((proxy_dns, bypass_local, autostart, minimize_to_tray, start_minimized)) = database::load_settings(&conn) {
                    engine_state_clone.proxy_dns.store(proxy_dns, Ordering::Relaxed);
                    engine_state_clone.bypass_local.store(bypass_local, Ordering::Relaxed);
                    engine_state_clone.autostart.store(autostart, Ordering::Relaxed);
                    engine_state_clone.minimize_to_tray.store(minimize_to_tray, Ordering::Relaxed);
                    
                    if start_minimized {
                        if let Some(window) = app.webview_windows().values().next() {
                            let _ = window.hide();
                        }
                    }

                    // Restore proxies and rules into memory
                    let proxies = database::load_proxies(&conn).unwrap_or_default();
                    let rules = database::load_rules(&conn).unwrap_or_default();
                    if let Ok(mut cfg) = engine_state_clone.config.try_lock() {
                        *cfg = proxies.clone();
                    }
                    if let Ok(mut rls) = engine_state_clone.rules.try_lock() {
                        *rls = rules.clone();
                    }

                    // If autostart is enabled and we have proxies, start the engine immediately (Rust-side, deferred to avoid early setup panics)
                    if autostart && !proxies.is_empty() {
                        let engine_state_clone = engine_state_clone.clone();
                        let app_handle = app.handle().clone();
                        let db_path_clone = db_path.clone();
                        
                        tauri::async_runtime::spawn(async move {
                            // Defer startup slightly to ensure Tauri windows and event loop are fully ready
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            
                            // Re-open DB connection for background logs
                            let conn = match database::init_db(db_path_clone.clone()) {
                                Ok(c) => c,
                                Err(_) => return,
                            };
                            
                            engine_state_clone.running.store(true, Ordering::Relaxed);
                            
                            match proxy_core::start_windivert_loop(engine_state_clone.clone(), app_handle.clone(), db_path_clone.clone()) {
                                Ok(_) => {
                                    // Start TCP/UDP Relay servers
                                    let state_tcp = engine_state_clone.clone();
                                    let app_tcp = app_handle.clone();
                                    let db_tcp = db_path_clone.clone();
                                    tokio::spawn(async move {
                                        relay::start_tcp_relay(state_tcp, app_tcp, db_tcp).await;
                                    });

                                    let state_udp = engine_state_clone.clone();
                                    let app_udp = app_handle.clone();
                                    let db_udp = db_path_clone.clone();
                                    tokio::spawn(async move {
                                        relay::start_udp_relay(state_udp, app_udp, db_udp).await;
                                    });
                                    
                                    let _ = database::insert_log(&conn, "info", "Core", "Движок автозапущен при старте приложения (Rust)", None);
                                }
                                Err(e) => {
                                    engine_state_clone.running.store(false, Ordering::Relaxed);
                                    let _ = database::insert_log(&conn, "error", "Core", &format!("Ошибка автозапуска движка в Rust: {}", e), None);
                                }
                            }
                        });
                    }
                }
            }
            
            // Build system tray
            let tray_menu = Menu::with_items(
                app,
                &[
                    &MenuItem::with_id(app, "show", "Показать AppProxyBridge", true, None::<&str>)?,
                    &MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?,
                ],
            )?;

            let icon = match app.default_window_icon() {
                Some(ic) => ic.clone(),
                None => {
                    let icon_bytes = include_bytes!("../icons/128x128.png");
                    tauri::image::Image::from_bytes(icon_bytes)
                        .unwrap_or_else(|_| tauri::image::Image::new(&[], 0, 0))
                }
            };

            let _tray = TrayIconBuilder::new()
                .icon(icon)
                .menu(&tray_menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.webview_windows().values().next() {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.webview_windows().values().next() {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;
            
            app.manage(DbPath(db_path));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            is_engine_running,
            get_active_connections,
            get_traffic_stats,
            get_saved_data,
            save_proxy,
            delete_proxy,
            start_engine,
            stop_engine,
            update_engine_rules,
            save_routing_settings,
            get_known_processes,
            set_process_group,
            get_app_logs,
            clear_app_logs,
            restart_app,
            write_string_to_file,
            read_string_from_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
