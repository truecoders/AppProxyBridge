mod proxy_core;
mod relay;
mod database;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::path::PathBuf;
use tauri::{State, AppHandle, Manager};
use tauri::tray::{TrayIconBuilder, TrayIconEvent};
use tauri::menu::{Menu, MenuItem};
use proxy_core::{EngineState, ProxyConfig, Rule};

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
async fn get_active_connections(state: State<'_, Arc<EngineState>>) -> Result<Vec<proxy_core::ConnectionInfo>, String> {
    Ok(proxy_core::get_active_system_connections(&state))
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
    
    // Start WinDivert packet capture loop (synchronous handle initialization)
    if let Err(e) = proxy_core::start_windivert_loop(state.inner().clone(), app_handle.clone()) {
        state.running.store(false, Ordering::Relaxed);
        return Err(e);
    }
    
    // Start TCP/UDP Relay servers
    let state_tcp = state.inner().clone();
    let app_tcp = app_handle.clone();
    tokio::spawn(async move {
        relay::start_tcp_relay(state_tcp, app_tcp).await;
    });

    let state_udp = state.inner().clone();
    let app_udp = app_handle.clone();
    tokio::spawn(async move {
        relay::start_udp_relay(state_udp, app_udp).await;
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Create global thread-safe state
    let engine_state = Arc::new(EngineState::new());
    let engine_state_clone = engine_state.clone();
    
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
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
                }
                
                // Restore proxies
                if let Ok(proxies) = database::load_proxies(&conn) {
                    if let Ok(mut cfg) = engine_state_clone.config.try_lock() {
                        *cfg = proxies;
                    }
                }
                
                // Restore rules
                if let Ok(rules) = database::load_rules(&conn) {
                    if let Ok(mut rls) = engine_state_clone.rules.try_lock() {
                        *rls = rules;
                    }
                }
            }
            
            // Build system tray
            let tray_menu = Menu::with_items(
                app,
                &[
                    &MenuItem::with_id(app, "show", "Показать Proxier", true, None::<&str>)?,
                    &MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?,
                ],
            )?;

            if let Some(icon) = app.default_window_icon() {
                let _tray = TrayIconBuilder::new()
                    .icon(icon.clone())
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
                        if let TrayIconEvent::Click { .. } = event {
                            let app = tray.app_handle();
                            if let Some(window) = app.webview_windows().values().next() {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    })
                    .build(app)?;
            }
            
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
            save_routing_settings
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
