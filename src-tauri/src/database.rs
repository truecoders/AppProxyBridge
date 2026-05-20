use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use rusqlite::{Connection, Result};
use crate::proxy_core::{ProxyConfig, Rule, KnownProcess, LogEntry};

// Initialize the database at the user app data directory
pub fn init_db(db_path: PathBuf) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    
    // Create Proxies table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS proxies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            proxy_type TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            username TEXT,
            password TEXT,
            is_primary INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )?;

    // Create Rules table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            process_name TEXT NOT NULL,
            action TEXT NOT NULL,
            proxy_id TEXT
        )",
        [],
    )?;

    // Create Settings table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    // Create Known Processes table (process grouping persistence)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS known_processes (
            process_name TEXT PRIMARY KEY,
            group_action TEXT NOT NULL DEFAULT 'new',
            proxy_id TEXT,
            created_at INTEGER NOT NULL
        )",
        [],
    )?;

    // Create Application Logs table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS app_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            level TEXT NOT NULL,
            source TEXT NOT NULL,
            message TEXT NOT NULL
        )",
        [],
    )?;

    // Set default settings if they do not exist
    {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM settings WHERE key = ?")?;
        
        let dns_exists: i64 = stmt.query_row(["proxy_dns"], |row| row.get(0))?;
        if dns_exists == 0 {
            conn.execute("INSERT INTO settings (key, value) VALUES ('proxy_dns', 'true')", [])?;
        }

        let bypass_exists: i64 = stmt.query_row(["bypass_local"], |row| row.get(0))?;
        if bypass_exists == 0 {
            conn.execute("INSERT INTO settings (key, value) VALUES ('bypass_local', 'false')", [])?;
        }

        let autostart_exists: i64 = stmt.query_row(["autostart"], |row| row.get(0))?;
        if autostart_exists == 0 {
            conn.execute("INSERT INTO settings (key, value) VALUES ('autostart', 'true')", [])?;
            let _ = set_autostart(true);
        }

        let tray_exists: i64 = stmt.query_row(["minimize_to_tray"], |row| row.get(0))?;
        if tray_exists == 0 {
            conn.execute("INSERT INTO settings (key, value) VALUES ('minimize_to_tray', 'true')", [])?;
        }

        let start_minimized_exists: i64 = stmt.query_row(["start_minimized"], |row| row.get(0))?;
        if start_minimized_exists == 0 {
            conn.execute("INSERT INTO settings (key, value) VALUES ('start_minimized', 'false')", [])?;
        }
    }

    Ok(conn)
}

// Helper to set/remove Windows autostart using Task Scheduler (necessary to bypass UAC block for elevated apps)
pub fn set_autostart(enabled: bool) -> Result<(), rusqlite::Error> {
    let current_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return Ok(()),
    };
    let exe_path = current_exe.to_string_lossy().to_string();

    #[cfg(target_os = "windows")]
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // 1. Clean up legacy registry keys that are blocked by UAC anyway
    let mut reg_cmd = std::process::Command::new("reg");
    #[cfg(target_os = "windows")]
    reg_cmd.creation_flags(CREATE_NO_WINDOW);
    let _ = reg_cmd
        .args(&[
            "delete",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "/v",
            "Proxier",
            "/f"
        ])
        .status();

    let mut reg_cmd2 = std::process::Command::new("reg");
    #[cfg(target_os = "windows")]
    reg_cmd2.creation_flags(CREATE_NO_WINDOW);
    let _ = reg_cmd2
        .args(&[
            "delete",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "/v",
            "AppProxyBridge",
            "/f"
        ])
        .status();

    // 2. Manage Task Scheduler task
    if enabled {
        let mut sch_cmd = std::process::Command::new("schtasks");
        #[cfg(target_os = "windows")]
        sch_cmd.creation_flags(CREATE_NO_WINDOW);
        let _ = sch_cmd
            .args(&[
                "/create",
                "/tn",
                "AppProxyBridge",
                "/tr",
                &format!("\"{}\"", exe_path),
                "/sc",
                "onlogon",
                "/rl",
                "highest",
                "/f"
            ])
            .status();
    } else {
        let mut sch_cmd = std::process::Command::new("schtasks");
        #[cfg(target_os = "windows")]
        sch_cmd.creation_flags(CREATE_NO_WINDOW);
        let _ = sch_cmd
            .args(&[
                "/delete",
                "/tn",
                "AppProxyBridge",
                "/f"
            ])
            .status();
    }
    Ok(())
}

// Load all saved proxies
pub fn load_proxies(conn: &Connection) -> Result<Vec<ProxyConfig>> {
    let mut stmt = conn.prepare("SELECT id, name, proxy_type, host, port, username, password, is_primary FROM proxies")?;
    let proxy_iter = stmt.query_map([], |row| {
        let is_primary_int: i32 = row.get(7)?;
        Ok(ProxyConfig {
            id: row.get(0)?,
            name: row.get(1)?,
            proxy_type: row.get(2)?,
            host: row.get(3)?,
            port: row.get::<_, i32>(4)? as u16,
            username: row.get(5)?,
            password: row.get(6)?,
            is_primary: is_primary_int != 0,
        })
    })?;

    let mut list = Vec::new();
    for p in proxy_iter {
        list.push(p?);
    }
    Ok(list)
}

// Insert or replace a proxy
pub fn save_proxy(conn: &Connection, proxy: &ProxyConfig) -> Result<()> {
    // If saving a primary proxy, set all other proxies' is_primary to 0
    if proxy.is_primary {
        conn.execute("UPDATE proxies SET is_primary = 0", [])?;
    }
    
    conn.execute(
        "INSERT OR REPLACE INTO proxies (id, name, proxy_type, host, port, username, password, is_primary)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        (
            &proxy.id,
            &proxy.name,
            &proxy.proxy_type,
            &proxy.host,
            proxy.port as i32,
            &proxy.username,
            &proxy.password,
            if proxy.is_primary { 1 } else { 0 },
        ),
    )?;
    Ok(())
}

// Delete a proxy by ID
pub fn delete_proxy(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM proxies WHERE id = ?", [id])?;
    Ok(())
}

// Load all saved rules
pub fn load_rules(conn: &Connection) -> Result<Vec<Rule>> {
    let mut stmt = conn.prepare("SELECT id, process_name, action, proxy_id FROM rules")?;
    let rule_iter = stmt.query_map([], |row| {
        let action_str: String = row.get(2)?;
        let action = match action_str.as_str() {
            "Block" => crate::proxy_core::RuleAction::Block,
            "Direct" => crate::proxy_core::RuleAction::Direct,
            _ => crate::proxy_core::RuleAction::Proxy,
        };
        Ok(Rule {
            id: row.get(0)?,
            process_name: row.get(1)?,
            action,
            proxy_id: row.get(3)?,
        })
    })?;

    let mut list = Vec::new();
    for r in rule_iter {
        list.push(r?);
    }
    Ok(list)
}

// Batch save rules
pub fn save_rules(conn: &Connection, rules: &[Rule]) -> Result<()> {
    conn.execute("DELETE FROM rules", [])?;
    for rule in rules {
        let action_str = format!("{:?}", rule.action);
        conn.execute(
            "INSERT INTO rules (id, process_name, action, proxy_id) VALUES (?1, ?2, ?3, ?4)",
            (
                &rule.id,
                &rule.process_name,
                &action_str,
                &rule.proxy_id,
            ),
        )?;
    }
    Ok(())
}

// Load DNS, Intranet Bypass, Autostart, and Minimize to Tray flags
pub fn load_settings(conn: &Connection) -> Result<(bool, bool, bool, bool, bool)> {
    let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?")?;
    let proxy_dns_str: String = stmt.query_row(["proxy_dns"], |row| row.get(0)).unwrap_or_else(|_| "true".to_string());
    let bypass_local_str: String = stmt.query_row(["bypass_local"], |row| row.get(0)).unwrap_or_else(|_| "false".to_string());
    let autostart_str: String = stmt.query_row(["autostart"], |row| row.get(0)).unwrap_or_else(|_| "true".to_string());
    let minimize_to_tray_str: String = stmt.query_row(["minimize_to_tray"], |row| row.get(0)).unwrap_or_else(|_| "true".to_string());
    let start_minimized_str: String = stmt.query_row(["start_minimized"], |row| row.get(0)).unwrap_or_else(|_| "false".to_string());

    Ok((
        proxy_dns_str == "true",
        bypass_local_str == "true",
        autostart_str == "true",
        minimize_to_tray_str == "true",
        start_minimized_str == "true"
    ))
}

// Save DNS, Intranet Bypass, Autostart, and Minimize to Tray flags
pub fn save_settings(
    conn: &Connection,
    proxy_dns: bool,
    bypass_local: bool,
    autostart: bool,
    minimize_to_tray: bool,
    start_minimized: bool
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_dns', ?1)",
        [if proxy_dns { "true" } else { "false" }],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('bypass_local', ?1)",
        [if bypass_local { "true" } else { "false" }],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('autostart', ?1)",
        [if autostart { "true" } else { "false" }],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('minimize_to_tray', ?1)",
        [if minimize_to_tray { "true" } else { "false" }],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('start_minimized', ?1)",
        [if start_minimized { "true" } else { "false" }],
    )?;

    // Sync registry
    let _ = set_autostart(autostart);

    Ok(())
}

// ==================== Known Processes ====================

/// Load all known processes from DB
pub fn load_known_processes(conn: &Connection) -> Result<Vec<KnownProcess>> {
    let mut stmt = conn.prepare(
        "SELECT process_name, group_action, proxy_id, created_at FROM known_processes ORDER BY created_at DESC"
    )?;
    let iter = stmt.query_map([], |row| {
        Ok(KnownProcess {
            process_name: row.get(0)?,
            group_action: row.get(1)?,
            proxy_id: row.get(2)?,
            created_at: row.get::<_, i64>(3)? as u64,
        })
    })?;
    let mut list = Vec::new();
    for p in iter {
        list.push(p?);
    }
    Ok(list)
}

/// Upsert a single known process
pub fn save_known_process(conn: &Connection, proc: &KnownProcess) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO known_processes (process_name, group_action, proxy_id, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        (
            &proc.process_name,
            &proc.group_action,
            &proc.proxy_id,
            proc.created_at as i64,
        ),
    )?;
    Ok(())
}

/// Batch upsert new processes (only insert if not exists, preserving existing group_action)
pub fn upsert_new_processes(conn: &Connection, process_names: &[String]) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    for name in process_names {
        conn.execute(
            "INSERT OR IGNORE INTO known_processes (process_name, group_action, proxy_id, created_at)
             VALUES (?1, 'new', NULL, ?2)",
            (&name, now),
        )?;
    }
    Ok(())
}

// ==================== Application Logs ====================

/// Insert a log entry and trim to last 300 entries
pub fn insert_log(conn: &Connection, level: &str, source: &str, message: &str) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    conn.execute(
        "INSERT INTO app_logs (timestamp, level, source, message) VALUES (?1, ?2, ?3, ?4)",
        (now, level, source, message),
    )?;
    // Trim: keep only the last 300 entries
    conn.execute(
        "DELETE FROM app_logs WHERE id NOT IN (SELECT id FROM app_logs ORDER BY id DESC LIMIT 300)",
        [],
    )?;
    Ok(())
}

/// Load last 300 log entries (newest first)
pub fn load_logs(conn: &Connection) -> Result<Vec<LogEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, level, source, message FROM app_logs ORDER BY id DESC LIMIT 300"
    )?;
    let iter = stmt.query_map([], |row| {
        Ok(LogEntry {
            id: row.get(0)?,
            timestamp: row.get::<_, i64>(1)? as u64,
            level: row.get(2)?,
            source: row.get(3)?,
            message: row.get(4)?,
        })
    })?;
    let mut list = Vec::new();
    for l in iter {
        list.push(l?);
    }
    Ok(list)
}

/// Clear all log entries
pub fn clear_logs(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM app_logs", [])?;
    Ok(())
}

