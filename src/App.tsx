import { useState, useEffect, useRef, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { check } from "@tauri-apps/plugin-updater";
import {
  AppShell,
  Burger,
  Group,
  NavLink,
  Title,
  Text,
  Button,
  TextInput,
  NumberInput,
  Select,
  Switch,
  Table,
  Badge,
  Paper,
  SimpleGrid,
  ThemeIcon,
  Card,
  ActionIcon,
  Stack,
  ScrollArea,
  Notification,
  Divider,
  Checkbox,
  Tooltip,
  Modal,
  Progress,
  Accordion,
  Tabs,
  SegmentedControl,
  Skeleton,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconDashboard,
  IconShield,
  IconSettings,
  IconPower,
  IconPlus,
  IconTrash,
  IconAlertCircle,
  IconCheck,
  IconActivity,
  IconArrowUpRight,
  IconArrowDownLeft,
  IconStar,
  IconStarFilled,
  IconCopy,
  IconSearch,
  IconRefresh,
  IconTerminal2,
  IconRoute,
  IconLock,
  IconSparkles,
  IconChevronDown,
  IconChevronRight,
  IconClearAll,
  IconHistory,
  IconAdjustments,
} from "@tabler/icons-react";

// Types matching Rust model
interface ConnectionInfo {
  id: string;
  pid: number;
  process_name: string;
  protocol: string;
  source_addr: string;
  original_dest: string;
  action: string;
  bytes_sent: number;
  bytes_received: number;
  timestamp: number;
  status: string;
}

interface ProxyConfig {
  id: string;
  name: string;
  proxy_type: string; // "SOCKS5" or "HTTP"
  host: string;
  port: number;
  username?: string;
  password?: string;
  is_primary: boolean;
}

interface Rule {
  id: string;
  process_name: string;
  action: "Block" | "Direct" | "Proxy";
  proxy_id?: string; // Optional binding to a specific proxy ID
}

interface SavedData {
  proxies: ProxyConfig[];
  rules: Rule[];
  proxy_dns: boolean;
  bypass_local: boolean;
  autostart: boolean;
  minimize_to_tray: boolean;
  start_minimized: boolean;
}

interface KnownProcess {
  process_name: string;
  group_action: "new" | "proxy" | "direct" | "block";
  proxy_id?: string;
  created_at: number;
}

interface LogEntry {
  id: number;
  timestamp: number;
  level: string;
  source: string;
  message: string;
  process_name?: string;
}

function formatConnectionTime(timestampMs: number): string {
  if (!timestampMs) return "—";
  const date = new Date(timestampMs);
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const timeStr = `${hours}:${minutes}`;

  const diffSeconds = Math.floor((Date.now() - timestampMs) / 1000);
  if (diffSeconds < 0) return timeStr;
  if (diffSeconds < 5) return `${timeStr} (только что)`;
  if (diffSeconds < 60) return `${timeStr} (${diffSeconds} сек. назад)`;
  
  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes < 60) {
    const lastDigit = diffMinutes % 10;
    const lastTwoDigits = diffMinutes % 100;
    let minWord = "минут";
    if (lastDigit === 1 && lastTwoDigits !== 11) {
      minWord = "минуту";
    } else if (lastDigit >= 2 && lastDigit <= 4 && (lastTwoDigits < 10 || lastTwoDigits >= 20)) {
      minWord = "минуты";
    }
    return `${timeStr} (${diffMinutes} ${minWord} назад)`;
  }

  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) {
    let hourWord = "часов";
    const lastDigit = diffHours % 10;
    const lastTwoDigits = diffHours % 100;
    if (lastDigit === 1 && lastTwoDigits !== 11) {
      hourWord = "час";
    } else if (lastDigit >= 2 && lastDigit <= 4 && (lastTwoDigits < 10 || lastTwoDigits >= 20)) {
      hourWord = "часа";
    }
    return `${timeStr} (${diffHours} ${hourWord} назад)`;
  }

  return timeStr;
}

function App() {
  const [opened, { toggle }] = useDisclosure();
  const [activeTab, setActiveTab] = useState("dashboard");

  // Log display settings
  const [logViewMode, setLogViewMode] = useState<string>("all");

  // GitHub Changelog states
  interface GitHubRelease {
    id: number;
    tag_name: string;
    name: string;
    published_at: string;
    body: string;
    html_url: string;
  }
  const [releases, setReleases] = useState<GitHubRelease[]>([]);
  const [isLoadingReleases, setIsLoadingReleases] = useState(false);
  const [releasesError, setReleasesError] = useState<string | null>(null);

  const fetchReleases = async () => {
    setIsLoadingReleases(true);
    setReleasesError(null);
    try {
      const response = await fetch("https://api.github.com/repos/truecoders/AppProxyBridge/releases");
      if (!response.ok) {
        throw new Error(`Ошибка загрузки: ${response.statusText}`);
      }
      const data = await response.json();
      setReleases(data);
    } catch (err: any) {
      setReleasesError(err.message || "Не удалось загрузить историю изменений");
    } finally {
      setIsLoadingReleases(false);
    }
  };

  // Fetch releases when settings tab is opened and releases are not loaded yet
  useEffect(() => {
    if (activeTab === "settings" && releases.length === 0) {
      fetchReleases();
    }
  }, [activeTab, releases.length]);

  // App Engine states
  const [isRunning, setIsRunning] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [statusType, setStatusType] = useState<"success" | "error" | "info">("info");

  // Global Engine Rules & Options (Empty/Default user preferences on fresh db)
  const [bypassLocal, setBypassLocal] = useState<boolean>(false); // Deactivated by default
  const [proxyDns, setProxyDns] = useState<boolean>(true);       // Activated by default
  const [autostart, setAutostart] = useState<boolean>(true);       // Activated by default
  const [minimizeToTray, setMinimizeToTray] = useState<boolean>(true); // Activated by default
  const [startMinimized, setStartMinimized] = useState<boolean>(false); // Deactivated by default

  // Proxies Pool State (Completely empty by default)
  const [proxies, setProxies] = useState<ProxyConfig[]>([]);

  // Form states for creating a new proxy
  const [newProxyName, setNewProxyName] = useState<string>("");
  const [proxyType, setProxyType] = useState<string>("SOCKS5");
  const [proxyHost, setProxyHost] = useState<string>("127.0.0.1");
  const [proxyPort, setProxyPort] = useState<number>(1080);
  const [username, setUsername] = useState<string>("");
  const [password, setPassword] = useState<string>("");
  const [isPrimaryChecked, setIsPrimaryChecked] = useState<boolean>(false);
  const [connectionString, setConnectionString] = useState<string>("");

  // Rules State (Completely empty by default)
  const [rules, setRules] = useState<Rule[]>([]);
  const [newProcessName, setNewProcessName] = useState("");
  const [newAction, setNewAction] = useState<string>("Proxy");
  const [selectedProxyId, setSelectedProxyId] = useState<string>("");

  // Connection log state
  const [connections, setConnections] = useState<ConnectionInfo[]>([]);
  const [totalSent, setTotalSent] = useState<number>(0);
  const [totalReceived, setTotalReceived] = useState<number>(0);
  const [blockedCount, setBlockedCount] = useState<number>(0);
  const [activeConnectionsCount, setActiveConnectionsCount] = useState<number>(0);

  // Per-process traffic from backend (polled from get_traffic_stats)
  const [processTraffic, setProcessTraffic] = useState<Record<string, { sent: number; recv: number; last_activity: number }>>({}); 

  // UI Search, Sorting and Filtering States for live connections
  const [procSearchQuery, setProcSearchQuery] = useState("");
  const [procSortBy, setProcSortBy] = useState<string>("name"); // "name" | "activity" | "time" (Default sorting: by name)
  const [procFilterAction, setProcFilterAction] = useState<string>("all"); // "all" | "proxy" | "direct" | "blocked"
  const [refreshNonce, setRefreshNonce] = useState<number>(0);
  const [selectedProcessName, setSelectedProcessName] = useState<string | null>(null);

  // Known processes from DB (grouping state)
  const [knownProcesses, setKnownProcesses] = useState<KnownProcess[]>([]);

  // Application logs state
  const [appLogs, setAppLogs] = useState<LogEntry[]>([]);

  // Dashboard group sections collapsed state
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({});

  // Stable connection history per process name (up to 100 per process)
  const [processConnHistory, setProcessConnHistory] = useState<Record<string, ConnectionInfo[]>>({});

  useEffect(() => {
    setProcessConnHistory((prev) => {
      const next = { ...prev };
      const activeIds = new Set(connections.map((c) => c.id));

      // 1. Mark disappeared active connections in the entire history map as Closed
      Object.keys(next).forEach((procName) => {
        const history = next[procName] || [];
        let updated = false;

        const nextHistory = history.map((h) => {
          if ((h.status === "Active" || h.status === "Proxied") && !activeIds.has(h.id)) {
            updated = true;
            return { ...h, status: "Closed" };
          }
          return h;
        });

        if (updated) {
          next[procName] = nextHistory;
        }
      });

      // 2. Add or update latest connections in their respective process history
      connections.forEach((conn) => {
        const procName = conn.process_name;
        if (!procName || procName.toLowerCase() === "unknown") return;

        const history = next[procName] || [];
        const existingIdx = history.findIndex((h) => h.id === conn.id);

        if (existingIdx > -1) {
          const updated = [...history];
          const prevEntry = updated[existingIdx];

          if (
            prevEntry.bytes_sent !== conn.bytes_sent ||
            prevEntry.bytes_received !== conn.bytes_received ||
            prevEntry.status !== conn.status
          ) {
            updated[existingIdx] = {
              ...prevEntry,
              ...conn,
              timestamp: prevEntry.timestamp || conn.timestamp || Date.now(),
            };
            next[procName] = updated;
          }
        } else {
          const newEntry = {
            ...conn,
            timestamp: conn.timestamp || Date.now(),
          };
          const updated = [newEntry, ...history]
            .sort((a, b) => b.timestamp - a.timestamp)
            .slice(0, 100);
          next[procName] = updated;
        }
      });

      return next;
    });
  }, [connections]);

  // Real-time highlight state for active connections (flashing/glow for 300ms)
  const [highlightedConns, setHighlightedConns] = useState<Record<string, number>>({});
  const [highlightedProcesses, setHighlightedProcesses] = useState<Record<string, number>>({});
  const prevConnsRef = useRef<ConnectionInfo[]>([]);

  const timeoutRef = useRef<number | null>(null);
  const isStartingRef = useRef<boolean>(false);

  // Set notification helper
  const showNotification = (msg: string, type: "success" | "error" | "info") => {
    setStatusMessage(msg);
    setStatusType(type);
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = window.setTimeout(() => setStatusMessage(null), 6000);
  };

  // Update states
  const [appVersion, setAppVersion] = useState<string>("0.4.5");
  const [updateInfo, setUpdateInfo] = useState<{
    version: string;
    body?: string;
    updateObj: any;
  } | null>(null);
  const [isCheckingUpdate, setIsCheckingUpdate] = useState<boolean>(false);
  const [isDownloadingUpdate, setIsDownloadingUpdate] = useState<boolean>(false);
  const [updateProgress, setUpdateProgress] = useState<number>(0);
  const [updateProgressText, setUpdateProgressText] = useState<string>("");

  useEffect(() => {
    const fetchVersion = async () => {
      try {
        const ver = await getVersion();
        setAppVersion(ver);
      } catch (e) {
        console.error("Failed to get app version", e);
      }
    };
    fetchVersion();
  }, []);

  useEffect(() => {
    const autoCheckUpdate = async () => {
      const hasChecked = sessionStorage.getItem("hasCheckedUpdates");
      if (hasChecked) return;
      sessionStorage.setItem("hasCheckedUpdates", "true");
      
      try {
        const update = await check();
        if (update?.available) {
          setUpdateInfo({
            version: update.version,
            body: update.body || "Нет описания изменений.",
            updateObj: update,
          });
        }
      } catch (err) {
        console.error("Auto update check failed", err);
      }
    };
    
    const timer = setTimeout(autoCheckUpdate, 2000);
    return () => clearTimeout(timer);
  }, []);

  const handleManualUpdateCheck = async (silentOnNoUpdate: boolean = false) => {
    setIsCheckingUpdate(true);
    try {
      const update = await check();
      if (update?.available) {
        setUpdateInfo({
          version: update.version,
          body: update.body || "Нет описания изменений.",
          updateObj: update,
        });
      } else {
        if (!silentOnNoUpdate) {
          showNotification("У вас установлена последняя версия приложения", "success");
        }
      }
    } catch (err) {
      console.error("Manual update check failed", err);
      showNotification(`Ошибка при проверке обновлений: ${err}`, "error");
    } finally {
      setIsCheckingUpdate(false);
    }
  };

  const handleDownloadAndInstall = async () => {
    if (!updateInfo?.updateObj) return;
    setIsDownloadingUpdate(true);
    setUpdateProgress(0);
    setUpdateProgressText("Подготовка к скачиванию...");
    
    let downloaded = 0;
    let contentLength = 0;

    try {
      await updateInfo.updateObj.downloadAndInstall((event: any) => {
        switch (event.event) {
          case "Started":
            contentLength = event.data.contentLength || 0;
            setUpdateProgressText("Скачивание обновления началось...");
            break;
          case "Progress":
            downloaded += event.data.chunkLength;
            if (contentLength > 0) {
              const pct = Math.round((downloaded / contentLength) * 100);
              setUpdateProgress(pct);
              setUpdateProgressText(`Скачивание... ${pct}% (${formatBytes(downloaded)} из ${formatBytes(contentLength)})`);
            } else {
              setUpdateProgressText(`Скачивание... (${formatBytes(downloaded)} загружено)`);
            }
            break;
          case "Finished":
            setUpdateProgress(100);
            setUpdateProgressText("Установка обновления... Приложение сейчас перезагрузится.");
            break;
        }
      });
      
      await invoke("restart_app");
    } catch (err) {
      console.error("Update download & install failed", err);
      showNotification(`Ошибка обновления: ${err}`, "error");
      setIsDownloadingUpdate(false);
    }
  };

  // Sync running status and load saved session on mount
  useEffect(() => {
    const checkRunning = async () => {
      try {
        const running: boolean = await invoke("is_engine_running");
        setIsRunning(running);
      } catch (err) {
        console.error("Failed to check status", err);
      }
    };
    checkRunning();

    // Load initial SQLite database configurations
    const loadSessionData = async () => {
      try {
        const data: SavedData = await invoke("get_saved_data");
        setProxies(data.proxies);
        setRules(data.rules);
        setProxyDns(data.proxy_dns);
        setBypassLocal(data.bypass_local);
        setAutostart(data.autostart);
        setMinimizeToTray(data.minimize_to_tray);
        setStartMinimized(data.start_minimized);

        // Load known processes grouping
        try {
          const kp: KnownProcess[] = await invoke("get_known_processes");
          setKnownProcesses(kp);
        } catch (_) {}

        // Load initial app logs from DB
        try {
          const logs: LogEntry[] = await invoke("get_app_logs");
          setAppLogs(logs);
        } catch (_) {}

        // Auto-start engine if there is at least one proxy added and not already running
        const alreadyRunning: boolean = await invoke("is_engine_running");
        setIsRunning(alreadyRunning);

        if (!alreadyRunning && data.autostart && data.proxies && data.proxies.length > 0 && !isStartingRef.current) {
          isStartingRef.current = true;
          try {
            await invoke("start_engine", {
              config: data.proxies,
              rules: data.rules,
              bypassLocal: data.bypass_local,
              proxyDns: data.proxy_dns,
            });
            setIsRunning(true);
            showNotification("Движок прокси запущен автоматически на основе сохраненных настроек", "success");
          } catch (engineErr) {
            console.error("Failed to auto-start proxy engine", engineErr);
            showNotification("Не удалось автоматически запустить прокси (требуются права UAC)", "error");
          } finally {
            isStartingRef.current = false;
          }
        }
      } catch (err) {
        console.error("Failed to load persistent configurations from DB", err);
        showNotification("Не удалось загрузить конфигурации из базы данных", "error");
      }
    };
    loadSessionData();

    // Listen to real-time events from Tauri backend
    const setupListener = async () => {
      const unlisten = await listen<ConnectionInfo>("connection-event", (event) => {
        const newConn = event.payload;
        
        // Highlight connection row with timestamp protection for 300ms
        const now = Date.now();
        setHighlightedConns((prev) => ({ ...prev, [newConn.id]: now }));
        setHighlightedProcesses((prev) => ({ ...prev, [newConn.process_name]: now }));
        setTimeout(() => {
          setHighlightedConns((prev) => {
            if (prev[newConn.id] <= now) {
              const next = { ...prev };
              delete next[newConn.id];
              return next;
            }
            return prev;
          });
          setHighlightedProcesses((prev) => {
            if (prev[newConn.process_name] <= now) {
              const next = { ...prev };
              delete next[newConn.process_name];
              return next;
            }
            return prev;
          });
        }, 300);

        setConnections((prev) => {
          const existing = prev.find((c) => c.id === newConn.id);
          let accumulatedSent = newConn.bytes_sent;
          let accumulatedReceived = newConn.bytes_received;
          
          if (newConn.status !== "Closed") {
            accumulatedSent = existing ? existing.bytes_sent + newConn.bytes_sent : newConn.bytes_sent;
            accumulatedReceived = existing ? existing.bytes_received + newConn.bytes_received : newConn.bytes_received;
          }
          
          const filtered = prev.filter((c) => c.id !== newConn.id);
          return [{
            ...newConn,
            bytes_sent: accumulatedSent,
            bytes_received: accumulatedReceived
          }, ...filtered].slice(0, 100);
        });

        // Update total stats
        if (newConn.action === "Block") {
          setBlockedCount((c) => c + 1);
        }
      });
      return unlisten;
    };

    let unlistenFn: (() => void) | null = null;
    setupListener().then((fn) => {
      unlistenFn = fn;
    });

    // Listen for log events from backend (real-time, no polling)
    let unlistenLogFn: (() => void) | null = null;
    const setupLogListener = async () => {
      const unlisten = await listen<LogEntry>("log-event", (event) => {
        setAppLogs((prev) => [event.payload, ...prev].slice(0, 300));
      });
      return unlisten;
    };
    setupLogListener().then((fn) => {
      unlistenLogFn = fn;
    });

    return () => {
      if (unlistenFn) unlistenFn();
      if (unlistenLogFn) unlistenLogFn();
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  // Poll known processes periodically to pick up auto-discovered processes
  useEffect(() => {
    const fetchKnown = async () => {
      try {
        const kp: KnownProcess[] = await invoke("get_known_processes");
        setKnownProcesses(kp);
      } catch (_) {}
    };
    const interval = setInterval(fetchKnown, 5000);
    return () => clearInterval(interval);
  }, []);

  // Poll active system connections dynamically (TCP/UDP live monitor)
  useEffect(() => {
    const fetchActive = async () => {
      try {
        const activeConns: ConnectionInfo[] = await invoke("get_active_connections");
        setActiveConnectionsCount(activeConns.length);
        
        setConnections((prev) => {
          const diverts = prev.filter(
            (c) => c.bytes_sent > 0 || c.action === "Block" || c.status === "Blocked" || c.status === "Proxied"
          );
          
          const filteredActive = activeConns
            .filter((ac) => !diverts.some((d) => d.id === ac.id))
            .map((ac) => {
              const existing = prev.find((p) => p.id === ac.id);
              return {
                ...ac,
                bytes_sent: existing ? existing.bytes_sent : ac.bytes_sent,
                bytes_received: existing ? existing.bytes_received : ac.bytes_received,
                timestamp: existing ? existing.timestamp : ac.timestamp,
              };
            });
            
          return [...diverts, ...filteredActive].slice(0, 150);
        });
      } catch (err) {
        console.error("Failed to query active connections", err);
      }
    };

    fetchActive();
    const interval = setInterval(fetchActive, 2000);
    return () => clearInterval(interval);
  }, []);

  // Poll per-process traffic stats from backend (the single source of truth)
  useEffect(() => {
    const fetchTrafficStats = async () => {
      try {
        interface TrafficEntry {
          process_name: string;
          bytes_sent: number;
          bytes_received: number;
          last_activity: number;
        }
        const stats: TrafficEntry[] = await invoke("get_traffic_stats");
        const map: Record<string, { sent: number; recv: number; last_activity: number }> = {};
        let sumSent = 0;
        let sumRecv = 0;
        for (const entry of stats) {
          map[entry.process_name] = { sent: entry.bytes_sent, recv: entry.bytes_received, last_activity: entry.last_activity };
          sumSent += entry.bytes_sent;
          sumRecv += entry.bytes_received;
        }
        setProcessTraffic(map);
        setTotalSent(sumSent);
        setTotalReceived(sumRecv);
      } catch (err) {
        // Silently ignore - stats will be 0 if engine not running
      }
    };

    fetchTrafficStats();
    const interval = setInterval(fetchTrafficStats, 2000);
    return () => clearInterval(interval);
  }, []);

  // Real-time Activity Highlighting engine (flashes rows and headers on network actions)
  useEffect(() => {
    const newHighlights: Record<string, number> = {};
    const newProcessHighlights: Record<string, number> = {};
    const prevConns = prevConnsRef.current;
    const now = Date.now();

    // Only identify updates if we actually had a previous connection list to compare with
    if (prevConns.length > 0) {
      for (const c of connections) {
        const prev = prevConns.find((p) => p.id === c.id);
        if (!prev) {
          // New connection created!
          newHighlights[c.id] = now;
          newProcessHighlights[c.process_name] = now;
        } else if (
          c.bytes_sent > prev.bytes_sent ||
          c.bytes_received > prev.bytes_received ||
          c.status !== prev.status
        ) {
          // New activity or status change!
          newHighlights[c.id] = now;
          newProcessHighlights[c.process_name] = now;
        }
      }
    }

    if (Object.keys(newHighlights).length > 0) {
      setHighlightedConns((prev) => ({ ...prev, ...newHighlights }));
      setHighlightedProcesses((prev) => ({ ...prev, ...newProcessHighlights }));

      setTimeout(() => {
        setHighlightedConns((prev) => {
          const next = { ...prev };
          let changed = false;
          for (const key of Object.keys(newHighlights)) {
            if (next[key] <= now) {
              delete next[key];
              changed = true;
            }
          }
          return changed ? next : prev;
        });
        setHighlightedProcesses((prev) => {
          const next = { ...prev };
          let changed = false;
          for (const key of Object.keys(newProcessHighlights)) {
            if (next[key] <= now) {
              delete next[key];
              changed = true;
            }
          }
          return changed ? next : prev;
        });
      }, 300);
    }

    prevConnsRef.current = connections;
  }, [connections]);

  // Update selectedProxyId when primary proxy changes
  useEffect(() => {
    const primary = proxies.find((p) => p.is_primary) || proxies[0];
    if (primary) {
      setSelectedProxyId(primary.id);
    }
  }, [proxies]);

  // Connection string parser
  const handleParseString = (str: string) => {
    setConnectionString(str);
    const cleanStr = str.trim();
    if (!cleanStr) return;

    // Pattern matches protocols like socks5://, http://
    const protocolRegex = /^([a-zA-Z0-9]+):\/\//;
    const matchProto = cleanStr.match(protocolRegex);
    let protocol = "SOCKS5";
    let rest = cleanStr;

    if (matchProto) {
      const parsedProto = matchProto[1].toUpperCase();
      if (parsedProto === "HTTP" || parsedProto === "SOCKS5") {
        protocol = parsedProto;
      }
      rest = cleanStr.substring(matchProto[0].length);
    }

    let userVal = "";
    let passVal = "";
    if (rest.includes("@")) {
      const parts = rest.split("@");
      const credentials = parts[0];
      rest = parts[1];
      if (credentials.includes(":")) {
        const credParts = credentials.split(":");
        userVal = credParts[0];
        passVal = credParts[1];
      } else {
        userVal = credentials;
      }
    }

    let hostVal = rest;
    let portVal = 1080;
    if (rest.includes(":")) {
      const hostParts = rest.split(":");
      hostVal = hostParts[0];
      const parsedPort = parseInt(hostParts[1], 10);
      if (!isNaN(parsedPort)) {
        portVal = parsedPort;
      }
    }

    setProxyType(protocol);
    setProxyHost(hostVal);
    setProxyPort(portVal);
    setUsername(userVal);
    setPassword(passVal);
    
    // Auto-generate name if empty
    if (!newProxyName) {
      setNewProxyName(`Импортированный ${protocol}`);
    }
  };

  // Toggle Engine (Start/Stop)
  const handleToggleEngine = async () => {
    if (isRunning) {
      try {
        await invoke("stop_engine");
        setIsRunning(false);
        showNotification("Прокси-движок успешно остановлен", "success");
      } catch (err: any) {
        showNotification(`Ошибка остановки: ${err}`, "error");
      }
    } else {
      // 1. Validation: Block start if no proxies added
      if (proxies.length === 0) {
        showNotification("Ошибка запуска: Добавьте хотя бы один прокси-сервер в настройках!", "error");
        setActiveTab("settings");
        return;
      }

      // 2. Validation: Warning if no rules added (but allow run)
      const hasProxyRules = rules.some((r) => r.action === "Proxy" || r.action === "Block");
      if (!hasProxyRules) {
        showNotification(
          "Внимание: У вас не настроено ни одного активного правила проксирования или блокировки. Весь сетевой трафик пойдет напрямую (Direct).",
          "info"
        );
      }

      try {
        await invoke("start_engine", {
          config: proxies,
          rules,
          bypassLocal,
          proxyDns: proxyDns,
        });
        setIsRunning(true);
        showNotification("Прокси-движок запущен. WinDivert успешно перехватывает пакеты.", "success");
      } catch (err: any) {
        showNotification(`Ошибка запуска: ${err}. Требуются права Администратора (UAC)!`, "error");
      }
    }
  };

  // Add a proxy to SQLite & local pool
  const handleAddProxy = async () => {
    if (!proxyHost || !proxyPort) return;
    const name = newProxyName.trim() || `Прокси ${proxies.length + 1}`;
    
    const newProxy: ProxyConfig = {
      id: `proxy-${Date.now()}`,
      name,
      proxy_type: proxyType,
      host: proxyHost,
      port: proxyPort,
      username: username || undefined,
      password: password || undefined,
      is_primary: proxies.length === 0 ? true : isPrimaryChecked,
    };

    try {
      await invoke("save_proxy", { proxy: newProxy });
      const refreshed: SavedData = await invoke("get_saved_data");
      setProxies(refreshed.proxies);

      // Reset fields
      setNewProxyName("");
      setProxyHost("127.0.0.1");
      setProxyPort(1080);
      setUsername("");
      setPassword("");
      setIsPrimaryChecked(false);
      setConnectionString("");
      showNotification(`Прокси-сервер "${name}" добавлен и сохранен в БД`, "success");
    } catch (err) {
      showNotification(`Ошибка добавления прокси: ${err}`, "error");
    }
  };

  // Delete a proxy from SQLite & local pool
  const handleDeleteProxy = async (id: string) => {
    try {
      await invoke("delete_proxy", { id });
      const refreshed: SavedData = await invoke("get_saved_data");
      setProxies(refreshed.proxies);
      showNotification("Прокси-сервер успешно удален из БД", "success");
    } catch (err) {
      showNotification(`Не удалось удалить прокси: ${err}`, "error");
    }
  };

  // Make a proxy primary and sync with SQLite
  const handleSetPrimaryProxy = async (id: string) => {
    const targetProxy = proxies.find((p) => p.id === id);
    if (!targetProxy) return;

    try {
      await invoke("save_proxy", { proxy: { ...targetProxy, is_primary: true } });
      const refreshed: SavedData = await invoke("get_saved_data");
      setProxies(refreshed.proxies);
      showNotification("Основной прокси успешно обновлен в БД", "success");
    } catch (err) {
      showNotification(`Не удалось изменить основной прокси: ${err}`, "error");
    }
  };

  // Add filtering rule and save to SQLite
  const handleAddRule = async () => {
    if (!newProcessName) return;
    const newRule: Rule = {
      id: Date.now().toString(),
      process_name: newProcessName,
      action: newAction as "Proxy" | "Direct" | "Block",
      proxy_id: newAction === "Proxy" ? selectedProxyId : undefined,
    };

    const updatedRules = [...rules, newRule];

    try {
      await invoke("update_engine_rules", { rules: updatedRules });
      setRules(updatedRules);
      setNewProcessName("");
      showNotification("Правило добавлено и сохранено в БД", "success");
    } catch (err) {
      showNotification(`Не удалось добавить правило: ${err}`, "error");
    }
  };

  // Delete filtering rule from SQLite
  const handleDeleteRule = async (id: string) => {
    const updatedRules = rules.filter((r) => r.id !== id);

    try {
      await invoke("update_engine_rules", { rules: updatedRules });
      setRules(updatedRules);
      showNotification("Правило удалено из БД", "success");
    } catch (err) {
      showNotification(`Не удалось удалить правило: ${err}`, "error");
    }
  };

  // Quick Rule Creator from Dashboard
  const handleQuickRuleCreate = async (procName: string) => {
    const existing = rules.find((r) => r.process_name.toLowerCase() === procName.toLowerCase());
    if (existing) return;

    const primaryProxy = proxies.find((p) => p.is_primary) || proxies[0];
    const newRule: Rule = {
      id: `rule-${Date.now()}`,
      process_name: procName,
      action: "Proxy",
      proxy_id: primaryProxy?.id || undefined,
    };

    const updatedRules = [...rules, newRule];
    try {
      await invoke("update_engine_rules", { rules: updatedRules });
      setRules(updatedRules);
      showNotification(`Создано правило проксирования для процесса ${procName}`, "success");
    } catch (err) {
      showNotification(`Не удалось создать правило: ${err}`, "error");
    }
  };

  // Quick Rule Deleter from Dashboard
  const handleQuickRuleDelete = async (procName: string) => {
    const updatedRules = rules.filter((r) => r.process_name.toLowerCase() !== procName.toLowerCase());
    try {
      await invoke("update_engine_rules", { rules: updatedRules });
      setRules(updatedRules);
      showNotification(`Правило для процесса ${procName} удалено`, "success");
    } catch (err) {
      showNotification(`Не удалось удалить правило: ${err}`, "error");
    }
  };

  // Quick Rule Action Modifier from Dashboard
  const handleQuickRuleAction = async (procName: string, action: "Proxy" | "Direct" | "Block") => {
    let updatedRules = [...rules];
    const index = rules.findIndex((r) => r.process_name.toLowerCase() === procName.toLowerCase());

    const primaryProxy = proxies.find((p) => p.is_primary) || proxies[0];

    if (index > -1) {
      updatedRules[index] = {
        ...updatedRules[index],
        action,
        proxy_id: action === "Proxy" ? updatedRules[index].proxy_id || primaryProxy?.id || undefined : undefined,
      };
    } else {
      updatedRules.push({
        id: `rule-${Date.now()}`,
        process_name: procName,
        action,
        proxy_id: action === "Proxy" ? primaryProxy?.id || undefined : undefined,
      });
    }

    try {
      await invoke("update_engine_rules", { rules: updatedRules });
      setRules(updatedRules);
      showNotification(
        `Правило для ${procName} изменено на "${
          action === "Proxy" ? "Проксировать" : action === "Block" ? "Блокировать" : "Напрямую"
        }"`,
        "success"
      );
    } catch (err) {
      showNotification(`Не удалось обновить действие правила: ${err}`, "error");
    }
  };

  // Quick Rule Proxy Modifier from Dashboard
  const handleQuickRuleProxy = async (procName: string, proxyId: string) => {
    let updatedRules = [...rules];
    const index = rules.findIndex((r) => r.process_name.toLowerCase() === procName.toLowerCase());

    if (index > -1) {
      updatedRules[index] = {
        ...updatedRules[index],
        action: "Proxy",
        proxy_id: proxyId || undefined,
      };
    } else {
      updatedRules.push({
        id: `rule-${Date.now()}`,
        process_name: procName,
        action: "Proxy",
        proxy_id: proxyId || undefined,
      });
    }

    try {
      await invoke("update_engine_rules", { rules: updatedRules });
      setRules(updatedRules);
      showNotification(`Правило для ${procName} перенаправлено на выбранный прокси`, "success");
    } catch (err) {
      showNotification(`Не удалось обновить привязку прокси: ${err}`, "error");
    }
  };

  // Save global settings (DNS, Local Bypass, Autostart, minimize to tray, start minimized) to SQLite
  const handleSaveSettings = async (dns: boolean, local: boolean, autoStartVal: boolean, minimizeToTrayVal: boolean, startMinimizedVal: boolean) => {
    try {
      await invoke("save_routing_settings", {
        proxyDns: dns,
        bypassLocal: local,
        autostart: autoStartVal,
        minimizeToTray: minimizeToTrayVal,
        startMinimized: startMinimizedVal,
      });
    } catch (err) {
      showNotification("Не удалось сохранить системные настройки в БД", "error");
    }
  };

  // Set process group (new/proxy/direct/block) via backend command
  const handleSetProcessGroup = async (procName: string, groupAction: string, proxyId?: string) => {
    try {
      const primaryProxy = proxies.find((p) => p.is_primary) || proxies[0];
      const effectiveProxyId = proxyId || (groupAction === "proxy" ? primaryProxy?.id : undefined);
      
      await invoke("set_process_group", {
        processName: procName,
        groupAction,
        proxyId: effectiveProxyId || null,
      });
      
      // Refresh known processes and rules
      const kp: KnownProcess[] = await invoke("get_known_processes");
      setKnownProcesses(kp);
      const data: SavedData = await invoke("get_saved_data");
      setRules(data.rules);
      
      const labels: Record<string, string> = {
        proxy: "Проксировать",
        direct: "Напрямую",
        block: "Заблокировать",
        new: "Новые",
      };
      showNotification(`${procName} → ${labels[groupAction] || groupAction}`, "success");
    } catch (err) {
      showNotification(`Ошибка: ${err}`, "error");
    }
  };

  // Clear all application logs
  const handleClearLogs = async () => {
    try {
      await invoke("clear_app_logs");
      setAppLogs([]);
      showNotification("Лог очищен", "success");
    } catch (err) {
      showNotification(`Ошибка очистки лога: ${err}`, "error");
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes <= 0 || isNaN(bytes)) return "0.00 КБ";
    const k = 1024;
    const sizes = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    if (bytes < 1024) {
      return (bytes / 1024).toFixed(2) + " КБ";
    }
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const formatted = (bytes / Math.pow(k, i)).toFixed(2);
    return `${formatted} ${sizes[i]}`;
  };

  // Group connections by process name for System Connections Accordion
  // Merge active connections and ALL processes that have had traffic
  const groupedConnections: Record<string, ConnectionInfo[]> = {};
  
  // Initialize all known processes from traffic stats
  Object.keys(processTraffic).forEach((procName) => {
    groupedConnections[procName] = [];
  });
  
  // Add actual connections
  connections.forEach((conn) => {
    if (!groupedConnections[conn.process_name]) {
      groupedConnections[conn.process_name] = [];
    }
    groupedConnections[conn.process_name].push(conn);
  });

  // Filter and sort the process list dynamically to keep it perfectly in sync with all live traffic and active rules
  const sortedProcesses = useMemo(() => {
    const rawNames = Object.keys(groupedConnections);
    return [...rawNames]
      .filter((procName) => {
        const lower = procName.toLowerCase();
        // Hide own process from dashboard
        if (lower.includes("appproxybridge") || lower.includes("proxier")) return false;
        return lower.includes(procSearchQuery.toLowerCase());
      })
      .filter((procName) => {
        const connsList = groupedConnections[procName] || [];
        
        // A process is proxied if it has a proxy rule OR has any proxy connection
        const activeRule = rules.find((r) => r.process_name.toLowerCase() === procName.toLowerCase());
        const hasProxyRule = activeRule?.action === "Proxy";
        const hasBlockRule = activeRule?.action === "Block";
        
        const hasProxyConn = connsList.some((c) => c.action === "Proxy" || c.status === "Proxied");
        const hasBlockConn = connsList.some((c) => c.action === "Block" || c.status === "Blocked");

        if (procFilterAction === "proxy") return hasProxyRule || hasProxyConn;
        if (procFilterAction === "blocked") return hasBlockRule || hasBlockConn;
        if (procFilterAction === "direct") {
          if (hasProxyRule || hasBlockRule) return false;
          if (hasProxyConn || hasBlockConn) return false;
          return true;
        }
        return true;
      })
      .sort((a, b) => {
        const lastActA = processTraffic[a]?.last_activity || 0;
        const lastActB = processTraffic[b]?.last_activity || 0;
        
        const isActiveA = (Date.now() - lastActA) <= 5000;
        const isActiveB = (Date.now() - lastActB) <= 5000;

        // Keep active processes (activity within 5 seconds) always on top
        if (isActiveA && !isActiveB) return -1;
        if (!isActiveA && isActiveB) return 1;

        // Within the active/inactive group, sort by the selected criteria
        if (procSortBy === "name") return a.localeCompare(b);
        if (procSortBy === "time") return lastActB - lastActA;
        
        // Default sorting: "activity" (total traffic volume)
        const trafA = (processTraffic[a]?.sent || 0) + (processTraffic[a]?.recv || 0);
        const trafB = (processTraffic[b]?.sent || 0) + (processTraffic[b]?.recv || 0);
        return trafB - trafA;
      })
      .slice(0, 100);
  }, [
    connections,
    processTraffic,
    rules,
    procSearchQuery,
    procFilterAction,
    procSortBy,
    refreshNonce
  ]);

  return (
    <AppShell
      layout="alt"
      header={{ height: 60 }}
      navbar={{
        width: 260,
        breakpoint: "sm",
        collapsed: { mobile: !opened },
      }}
      padding="md"
      styles={{
        main: {
          background: "transparent",
        },
      }}
    >
      {/* Header */}
      <AppShell.Header
        className="glass-panel"
        style={{
          borderBottom: "1px solid var(--glass-border)",
          background: "rgba(22, 17, 34, 0.6)",
          zIndex: 100,
        }}
      >
        <Group h="100%" px="md" justify="space-between">
          <Group>
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <img src="/icon.png" alt="AppProxyBridge Logo" style={{ width: 32, height: 32, objectFit: "contain" }} />
            <Title order={3} className="glow-purple" style={{ fontFamily: "Outfit, sans-serif", letterSpacing: "1px" }}>
              AppProxyBridge
            </Title>
            <Badge color={isRunning ? "teal" : "red"} variant="light" size="lg" radius="sm">
              {isRunning ? "АКТИВЕН" : "ВЫКЛЮЧЕН"}
            </Badge>
          </Group>

          <Group gap="md">
            <Switch
              checked={isRunning}
              onChange={handleToggleEngine}
              size="lg"
              onLabel="ON"
              offLabel="OFF"
              color="violet"
              thumbIcon={
                isRunning ? (
                  <IconCheck size="0.8rem" color="var(--mantine-color-teal-6)" stroke={3} />
                ) : (
                  <IconPower size="0.8rem" color="var(--mantine-color-red-6)" stroke={3} />
                )
              }
            />
          </Group>
        </Group>
      </AppShell.Header>

      {/* Sidebar Navigation */}
      <AppShell.Navbar
        p="md"
        className="glass-panel"
        style={{
          borderRight: "1px solid var(--glass-border)",
          background: "rgba(13, 10, 21, 0.8)",
          overflowY: "auto",
        }}
      >
        <Stack gap="xs" style={{ minHeight: "100%" }}>
          <NavLink
            label="Дашборд"
            leftSection={<IconDashboard size={18} />}
            active={activeTab === "dashboard"}
            onClick={() => setActiveTab("dashboard")}
            variant="filled"
            color="violet"
            className="interactive-element"
            style={{ borderRadius: "8px" }}
          />
          <NavLink
            label="Правила фильтрации"
            leftSection={<IconShield size={18} />}
            active={activeTab === "rules"}
            onClick={() => setActiveTab("rules")}
            variant="filled"
            color="violet"
            className="interactive-element"
            style={{ borderRadius: "8px" }}
          />
          <NavLink
            label="Настройки прокси"
            leftSection={<IconSettings size={18} />}
            active={activeTab === "proxy_settings"}
            onClick={() => setActiveTab("proxy_settings")}
            variant="filled"
            color="violet"
            className="interactive-element"
            style={{ borderRadius: "8px" }}
          />
          <NavLink
            label="Настройки приложения"
            leftSection={<IconAdjustments size={18} />}
            active={activeTab === "settings"}
            onClick={() => setActiveTab("settings")}
            variant="filled"
            color="violet"
            className="interactive-element"
            style={{ borderRadius: "8px" }}
          />
          <NavLink
            label="Лог"
            leftSection={<IconTerminal2 size={18} />}
            active={activeTab === "logs"}
            onClick={() => setActiveTab("logs")}
            variant="filled"
            color="violet"
            className="interactive-element"
            style={{ borderRadius: "8px" }}
            rightSection={
              appLogs.length > 0 ? (
                <Badge size="xs" color="red" variant="filled" circle>
                  {appLogs.length > 99 ? "99+" : appLogs.length}
                </Badge>
              ) : null
            }
          />

          <Divider my="sm" label="СТАТИСТИКА СЕАНСА" labelPosition="center" styles={{ label: { fontSize: "10px", fontWeight: 700, letterSpacing: "1px", color: "rgba(255,255,255,0.4)" } }} />

          <Stack gap="xs" style={{ flexGrow: 1 }}>
            {/* Stat: Active Connections */}
            <Paper p="xs" radius="md" style={{ background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--glass-border)" }}>
              <Group justify="space-between" wrap="nowrap">
                <Stack gap={0}>
                  <Text size="10px" color="dimmed" fw={700} style={{ letterSpacing: "0.5px" }}>
                    АКТИВНЫЕ СОЕД.
                  </Text>
                  <Text fw={700} size="md" mt="4px">
                    {activeConnectionsCount}
                  </Text>
                </Stack>
                <ThemeIcon color="violet" variant="light" radius="md" size="md">
                  <IconActivity size={14} />
                </ThemeIcon>
              </Group>
            </Paper>

            {/* Stat: Sent */}
            <Paper p="xs" radius="md" style={{ background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--glass-border)" }}>
              <Group justify="space-between" wrap="nowrap">
                <Stack gap={0}>
                  <Text size="10px" color="dimmed" fw={700} style={{ letterSpacing: "0.5px" }}>
                    ОТПРАВЛЕНО
                  </Text>
                  <Text fw={700} size="md" mt="4px" style={{ color: "#00f2fe" }}>
                    {formatBytes(totalSent)}
                  </Text>
                </Stack>
                <ThemeIcon color="cyan" variant="light" radius="md" size="md">
                  <IconArrowUpRight size={14} />
                </ThemeIcon>
              </Group>
            </Paper>

            {/* Stat: Received */}
            <Paper p="xs" radius="md" style={{ background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--glass-border)" }}>
              <Group justify="space-between" wrap="nowrap">
                <Stack gap={0}>
                  <Text size="10px" color="dimmed" fw={700} style={{ letterSpacing: "0.5px" }}>
                    ПОЛУЧЕНО
                  </Text>
                  <Text fw={700} size="md" mt="4px" style={{ color: "#39d353" }}>
                    {formatBytes(totalReceived)}
                  </Text>
                </Stack>
                <ThemeIcon color="teal" variant="light" radius="md" size="md">
                  <IconArrowDownLeft size={14} />
                </ThemeIcon>
              </Group>
            </Paper>

            {/* Stat: Blocked */}
            <Paper p="xs" radius="md" style={{ background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--glass-border)" }}>
              <Group justify="space-between" wrap="nowrap">
                <Stack gap={0}>
                  <Text size="10px" color="dimmed" fw={700} style={{ letterSpacing: "0.5px" }}>
                    ЗАБЛОКИРОВАНО
                  </Text>
                  <Text fw={700} size="md" mt="4px" style={{ color: "#ff4757" }}>
                    {blockedCount}
                  </Text>
                </Stack>
                <ThemeIcon color="red" variant="light" radius="md" size="md">
                  <IconShield size={14} />
                </ThemeIcon>
              </Group>
            </Paper>
          </Stack>

          <Divider my="sm" label="ПАРАМЕТРЫ ЗАПУСКА" labelPosition="center" styles={{ label: { fontSize: "10px", fontWeight: 700, letterSpacing: "1px", color: "rgba(255,255,255,0.4)" } }} />

          <Stack gap="xs" px="xs" pb="xs">
            <Switch
              label="Запускать с системой"
              checked={autostart}
              onChange={(e) => {
                const val = e.currentTarget.checked;
                setAutostart(val);
                handleSaveSettings(proxyDns, bypassLocal, val, minimizeToTray, startMinimized);
              }}
              size="xs"
              color="violet"
              styles={{
                label: { color: "#ffffff", fontWeight: 500, fontSize: "11px", cursor: "pointer" }
              }}
            />

            <Switch
              label="Сворачивать при закрытии"
              checked={minimizeToTray}
              onChange={(e) => {
                const val = e.currentTarget.checked;
                setMinimizeToTray(val);
                handleSaveSettings(proxyDns, bypassLocal, autostart, val, startMinimized);
              }}
              size="xs"
              color="violet"
              styles={{
                label: { color: "#ffffff", fontWeight: 500, fontSize: "11px", cursor: "pointer" }
              }}
            />

            <Switch
              label="Запускать свернутым в трее"
              checked={startMinimized}
              onChange={(e) => {
                const val = e.currentTarget.checked;
                setStartMinimized(val);
                handleSaveSettings(proxyDns, bypassLocal, autostart, minimizeToTray, val);
              }}
              size="xs"
              color="violet"
              styles={{
                label: { color: "#ffffff", fontWeight: 500, fontSize: "11px", cursor: "pointer" }
              }}
            />
          </Stack>
        </Stack>
      </AppShell.Navbar>

      {/* Main Content Area */}
      <AppShell.Main style={{ minHeight: "calc(100vh - 60px)" }}>
        {statusMessage && (
          <Notification
            icon={statusType === "success" ? <IconCheck size={18} /> : <IconAlertCircle size={18} />}
            color={statusType === "success" ? "teal" : statusType === "error" ? "red" : "violet"}
            title={statusType === "success" ? "Успешно" : statusType === "error" ? "Ошибка" : "Информация"}
            onClose={() => setStatusMessage(null)}
            mb="md"
            className="glass-panel"
            style={{ position: "fixed", bottom: 20, right: 20, zIndex: 1000, minWidth: 350 }}
          >
            {statusMessage}
          </Notification>
        )}

        {/* TAB: Dashboard */}
        {activeTab === "dashboard" && (
          <Stack gap="md" style={{ height: "calc(100vh - 92px)", display: "flex", flexDirection: "column" }}>
            {/* Grouped Connection monitor (Accordion, up to 10 processes, stretched height) */}
            <Card radius="md" p="md" className="glass-panel" style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
              <Group justify="space-between" mb="md" align="center">
                <Title order={4} style={{ fontFamily: "Outfit, sans-serif" }}>
                  СЕТЕВОЙ МОНИТОР В РЕАЛЬНОМ ВРЕМЕНИ (ГРУППИРОВКА ПО ПРОЦЕССАМ)
                </Title>
              </Group>

              {/* Advanced Controls Row */}
              <Group gap="md" mb="md" justify="space-between" wrap="wrap">
                <TextInput
                  placeholder="Поиск по имени процесса..."
                  leftSection={<IconSearch size={16} color="gray" />}
                  value={procSearchQuery}
                  onChange={(e) => setProcSearchQuery(e.currentTarget.value)}
                  style={{ flexGrow: 1, minWidth: "220px" }}
                  radius="md"
                  size="sm"
                />
                
                <Group gap="xs" wrap="nowrap">
                  <Select
                    placeholder="Сортировка"
                    data={[
                      { value: "activity", label: "По активности (соед.)" },
                      { value: "name", label: "По имени (А-Я)" },
                      { value: "time", label: "По последней активности" },
                    ]}
                    value={procSortBy}
                    onChange={(val) => setProcSortBy(val || "activity")}
                    radius="md"
                    size="sm"
                    style={{ width: "190px" }}
                  />

                  <Select
                    placeholder="Фильтр трафика"
                    data={[
                      { value: "all", label: "Все процессы" },
                      { value: "proxy", label: "Только через прокси" },
                      { value: "direct", label: "Только напрямую" },
                      { value: "blocked", label: "Только заблокированные" },
                    ]}
                    value={procFilterAction}
                    onChange={(val) => setProcFilterAction(val || "all")}
                    radius="md"
                    size="sm"
                    style={{ width: "190px" }}
                  />

                  <Tooltip label="Переупорядочить список (сортировка)">
                    <ActionIcon
                      variant="light"
                      color="violet"
                      size="lg"
                      radius="md"
                      onClick={() => setRefreshNonce((n) => n + 1)}
                      style={{ height: "36px", width: "36px" }}
                    >
                      <IconRefresh size={18} />
                    </ActionIcon>
                  </Tooltip>
                </Group>
              </Group>

              <ScrollArea style={{ flex: 1, minHeight: 0 }}>
                {sortedProcesses.length === 0 ? (
                  <Text color="dimmed" style={{ textAlign: "center" }} py="xl">
                    Процессов с заданными фильтрами не найдено. Начните сетевую активность.
                  </Text>
                ) : (() => {
                  // Build a lookup map for known processes
                  const knownMap: Record<string, KnownProcess> = {};
                  knownProcesses.forEach((kp) => {
                    knownMap[kp.process_name.toLowerCase()] = kp;
                  });
                  
                  // Categorize processes into 4 groups
                  const groups: Record<string, string[]> = {
                    new: [],
                    proxy: [],
                    direct: [],
                    block: [],
                  };
                  
                  sortedProcesses.forEach((procName) => {
                    const known = knownMap[procName.toLowerCase()];
                    const group = known?.group_action || "new";
                    if (groups[group]) {
                      groups[group].push(procName);
                    } else {
                      groups.new.push(procName);
                    }
                  });

                  const groupConfig = [
                    { key: "new", label: "НОВЫЕ", icon: <IconSparkles size={16} />, color: "violet", gradient: { from: "violet", to: "pink" } },
                    { key: "proxy", label: "ПРОКСИРУЮТСЯ", icon: <IconRoute size={16} />, color: "teal", gradient: { from: "teal", to: "cyan" } },
                    { key: "direct", label: "НАПРЯМУЮ", icon: <IconArrowUpRight size={16} />, color: "gray", gradient: { from: "gray", to: "dark" } },
                    { key: "block", label: "ЗАБЛОКИРОВАНЫ", icon: <IconLock size={16} />, color: "red", gradient: { from: "red", to: "orange" } },
                  ];

                  const toggleGroup = (key: string) => {
                    setCollapsedGroups((prev) => ({ ...prev, [key]: !prev[key] }));
                  };

                  // Render a single process row
                  const renderProcessRow = (procName: string, group: string) => {
                    const connsList = groupedConnections[procName] || [];
                    const lastActivity = processTraffic[procName]?.last_activity || 0;
                    const isInactive = (Date.now() - lastActivity) > 5000;

                    let bg = "rgba(255, 255, 255, 0.01)";
                    let border = "1px solid var(--glass-border)";
                    let hoverBg = "rgba(255, 255, 255, 0.03)";
                    let boxShadow = "none";

                    if (group === "proxy") {
                      bg = "rgba(12, 196, 178, 0.04)";
                      border = "1px solid rgba(12, 196, 178, 0.15)";
                      hoverBg = "rgba(12, 196, 178, 0.08)";
                    } else if (group === "block") {
                      bg = "rgba(239, 68, 68, 0.04)";
                      border = "1px solid rgba(239, 68, 68, 0.15)";
                      hoverBg = "rgba(239, 68, 68, 0.08)";
                    }

                    if (highlightedProcesses[procName]) {
                      bg = "rgba(124, 58, 237, 0.2)";
                      border = "1px solid rgba(124, 58, 237, 0.5)";
                      hoverBg = "rgba(124, 58, 237, 0.25)";
                      boxShadow = "0 0 10px rgba(124, 58, 237, 0.25)";
                    }

                    // Action buttons: show all actions EXCEPT the current group
                    const actions = [
                      { key: "proxy", tooltip: "Проксировать", icon: <IconRoute size={14} />, color: "teal" },
                      { key: "direct", tooltip: "Напрямую", icon: <IconArrowUpRight size={14} />, color: "gray" },
                      { key: "block", tooltip: "Заблокировать", icon: <IconLock size={14} />, color: "red" },
                    ].filter((a) => a.key !== group);

                    return (
                      <Paper
                        key={procName}
                        p="xs"
                        radius="md"
                        style={{
                          cursor: "pointer",
                          transition: "all 0.15s ease",
                          background: bg,
                          border,
                          opacity: isInactive ? 0.6 : 1,
                          filter: isInactive ? "grayscale(100%)" : "none",
                          boxShadow,
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = hoverBg;
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = bg;
                        }}
                      >
                        <Group justify="space-between" wrap="nowrap" style={{ width: "100%" }}>
                          <Group gap="xs" wrap="nowrap" onClick={() => setSelectedProcessName(procName)} style={{ cursor: "pointer", flex: 1, minWidth: 0 }}>
                            <ThemeIcon size="sm" variant="gradient" gradient={{ from: "violet", to: "cyan" }} radius="sm">
                              <IconActivity size={14} />
                            </ThemeIcon>
                            <Text fw={600} size="sm" style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              {procName} <span style={{ fontWeight: 400, opacity: 0.6, fontSize: "11px" }}>(PID: {connsList[0]?.pid || "N/A"})</span>
                            </Text>
                          </Group>
                          <Group gap={4} wrap="nowrap" style={{ flexShrink: 0 }}>
                            {connsList.length > 0 && (
                              <Badge variant="filled" color="dark" size="xs" style={{ minWidth: "50px", textAlign: "center" }}>
                                {connsList.length}
                              </Badge>
                            )}
                            {processTraffic[procName] && (processTraffic[procName].sent > 0 || processTraffic[procName].recv > 0) && (
                              <>
                                <Badge size="xs" variant="light" color="cyan" leftSection="↑" style={{ minWidth: "75px" }}>
                                  {formatBytes(processTraffic[procName].sent)}
                                </Badge>
                                <Badge size="xs" variant="light" color="green" leftSection="↓" style={{ minWidth: "75px" }}>
                                  {formatBytes(processTraffic[procName].recv)}
                                </Badge>
                              </>
                            )}
                            <Divider orientation="vertical" color="var(--glass-border)" style={{ height: "20px", margin: "0 4px" }} />
                            {actions.map((action) => (
                              <Tooltip key={action.key} label={action.tooltip} position="top" withArrow>
                                <ActionIcon
                                  variant="subtle"
                                  color={action.color}
                                  size="sm"
                                  radius="md"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleSetProcessGroup(procName, action.key);
                                  }}
                                  style={{ transition: "all 0.15s ease" }}
                                >
                                  {action.icon}
                                </ActionIcon>
                              </Tooltip>
                            ))}
                          </Group>
                        </Group>
                      </Paper>
                    );
                  };

                  return (
                    <Stack gap="md">
                      {groupConfig.map((gc) => {
                        const items = groups[gc.key] || [];
                        if (items.length === 0) return null;
                        const isCollapsed = collapsedGroups[gc.key] || false;

                        return (
                          <div key={gc.key}>
                            <Paper
                              p="xs"
                              radius="md"
                              onClick={() => toggleGroup(gc.key)}
                              style={{
                                cursor: "pointer",
                                background: `rgba(${gc.color === "teal" ? "12, 196, 178" : gc.color === "red" ? "239, 68, 68" : gc.color === "violet" ? "124, 58, 237" : "120, 120, 130"}, 0.08)`,
                                border: `1px solid rgba(${gc.color === "teal" ? "12, 196, 178" : gc.color === "red" ? "239, 68, 68" : gc.color === "violet" ? "124, 58, 237" : "120, 120, 130"}, 0.25)`,
                                transition: "all 0.15s ease",
                                marginBottom: isCollapsed ? 0 : "4px",
                              }}
                            >
                              <Group justify="space-between" wrap="nowrap">
                                <Group gap="xs" wrap="nowrap">
                                  <ThemeIcon size="sm" variant="gradient" gradient={gc.gradient} radius="sm">
                                    {gc.icon}
                                  </ThemeIcon>
                                  <Text fw={700} size="xs" style={{ letterSpacing: "1px", textTransform: "uppercase" }}>
                                    {gc.label}
                                  </Text>
                                  <Badge size="xs" variant="filled" color={gc.color}>
                                    {items.length}
                                  </Badge>
                                </Group>
                                {isCollapsed ? <IconChevronRight size={16} /> : <IconChevronDown size={16} />}
                              </Group>
                            </Paper>
                            {!isCollapsed && (
                              <Stack gap={3} mt={4}>
                                {items.map((procName) => renderProcessRow(procName, gc.key))}
                              </Stack>
                            )}
                          </div>
                        );
                      })}
                    </Stack>
                  );
                })()}
              </ScrollArea>
            </Card>
          </Stack>
        )}

        <Modal
          opened={updateInfo !== null}
          onClose={() => {
            if (!isDownloadingUpdate) {
              setUpdateInfo(null);
            }
          }}
          title={
            <Group gap="xs">
              <ThemeIcon size="md" variant="gradient" gradient={{ from: "violet", to: "cyan" }} radius="md">
                <IconSparkles size={18} />
              </ThemeIcon>
              <Text fw={700} size="lg">
                Доступно обновление v{updateInfo?.version}
              </Text>
            </Group>
          }
          size="lg"
          radius="md"
          centered
          closeOnEscape={!isDownloadingUpdate}
          closeOnClickOutside={!isDownloadingUpdate}
          withCloseButton={!isDownloadingUpdate}
          styles={{
            content: {
              background: "rgba(20, 20, 25, 0.95)",
              backdropFilter: "blur(20px)",
              border: "1px solid rgba(255, 255, 255, 0.1)",
              color: "#fff"
            },
            header: {
              background: "rgba(20, 20, 25, 0.95)",
              color: "#fff"
            }
          }}
        >
          <Stack gap="md">
            {!isDownloadingUpdate ? (
              <>
                <Text size="sm" color="dimmed">
                  Новая версия <b>{updateInfo?.version}</b> готова к установке. Ниже приведено описание изменений:
                </Text>
                
                <Paper
                  p="md"
                  radius="md"
                  style={{
                    background: "rgba(255, 255, 255, 0.02)",
                    border: "1px solid var(--glass-border)",
                    maxHeight: "250px",
                    overflowY: "auto",
                    whiteSpace: "pre-wrap",
                    fontSize: "13px",
                    lineHeight: "1.6",
                    fontFamily: "Inter, sans-serif",
                    color: "rgba(255, 255, 255, 0.9)"
                  }}
                >
                  {updateInfo?.body || "Описания изменений нет."}
                </Paper>

                <Group justify="flex-end" mt="md">
                  <Button
                    variant="subtle"
                    color="gray"
                    onClick={() => setUpdateInfo(null)}
                    radius="md"
                  >
                    Позже
                  </Button>
                  <Button
                    variant="gradient"
                    gradient={{ from: "violet", to: "cyan" }}
                    onClick={handleDownloadAndInstall}
                    radius="md"
                  >
                    Скачать и установить
                  </Button>
                </Group>
              </>
            ) : (
              <Stack align="center" py="xl" gap="md">
                <Text fw={600} size="md">
                  {updateProgressText}
                </Text>
                <div style={{ width: "100%" }}>
                  <Progress
                    value={updateProgress}
                    size="xl"
                    radius="xl"
                    striped
                    animated
                    color="violet"
                  />
                </div>
                <Text size="xs" color="dimmed">
                  Пожалуйста, не закрывайте приложение до завершения обновления.
                </Text>
              </Stack>
            )}
          </Stack>
        </Modal>

        <Modal
          opened={selectedProcessName !== null}
          onClose={() => setSelectedProcessName(null)}
          title={
            <Group gap="xs">
              <ThemeIcon size="md" variant="gradient" gradient={{ from: "violet", to: "cyan" }} radius="md">
                <IconActivity size={18} />
              </ThemeIcon>
              <Text fw={700} size="lg">
                Детали процесса: {selectedProcessName}
              </Text>
            </Group>
          }
          size="xl"
          radius="md"
          centered
          styles={{
            content: {
              background: "rgba(20, 20, 25, 0.95)",
              backdropFilter: "blur(20px)",
              border: "1px solid rgba(255, 255, 255, 0.1)",
              color: "#fff"
            },
            header: {
              background: "rgba(20, 20, 25, 0.95)",
              color: "#fff"
            }
          }}
        >
          {selectedProcessName && (() => {
            const procName = selectedProcessName;
            const connsList = processConnHistory[procName] || [];
            const activeRule = rules.find((r) => r.process_name.toLowerCase() === procName.toLowerCase());
            
            // Total process traffic stats from global tracker
            const stats = processTraffic[procName] || { sent: 0, recv: 0, last_activity: 0 };
            const totalSentBytes = stats.sent;
            const totalRecvBytes = stats.recv;
            
            const activeConns = connsList.filter(c => c.status !== "Closed").length;
            const totalConns = connsList.length;
            const isProcessActive = (Date.now() - stats.last_activity) <= 5000;

            return (
              <Stack gap="md">
                {/* Real-time Traffic Metrics Cards */}
                <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
                  {/* Sent Card */}
                  <Paper
                    p="sm"
                    radius="md"
                    style={{
                      background: "rgba(12, 196, 178, 0.04)",
                      border: "1px solid rgba(12, 196, 178, 0.15)",
                      display: "flex",
                      alignItems: "center",
                      gap: "12px",
                    }}
                  >
                    <ThemeIcon color="teal" variant="light" size="lg" radius="md">
                      <IconArrowUpRight size={20} />
                    </ThemeIcon>
                    <div>
                      <Text size="xs" color="dimmed" fw={500}>ОТПРАВЛЕНО</Text>
                      <Text size="md" fw={700} style={{ color: "#0cc4b2", fontFamily: "Outfit, sans-serif" }}>
                        {formatBytes(totalSentBytes)}
                      </Text>
                    </div>
                  </Paper>

                  {/* Received Card */}
                  <Paper
                    p="sm"
                    radius="md"
                    style={{
                      background: "rgba(124, 58, 237, 0.04)",
                      border: "1px solid rgba(124, 58, 237, 0.15)",
                      display: "flex",
                      alignItems: "center",
                      gap: "12px",
                    }}
                  >
                    <ThemeIcon color="violet" variant="light" size="lg" radius="md">
                      <IconArrowDownLeft size={20} />
                    </ThemeIcon>
                    <div>
                      <Text size="xs" color="dimmed" fw={500}>ПОЛУЧЕНО</Text>
                      <Text size="md" fw={700} style={{ color: "#a78bfa", fontFamily: "Outfit, sans-serif" }}>
                        {formatBytes(totalRecvBytes)}
                      </Text>
                    </div>
                  </Paper>

                  {/* Active Connections Card */}
                  <Paper
                    p="sm"
                    radius="md"
                    style={{
                      background: "rgba(59, 130, 246, 0.04)",
                      border: "1px solid rgba(59, 130, 246, 0.15)",
                      display: "flex",
                      alignItems: "center",
                      gap: "12px",
                    }}
                  >
                    <ThemeIcon color="blue" variant="light" size="lg" radius="md">
                      <IconActivity size={20} />
                    </ThemeIcon>
                    <div style={{ flex: 1 }}>
                      <Group justify="space-between" align="center" wrap="nowrap">
                        <div>
                          <Text size="xs" color="dimmed" fw={500}>АКТИВНОСТЬ</Text>
                          <Text size="sm" fw={700} style={{ color: "#60a5fa", fontFamily: "Outfit, sans-serif" }}>
                            {activeConns} акт. / {totalConns} всего
                          </Text>
                        </div>
                        <Badge
                          color={isProcessActive ? "teal" : "gray"}
                          variant="dot"
                          size="sm"
                          style={{ textTransform: "none" }}
                        >
                          {isProcessActive ? "Активен" : "Сон"}
                        </Badge>
                      </Group>
                    </div>
                  </Paper>
                </SimpleGrid>

                {/* Quick routing rules panel */}
                <Paper
                  p="md"
                  radius="md"
                  style={{
                    background: "rgba(255, 255, 255, 0.02)",
                    border: "1px solid var(--glass-border)",
                  }}
                >
                  <Group justify="space-between" align="center" wrap="wrap" gap="md">
                    <Stack gap="xs" style={{ flexGrow: 1, minWidth: "200px" }}>
                      <Text size="xs" color="dimmed" fw={600} style={{ letterSpacing: "1px" }}>
                        БЫСТРОЕ ПРАВИЛО МАРШРУТИЗАЦИИ
                      </Text>
                      <Group gap="xs" wrap="nowrap">
                        <Text size="sm" fw={500} style={{ whiteSpace: "nowrap" }}>
                          Действие:
                        </Text>
                        <Badge
                          variant="filled"
                          size="sm"
                          color={
                            activeRule
                              ? activeRule.action === "Proxy"
                                ? "teal"
                                : activeRule.action === "Block"
                                ? "red"
                                : "gray"
                              : "gray"
                          }
                        >
                          {activeRule
                            ? activeRule.action === "Proxy"
                              ? `ПРОКСИ (${proxies.find(p => p.id === activeRule.proxy_id)?.name || proxies.find(p => p.is_primary)?.name || "Основной"})`
                              : activeRule.action === "Block"
                              ? "БЛОКИРОВАТЬ"
                              : "НАПРЯМУЮ"
                            : "ПО УМОЛЧАНИЮ (ПРЯМОЙ / ОБЩИЙ)"}
                        </Badge>
                      </Group>
                    </Stack>

                    <Group gap="xs" align="flex-end" wrap="wrap">
                      <Select
                        label="Маршрут"
                        size="xs"
                        data={[
                          { value: "Proxy", label: "Проксировать" },
                          { value: "Direct", label: "Напрямую" },
                          { value: "Block", label: "Блокировать" },
                        ]}
                        value={activeRule ? activeRule.action : "Direct"}
                        onChange={(val) => handleQuickRuleAction(procName, val as any)}
                        style={{ width: "135px" }}
                      />

                      {(!activeRule || activeRule.action === "Proxy") && (
                        <Select
                          label="Использовать прокси"
                          size="xs"
                          data={proxies.map((p) => ({
                            value: p.id,
                            label: `${p.name} ${p.is_primary ? "★" : ""}`,
                          }))}
                          value={activeRule?.proxy_id || proxies.find(p => p.is_primary)?.id || proxies[0]?.id || ""}
                          disabled={proxies.length === 0}
                          onChange={(val) => handleQuickRuleProxy(procName, val || "")}
                          placeholder={proxies.length === 0 ? "Нет прокси" : "Выберите прокси"}
                          style={{ width: "165px" }}
                        />
                      )}

                      {activeRule ? (
                        <Button
                          size="xs"
                          color="red"
                          variant="light"
                          onClick={() => handleQuickRuleDelete(procName)}
                          style={{ height: "30px" }}
                        >
                          Сбросить
                        </Button>
                      ) : (
                        <Button
                          size="xs"
                          color="violet"
                          variant="light"
                          onClick={() => handleQuickRuleCreate(procName)}
                          style={{ height: "30px" }}
                        >
                          Активировать
                        </Button>
                      )}
                    </Group>
                  </Group>
                </Paper>

                {/* Connections list */}
                <Text fw={600} size="sm">История сетевых соединений (до 100 последних)</Text>
                
                <div style={{
                  maxHeight: "400px",
                  overflowY: "auto",
                  paddingRight: "6px",
                  scrollbarWidth: "thin",
                  scrollbarColor: "rgba(255, 255, 255, 0.2) transparent",
                }}>
                  {connsList.length === 0 ? (
                    <Text color="dimmed" size="sm" py="xl" style={{ textAlign: 'center' }}>
                      Нет истории соединений для этого процесса.
                    </Text>
                  ) : (
                    <Table striped highlightOnHover verticalSpacing="xs">
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th style={{ fontSize: "11px" }}>Время</Table.Th>
                          <Table.Th style={{ fontSize: "11px" }}>Протокол</Table.Th>
                          <Table.Th style={{ fontSize: "11px" }}>Локальный адрес</Table.Th>
                          <Table.Th style={{ fontSize: "11px" }}>Адрес назначения</Table.Th>
                          <Table.Th style={{ fontSize: "11px" }}>Действие</Table.Th>
                          <Table.Th style={{ fontSize: "11px" }}>Объем (WinDivert)</Table.Th>
                          <Table.Th style={{ fontSize: "11px" }}>Статус</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {[...connsList].sort((a, b) => {
                          const aActive = a.status !== "Closed";
                          const bActive = b.status !== "Closed";
                          if (aActive && !bActive) return -1;
                          if (!aActive && bActive) return 1;
                          return b.timestamp - a.timestamp;
                        }).map((c) => (
                          <Table.Tr
                            key={c.id}
                            style={{
                              transition: "all 0.15s ease",
                              backgroundColor: highlightedConns[c.id]
                                ? "rgba(124, 58, 237, 0.25)"
                                : "transparent",
                              boxShadow: highlightedConns[c.id]
                                ? "inset 0 0 12px rgba(124, 58, 237, 0.3)"
                                : "none",
                              opacity: c.status === "Closed" ? 0.55 : 1,
                            }}
                          >
                            <Table.Td style={{ fontSize: "11px", color: "rgba(255, 255, 255, 0.75)", whiteSpace: "nowrap" }}>
                              {formatConnectionTime(c.timestamp)}
                            </Table.Td>
                            <Table.Td>
                              <Badge variant="outline" size="xs" color={c.protocol === "TCP" ? "cyan" : "orange"}>
                                {c.protocol}
                              </Badge>
                            </Table.Td>
                            <Table.Td style={{ fontSize: "11px" }}>{c.source_addr}</Table.Td>
                            <Table.Td style={{ fontSize: "11px", fontWeight: 500 }}>{c.original_dest}</Table.Td>
                            <Table.Td>
                              <Badge
                                size="xs"
                                color={
                                  activeRule
                                    ? activeRule.action === "Proxy"
                                      ? "teal"
                                      : activeRule.action === "Block"
                                      ? "red"
                                      : "gray"
                                    : c.action === "Proxy"
                                    ? "teal"
                                    : c.action === "Block"
                                    ? "red"
                                    : "gray"
                                }
                              >
                                {activeRule
                                  ? activeRule.action === "Proxy"
                                    ? "ПРОКСИ"
                                    : activeRule.action === "Block"
                                    ? "БЛОК"
                                    : "ПРЯМОЙ"
                                  : c.action === "Proxy"
                                  ? "ПРОКСИ"
                                  : c.action === "Block"
                                  ? "БЛОК"
                                  : "ПРЯМОЙ"}
                              </Badge>
                            </Table.Td>
                            <Table.Td style={{ fontSize: "11px" }}>
                              {c.bytes_sent > 0 || c.bytes_received > 0
                                ? formatBytes(c.bytes_sent + c.bytes_received)
                                : "—"}
                            </Table.Td>
                            <Table.Td>
                              <Badge
                                variant="dot"
                                size="xs"
                                color={
                                  c.status === "Proxied"
                                    ? "teal"
                                    : c.status === "Blocked"
                                    ? "red"
                                    : c.status === "Closed"
                                    ? "gray"
                                    : "blue"
                                }
                              >
                                {c.status === "Proxied"
                                  ? "Proxied"
                                  : c.status === "Blocked"
                                  ? "Blocked"
                                  : c.status === "Closed"
                                  ? "Closed"
                                  : "Active"}
                              </Badge>
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  )}
                </div>
              </Stack>
            );
          })()}
        </Modal>

        {/* TAB: Logs */}
        {activeTab === "logs" && (
          <Stack gap="md" style={{ height: "calc(100vh - 92px)", display: "flex", flexDirection: "column" }}>
            <Card radius="md" p="md" className="glass-panel" style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
              <Group justify="space-between" mb="md" align="center">
                <Group gap="xs">
                  <ThemeIcon size="md" variant="gradient" gradient={{ from: "red", to: "orange" }} radius="md">
                    <IconTerminal2 size={18} />
                  </ThemeIcon>
                  <Title order={4} style={{ fontFamily: "Outfit, sans-serif" }}>
                    СИСТЕМНЫЙ ЛОГ
                  </Title>
                  <Badge size="sm" variant="light" color="gray">
                    {appLogs.length} / 300
                  </Badge>
                </Group>

                <Group gap="md">
                  <SegmentedControl
                    value={logViewMode}
                    onChange={(val) => setLogViewMode(val || "all")}
                    data={[
                      { label: "Все логи", value: "all" },
                      { label: "По процессам", value: "by_process" },
                    ]}
                    size="xs"
                    radius="md"
                    color="violet"
                    styles={{
                      root: {
                        background: "rgba(255, 255, 255, 0.02)",
                        border: "1px solid var(--glass-border)",
                      }
                    }}
                  />

                  <Tooltip label="Очистить все записи">
                    <ActionIcon
                      variant="light"
                      color="red"
                      size="lg"
                      radius="md"
                      onClick={handleClearLogs}
                      disabled={appLogs.length === 0}
                    >
                      <IconClearAll size={18} />
                    </ActionIcon>
                  </Tooltip>
                </Group>
              </Group>

              <ScrollArea style={{ flex: 1, minHeight: 0 }}>
                {logViewMode === "by_process" ? (() => {
                  // Group logs by process
                  const groups: Record<string, LogEntry[]> = {};
                  appLogs.forEach((log) => {
                    const proc = log.process_name || "Система / Глобальные";
                    if (!groups[proc]) {
                      groups[proc] = [];
                    }
                    groups[proc].push(log);
                  });

                  const processNames = Object.keys(groups).sort((a, b) => {
                    if (a === "Система / Глобальные") return 1;
                    if (b === "Система / Глобальные") return -1;
                    return a.localeCompare(b);
                  });

                  if (appLogs.length === 0) {
                    return (
                      <Text color="dimmed" size="sm" style={{ textAlign: "center", fontFamily: "'JetBrains Mono', monospace", padding: "40px 0" }}>
                        Лог пуст. Ошибки приложения будут отображаться здесь в реальном времени.
                      </Text>
                    );
                  }

                  const renderConsoleLogs = (logs: LogEntry[]) => {
                    return (
                      <div style={{
                        background: "#050508",
                        borderRadius: "6px",
                        padding: "8px 12px",
                        fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
                        fontSize: "12px",
                        lineHeight: "1.7",
                        marginTop: "8px",
                      }}>
                        {logs.map((log, idx) => {
                          const date = new Date(log.timestamp);
                          const timeStr = `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
                          const dateStr = `${String(date.getDate()).padStart(2, '0')}.${String(date.getMonth() + 1).padStart(2, '0')}`;

                          const levelColors: Record<string, string> = {
                            error: "#ff4757",
                            warn: "#ffa502",
                            info: "#70a1ff",
                          };
                          const levelLabels: Record<string, string> = {
                            error: "ERROR",
                            warn: " WARN",
                            info: " INFO",
                          };
                          const sourceColors: Record<string, string> = {
                            relay: "#00d2d3",
                            windivert: "#a78bfa",
                            engine: "#60a5fa",
                            system: "#78909c",
                          };
                          const levelColor = levelColors[log.level] || "#aaa";
                          const srcColor = sourceColors[log.source] || "#aaa";

                          return (
                            <div
                              key={log.id || idx}
                              style={{
                                borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                                padding: "4px 0",
                                display: "flex",
                                gap: "8px",
                                alignItems: "flex-start",
                              }}
                            >
                              <span style={{ color: "rgba(255, 255, 255, 0.3)", whiteSpace: "nowrap", flexShrink: 0 }}>
                                {dateStr} {timeStr}
                              </span>
                              <span style={{
                                color: levelColor,
                                fontWeight: 700,
                                flexShrink: 0,
                                textShadow: `0 0 8px ${levelColor}33`,
                              }}>
                                {levelLabels[log.level] || log.level.toUpperCase().padStart(5)}
                              </span>
                              <span style={{
                                color: srcColor,
                                fontWeight: 600,
                                flexShrink: 0,
                                minWidth: "70px",
                              }}>
                                {log.source}
                              </span>
                              <span style={{
                                color: "rgba(255, 255, 255, 0.85)",
                                wordBreak: "break-all",
                              }}>
                                {log.message}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    );
                  };

                  return (
                    <Accordion
                      variant="separated"
                      defaultValue={processNames[0]}
                      styles={{
                        item: {
                          background: "rgba(255, 255, 255, 0.01)",
                          border: "1px solid var(--glass-border)",
                          borderRadius: "8px",
                          marginBottom: "10px",
                          overflow: "hidden",
                          transition: "all 0.2s ease",
                          "&[data-active]": {
                            background: "rgba(255, 255, 255, 0.03)",
                            borderColor: "rgba(124, 58, 237, 0.3)",
                            boxShadow: "0 4px 20px rgba(0, 0, 0, 0.15)",
                          }
                        },
                        control: {
                          padding: "12px 16px",
                          "&:hover": {
                            background: "rgba(255, 255, 255, 0.02)",
                          }
                        },
                        content: {
                          padding: "0 16px 16px 16px",
                          background: "rgba(0, 0, 0, 0.15)",
                        }
                      }}
                    >
                      {processNames.map((procName) => {
                        const procLogs = groups[procName];
                        const errs = procLogs.filter((l) => l.level === "error").length;
                        const warns = procLogs.filter((l) => l.level === "warn").length;

                        return (
                          <Accordion.Item key={procName} value={procName}>
                            <Accordion.Control>
                              <Group justify="space-between" wrap="nowrap" style={{ width: "100%", paddingRight: "16px" }}>
                                <Group gap="xs" wrap="nowrap">
                                  <ThemeIcon size="sm" color="violet" variant="light">
                                    <IconTerminal2 size={12} />
                                  </ThemeIcon>
                                  <Text fw={600} size="sm" style={{ color: "#ffffff" }}>
                                    {procName}
                                  </Text>
                                </Group>
                                <Group gap="xs" style={{ flexShrink: 0 }}>
                                  {errs > 0 && (
                                    <Badge color="red" variant="filled" size="xs">
                                      {errs} {errs === 1 ? "ошибка" : errs < 5 ? "ошибки" : "ошибок"}
                                    </Badge>
                                  )}
                                  {warns > 0 && (
                                    <Badge color="orange" variant="filled" size="xs">
                                      {warns} {warns === 1 ? "предупреждение" : warns < 5 ? "предупреждения" : "предупреждений"}
                                    </Badge>
                                  )}
                                  <Badge color="gray" variant="light" size="xs">
                                    Всего: {procLogs.length}
                                  </Badge>
                                </Group>
                              </Group>
                            </Accordion.Control>
                            <Accordion.Panel>
                              {renderConsoleLogs(procLogs)}
                            </Accordion.Panel>
                          </Accordion.Item>
                        );
                      })}
                    </Accordion>
                  );
                })() : (
                  <div style={{
                    background: "#0a0a0f",
                    borderRadius: "8px",
                    border: "1px solid rgba(255, 255, 255, 0.06)",
                    padding: "12px",
                    fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
                    fontSize: "12px",
                    lineHeight: "1.8",
                    minHeight: "300px",
                  }}>
                    {appLogs.length === 0 ? (
                      <Text color="dimmed" size="sm" style={{ textAlign: "center", fontFamily: "'JetBrains Mono', monospace", padding: "40px 0" }}>
                        Лог пуст. Ошибки приложения будут отображаться здесь в реальном времени.
                      </Text>
                    ) : (
                      appLogs.map((log, idx) => {
                        const date = new Date(log.timestamp);
                        const timeStr = `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
                        const dateStr = `${String(date.getDate()).padStart(2, '0')}.${String(date.getMonth() + 1).padStart(2, '0')}`;

                        const levelColors: Record<string, string> = {
                          error: "#ff4757",
                          warn: "#ffa502",
                          info: "#70a1ff",
                        };
                        const levelLabels: Record<string, string> = {
                          error: "ERROR",
                          warn: " WARN",
                          info: " INFO",
                        };
                        const sourceColors: Record<string, string> = {
                          relay: "#00d2d3",
                          windivert: "#a78bfa",
                          engine: "#60a5fa",
                          system: "#78909c",
                        };
                        const levelColor = levelColors[log.level] || "#aaa";
                        const srcColor = sourceColors[log.source] || "#aaa";

                        return (
                          <div
                            key={log.id || idx}
                            style={{
                              borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                              padding: "4px 0",
                              display: "flex",
                              gap: "8px",
                              alignItems: "flex-start",
                              transition: "background 0.15s ease",
                            }}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.background = "rgba(255, 255, 255, 0.03)";
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.background = "transparent";
                            }}
                          >
                            <span style={{ color: "rgba(255, 255, 255, 0.3)", whiteSpace: "nowrap", flexShrink: 0 }}>
                              {dateStr} {timeStr}
                            </span>
                            <span style={{
                              color: levelColor,
                              fontWeight: 700,
                              flexShrink: 0,
                              textShadow: `0 0 8px ${levelColor}33`,
                            }}>
                              {levelLabels[log.level] || log.level.toUpperCase().padStart(5)}
                            </span>
                            <span style={{
                              color: srcColor,
                              fontWeight: 600,
                              flexShrink: 0,
                              minWidth: "70px",
                            }}>
                              {log.source}
                            </span>
                            {log.process_name && (
                              <Badge size="xs" color="violet" variant="outline" style={{ flexShrink: 0, textTransform: "none" }}>
                                {log.process_name}
                              </Badge>
                            )}
                            <span style={{
                              color: "rgba(255, 255, 255, 0.85)",
                              wordBreak: "break-all",
                            }}>
                              {log.message}
                            </span>
                          </div>
                        );
                      })
                    )}
                  </div>
                )}
              </ScrollArea>
            </Card>
          </Stack>
        )}

        {/* TAB: Rules */}
        {activeTab === "rules" && (
          <Stack gap="lg">
            <Card radius="md" p="md" className="glass-panel">
              <Title order={4} mb="md" style={{ fontFamily: "Outfit, sans-serif" }}>
                ДОБАВИТЬ ПРАВИЛО ФИЛЬТРАЦИИ
              </Title>
              <Group grow align="flex-end" gap="md">
                <TextInput
                  label="Имя исполняемого файла"
                  placeholder="Пример: chrome.exe или *telegram.exe"
                  value={newProcessName}
                  onChange={(e) => setNewProcessName(e.target.value)}
                  radius="md"
                />
                <Select
                  label="Действие"
                  data={[
                    { value: "Proxy", label: "Проксировать через туннель" },
                    { value: "Direct", label: "Направлять напрямую (Direct)" },
                    { value: "Block", label: "Блокировать (Drop)" },
                  ]}
                  value={newAction}
                  onChange={(val) => setNewAction(val || "Proxy")}
                  radius="md"
                />
                
                {newAction === "Proxy" && (
                  <Select
                    label="Выбор прокси"
                    placeholder="Выберите прокси..."
                    data={proxies.map((p) => ({
                      value: p.id,
                      label: `${p.name} (${p.host}:${p.port}) ${p.is_primary ? "★" : ""}`,
                    }))}
                    value={selectedProxyId}
                    onChange={(val) => setSelectedProxyId(val || "")}
                    radius="md"
                  />
                )}
                
                <Button
                  onClick={handleAddRule}
                  radius="md"
                  color="violet"
                  leftSection={<IconPlus size={16} />}
                  className="interactive-element"
                >
                  Добавить
                </Button>
              </Group>
            </Card>

            <Card radius="md" p="md" className="glass-panel">
              <Title order={4} mb="md" style={{ fontFamily: "Outfit, sans-serif" }}>
                СПИСОК ТЕКУЩИХ ПРАВИЛ
              </Title>
              <Divider mb="md" color="var(--glass-border)" />
              <Stack gap="sm">
                {rules.length === 0 ? (
                  <Text color="dimmed" style={{ textAlign: "center" }}>
                    Правила не заданы. Будут применены настройки по умолчанию.
                  </Text>
                ) : (
                  rules.map((rule) => {
                    const assignedProxy = proxies.find((p) => p.id === rule.proxy_id);
                    return (
                      <Paper
                        key={rule.id}
                        p="md"
                        radius="md"
                        className="interactive-element"
                        style={{
                          background: "rgba(255, 255, 255, 0.02)",
                          border: "1px solid var(--glass-border)",
                        }}
                      >
                        <Group justify="space-between">
                          <Group>
                            <ThemeIcon color="violet" variant="light" size="md">
                              <IconShield size={16} />
                            </ThemeIcon>
                            <Text fw={600}>{rule.process_name}</Text>
                          </Group>
                          <Group>
                            {rule.action === "Proxy" && assignedProxy && (
                              <Badge variant="light" color="cyan">
                                {assignedProxy.name} ({assignedProxy.host}:{assignedProxy.port})
                              </Badge>
                            )}
                            <Badge
                              size="lg"
                              color={
                                rule.action === "Proxy" ? "teal" : rule.action === "Block" ? "red" : "gray"
                              }
                            >
                              {rule.action === "Proxy" ? "ПРОКСИ" : rule.action === "Block" ? "БЛОК" : "ПРЯМОЙ"}
                            </Badge>
                            <ActionIcon
                              color="red"
                              variant="subtle"
                              onClick={() => handleDeleteRule(rule.id)}
                              className="interactive-element"
                            >
                              <IconTrash size={16} />
                            </ActionIcon>
                          </Group>
                        </Group>
                      </Paper>
                    );
                  })
                )}
              </Stack>
            </Card>
          </Stack>
        )}

        {/* TAB: Proxy Settings */}
        {activeTab === "proxy_settings" && (
          <Stack gap="lg">
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg">
              {/* Proxy List */}
              <Card radius="md" p="md" className="glass-panel">
                <Title order={4} mb="md" style={{ fontFamily: "Outfit, sans-serif" }}>
                  СПИСОК ПРОКСИ-СЕРВЕРОВ
                </Title>
                <Divider mb="md" color="var(--glass-border)" />
                <ScrollArea h={340}>
                  <Stack gap="sm">
                    {proxies.length === 0 ? (
                      <Text color="dimmed" style={{ textAlign: "center" }}>
                        Прокси-серверы не добавлены. Добавьте хотя бы один справа.
                      </Text>
                    ) : (
                      proxies.map((p) => (
                        <Paper
                          key={p.id}
                          p="sm"
                          radius="md"
                          style={{
                            background: "rgba(255, 255, 255, 0.01)",
                            border: "1px solid var(--glass-border)",
                          }}
                        >
                          <Group justify="space-between">
                            <Group gap="xs">
                              <ActionIcon
                                variant="transparent"
                                onClick={() => handleSetPrimaryProxy(p.id)}
                                color={p.is_primary ? "yellow" : "gray"}
                              >
                                {p.is_primary ? <IconStarFilled size={18} /> : <IconStar size={18} />}
                              </ActionIcon>
                              <div>
                                <Text fw={600} size="sm">
                                  {p.name} {p.is_primary && <Badge size="xs" color="yellow">ОСНОВНОЙ</Badge>}
                                </Text>
                                <Text size="xs" color="dimmed">
                                  {p.proxy_type} | {p.host}:{p.port}
                                </Text>
                              </div>
                            </Group>
                            
                            <Group>
                              <Badge color="violet">{p.proxy_type}</Badge>
                              <ActionIcon
                                color="red"
                                variant="subtle"
                                onClick={() => handleDeleteProxy(p.id)}
                              >
                                <IconTrash size={16} />
                              </ActionIcon>
                            </Group>
                          </Group>
                        </Paper>
                      ))
                    )}
                  </Stack>
                </ScrollArea>
              </Card>

              {/* Add Proxy Form */}
              <Card radius="md" p="md" className="glass-panel">
                <Title order={4} mb="sm" style={{ fontFamily: "Outfit, sans-serif" }}>
                  ДОБАВИТЬ ПРОКСИ-СЕРВЕР
                </Title>
                <Divider mb="sm" color="var(--glass-border)" />
                
                <Stack gap="xs">
                  <TextInput
                    label="Быстрый импорт из строки"
                    placeholder="Пример: socks5://user:pass@192.168.1.1:1080"
                    value={connectionString}
                    onChange={(e) => handleParseString(e.target.value)}
                    radius="md"
                    size="xs"
                    rightSection={
                      <Tooltip label="Вставьте строку подключения прокси">
                        <IconCopy size={14} color="gray" />
                      </Tooltip>
                    }
                  />

                  <TextInput
                    label="Название подключения"
                    placeholder="Название прокси..."
                    value={newProxyName}
                    onChange={(e) => setNewProxyName(e.target.value)}
                    radius="md"
                    size="xs"
                  />

                  <Select
                    label="Протокол прокси"
                    data={[
                      { value: "SOCKS5", label: "SOCKS5" },
                      { value: "HTTP", label: "HTTP Tunnel (CONNECT)" },
                    ]}
                    value={proxyType}
                    onChange={(val) => setProxyType(val || "SOCKS5")}
                    radius="md"
                    size="xs"
                  />

                  <Group grow gap="xs">
                    <TextInput
                      label="Адрес сервера"
                      placeholder="127.0.0.1"
                      value={proxyHost}
                      onChange={(e) => setProxyHost(e.target.value)}
                      radius="md"
                      size="xs"
                    />
                    <NumberInput
                      label="Порт"
                      placeholder="1080"
                      value={proxyPort}
                      onChange={(val) => setProxyPort(Number(val) || 1080)}
                      radius="md"
                      size="xs"
                    />
                  </Group>

                  <Group grow gap="xs">
                    <TextInput
                      label="Логин (опционально)"
                      placeholder="user"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      radius="md"
                      size="xs"
                    />
                    <TextInput
                      label="Пароль (опционально)"
                      type="password"
                      placeholder="pass"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      radius="md"
                      size="xs"
                    />
                  </Group>

                  <Checkbox
                    label="Сделать основным"
                    checked={isPrimaryChecked}
                    onChange={(e) => setIsPrimaryChecked(e.currentTarget.checked)}
                    mt="xs"
                    color="violet"
                    size="xs"
                  />

                  <Button
                    color="violet"
                    onClick={handleAddProxy}
                    radius="md"
                    mt="xs"
                    size="sm"
                    className="interactive-element"
                    leftSection={<IconPlus size={16} />}
                  >
                    Добавить в список
                  </Button>
                </Stack>
              </Card>
            </SimpleGrid>
          </Stack>
        )}

        {/* TAB: App Settings */}
        {activeTab === "settings" && (
          <Tabs defaultValue="general" color="violet" variant="outline" styles={{
            root: {
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
            },
            tab: {
              borderBottomWidth: '2px',
              padding: '12px 18px',
              fontWeight: 600,
              fontSize: '14px',
              color: 'rgba(255, 255, 255, 0.65)',
              transition: 'all 0.15s ease',
              '&:hover': {
                color: '#ffffff',
                background: 'rgba(255, 255, 255, 0.02)',
              },
              '&[data-active]': {
                color: '#ffffff',
                borderColor: '#7c3aed',
              }
            },
            panel: {
              paddingTop: '8px',
            }
          }}>
            <Tabs.List style={{ borderBottom: '1px solid var(--glass-border)' }}>
              <Tabs.Tab value="general" leftSection={<IconSettings size={16} />}>
                Основные
              </Tabs.Tab>
              <Tabs.Tab value="changelog" leftSection={<IconHistory size={16} />}>
                История изменений
              </Tabs.Tab>
            </Tabs.List>

            <Tabs.Panel value="general">
              <Stack gap="lg">
                {/* Engine Options */}
                <Card radius="md" p="md" className="glass-panel">
                  <Title order={4} mb="md" style={{ fontFamily: "Outfit, sans-serif" }}>
                    НАСТРОЙКИ МАРШРУТИЗАЦИИ
                  </Title>
                  <Divider mb="md" color="var(--glass-border)" />
                  <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg">
                    <Switch
                      label="Пускать DNS-запросы через прокси"
                      checked={proxyDns}
                      onChange={(e) => {
                        const val = e.currentTarget.checked;
                        setProxyDns(val);
                        handleSaveSettings(val, bypassLocal, autostart, minimizeToTray, startMinimized);
                      }}
                      size="md"
                      color="violet"
                    />
                    <Switch
                      label="Обходить локальные адреса (Intranet/Bypass Local)"
                      checked={bypassLocal}
                      onChange={(e) => {
                        const val = e.currentTarget.checked;
                        setBypassLocal(val);
                        handleSaveSettings(proxyDns, val, autostart, minimizeToTray, startMinimized);
                      }}
                      size="md"
                      color="violet"
                    />
                  </SimpleGrid>
                </Card>

                {/* Autostart/Window options */}
                <Card radius="md" p="md" className="glass-panel">
                  <Title order={4} mb="md" style={{ fontFamily: "Outfit, sans-serif" }}>
                    ПАРАМЕТРЫ ЗАПУСКА СИСТЕМЫ
                  </Title>
                  <Divider mb="md" color="var(--glass-border)" />
                  <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="lg">
                    <Switch
                      label="Запускать с системой"
                      checked={autostart}
                      onChange={(e) => {
                        const val = e.currentTarget.checked;
                        setAutostart(val);
                        handleSaveSettings(proxyDns, bypassLocal, val, minimizeToTray, startMinimized);
                      }}
                      size="md"
                      color="violet"
                    />

                    <Switch
                      label="Сворачивать при закрытии"
                      checked={minimizeToTray}
                      onChange={(e) => {
                        const val = e.currentTarget.checked;
                        setMinimizeToTray(val);
                        handleSaveSettings(proxyDns, bypassLocal, autostart, val, startMinimized);
                      }}
                      size="md"
                      color="violet"
                    />

                    <Switch
                      label="Запускать свернутым в трее"
                      checked={startMinimized}
                      onChange={(e) => {
                        const val = e.currentTarget.checked;
                        setStartMinimized(val);
                        handleSaveSettings(proxyDns, bypassLocal, autostart, minimizeToTray, val);
                      }}
                      size="md"
                      color="violet"
                    />
                  </SimpleGrid>
                </Card>

                {/* System Update Card */}
                <Card radius="md" p="md" className="glass-panel">
                  <Title order={4} mb="md" style={{ fontFamily: "Outfit, sans-serif" }}>
                    ОБНОВЛЕНИЕ СИСТЕМЫ
                  </Title>
                  <Divider mb="md" color="var(--glass-border)" />
                  <Group justify="space-between" align="center">
                    <div>
                      <Text size="sm" color="dimmed">
                        Текущая версия приложения: <b>v{appVersion}</b>
                      </Text>
                      <Text size="xs" color="dimmed" mt="xs">
                        При выходе нового релиза на GitHub вы сможете обновить приложение в один клик.
                      </Text>
                    </div>
                    <Button
                      onClick={() => handleManualUpdateCheck(false)}
                      loading={isCheckingUpdate}
                      radius="md"
                      color="violet"
                      leftSection={<IconRefresh size={16} />}
                      className="interactive-element"
                    >
                      Проверить обновления
                    </Button>
                  </Group>
                </Card>
              </Stack>
            </Tabs.Panel>

            <Tabs.Panel value="changelog">
              <Card radius="md" p="md" className="glass-panel">
                <Group justify="space-between" mb="md" align="center">
                  <div>
                    <Title order={4} style={{ fontFamily: "Outfit, sans-serif" }}>
                      ИСТОРИЯ ИЗМЕНЕНИЙ (CHANGELOG)
                    </Title>
                    <Text size="xs" color="dimmed" mt="xs">
                      Официальные релизы из репозитория GitHub
                    </Text>
                  </div>
                  <Badge size="lg" color="violet" variant="light">
                    Текущая версия: v{appVersion}
                  </Badge>
                </Group>
                <Divider mb="md" color="var(--glass-border)" />

                {isLoadingReleases ? (
                  <Stack gap="sm" py="xl">
                    <Skeleton height={40} radius="md" />
                    <Skeleton height={20} radius="md" />
                    <Skeleton height={20} radius="md" />
                    <Skeleton height={20} width="70%" radius="md" />
                    <Divider my="md" color="rgba(255, 255, 255, 0.05)" />
                    <Skeleton height={40} radius="md" />
                    <Skeleton height={20} radius="md" />
                  </Stack>
                ) : releasesError ? (
                  <Stack align="center" py="xl" gap="sm">
                    <Text color="red" size="sm">
                      {releasesError}
                    </Text>
                    <Button variant="light" color="violet" size="xs" onClick={fetchReleases}>
                      Повторить загрузку
                    </Button>
                  </Stack>
                ) : releases.length === 0 ? (
                  <Text color="dimmed" size="sm" style={{ textAlign: 'center' }} py="xl">
                    История изменений пуста или не загружена.
                  </Text>
                ) : (
                  <ScrollArea h={500} scrollbarSize={6}>
                    <Stack gap="lg" pr="md">
                      {releases.map((rel) => {
                        const date = new Date(rel.published_at);
                        const dateStr = date.toLocaleDateString("ru-RU", {
                          year: "numeric",
                          month: "long",
                          day: "numeric",
                        });
                        return (
                          <Paper
                            key={rel.id}
                            p="md"
                            radius="md"
                            style={{
                              background: "rgba(255, 255, 255, 0.01)",
                              border: "1px solid var(--glass-border)",
                              transition: "all 0.15s ease",
                            }}
                          >
                            <Group justify="space-between" mb="xs">
                              <Group gap="xs">
                                <Text fw={700} size="md" color="violet">
                                  {rel.name || rel.tag_name}
                                </Text>
                                {appVersion === rel.tag_name.replace(/^v/, "") && (
                                  <Badge size="xs" color="teal">Текущая версия</Badge>
                                )}
                              </Group>
                              <Text size="xs" color="dimmed">
                                {dateStr}
                              </Text>
                            </Group>
                            <Text
                              size="sm"
                              style={{
                                whiteSpace: "pre-wrap",
                                fontFamily: "sans-serif",
                                color: "rgba(255, 255, 255, 0.85)",
                                lineHeight: "1.6",
                              }}
                            >
                              {rel.body}
                            </Text>
                            <Divider my="sm" color="rgba(255, 255, 255, 0.05)" />
                            <Group justify="flex-end">
                              <Button
                                component="a"
                                href={rel.html_url}
                                target="_blank"
                                rel="noreferrer"
                                size="xs"
                                variant="subtle"
                                color="violet"
                                rightSection={<IconArrowUpRight size={12} />}
                              >
                                Открыть на GitHub
                              </Button>
                            </Group>
                          </Paper>
                        );
                      })}
                    </Stack>
                  </ScrollArea>
                )}
              </Card>
            </Tabs.Panel>
          </Tabs>
        )}
      </AppShell.Main>
    </AppShell>
  );
}

export default App;
