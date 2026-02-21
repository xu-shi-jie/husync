use clap::Parser;
use colored::*;
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event as CtEvent, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedConfig {
    #[serde(default)]
    project_root: String,
    directories: Vec<String>,
    remote_user: String,
    remote_host: String,
    remote_base: String,
    debounce: f64,
    ssh_key: String,
    verbose: bool,
    #[serde(default = "default_timeout_max_seconds")]
    timeout_max: u64,
}

fn default_timeout_max_seconds() -> u64 {
    300
}

impl SavedConfig {
    fn config_dir_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".husync")
    }

    fn config_file_path() -> PathBuf {
        Self::config_dir_path().join("configs.json")
    }

    fn legacy_config_file_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".husync")
    }

    fn current_project_root() -> Result<String, String> {
        let cwd = std::env::current_dir().map_err(|e| format!("failed to read cwd: {}", e))?;
        let canonical = cwd
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize cwd: {}", e))?;
        Ok(canonical.to_string_lossy().to_string())
    }

    fn load_all() -> Result<Vec<Self>, String> {
        let path = Self::config_file_path();
        if path.exists() {
            let content = fs::read_to_string(&path)
                .map_err(|e| format!("failed to read config: {}", e))?;
            let configs: Vec<Self> = serde_json::from_str(&content)
                .map_err(|e| format!("failed to parse config: {}", e))?;
            return Ok(configs);
        }
        let legacy = Self::legacy_config_file_path();
        if legacy.exists() && legacy.is_file() {
            let content = fs::read_to_string(&legacy)
                .map_err(|e| format!("failed to read legacy config: {}", e))?;
            let configs: Vec<Self> = serde_json::from_str(&content)
                .map_err(|e| format!("failed to parse legacy config: {}", e))?;
            return Ok(configs);
        }
        Ok(Vec::new())
    }

    fn save(&self) -> Result<(), String> {
        let mut configs = Self::load_all().unwrap_or_default();

        // Keep exactly one config per project_root; latest run overwrites previous values.
        if let Some(existing) = configs.iter_mut().find(|c| c.project_root == self.project_root) {
            *existing = self.clone();
        } else {
            configs.push(self.clone());
        }

        let dir = Self::config_dir_path();
        if dir.exists() && dir.is_file() {
            let backup = dir.with_extension("legacy.json");
            fs::rename(&dir, &backup).map_err(|e| {
                format!(
                    "failed to migrate legacy config file {} -> {}: {}",
                    dir.display(),
                    backup.display(),
                    e
                )
            })?;
        }
        fs::create_dir_all(&dir).map_err(|e| format!("failed to create config dir: {}", e))?;
        let path = Self::config_file_path();
        let content = serde_json::to_string_pretty(&configs)
            .map_err(|e| format!("failed to serialize config: {}", e))?;
        fs::write(&path, content)
            .map_err(|e| format!("failed to write config: {}", e))?;
        Ok(())
    }

}

#[derive(Debug, Clone)]
struct SyncConfig {
    remote_user: String,
    remote_host: String,
    remote_base: String,
    ssh_key: String,
    debounce_seconds: f64,
    exclude_patterns: Vec<String>,
    verbose: bool,
    timeout_max_seconds: u64,
}

impl SyncConfig {
    fn new(args: &Args) -> Self {
        let ssh_key = if args.ssh_key.starts_with("~/") {
            let home = std::env::var("HOME").unwrap_or_else(|_| String::from("~"));
            format!("{}/{}", home, &args.ssh_key[2..])
        } else {
            args.ssh_key.clone()
        };

        Self {
            remote_user: args.remote_user.as_ref().unwrap().clone(),
            remote_host: args.remote_host.as_ref().unwrap().clone(),
            remote_base: args.remote_base.as_ref().unwrap().clone(),
            ssh_key,
            debounce_seconds: args.debounce,
            exclude_patterns: vec![
                ".git/".to_string(),
                "wandb/".to_string(),
                "lightning_logs/".to_string(),
                "checkpoints/".to_string(),
                ".venv/".to_string(),
                "venv/".to_string(),
                "**/__pycache__/".to_string(),
                "outputs/".to_string(),
                "*.pyc".to_string(),
                "*.pyo".to_string(),
                ".DS_Store".to_string(),
                "tmp/".to_string(),
            ],
            verbose: args.verbose,
            timeout_max_seconds: args.timeout_max,
        }
    }
}

fn time_ago(ts: SystemTime) -> String {
    let now = SystemTime::now();
    let diff = now.duration_since(ts).unwrap_or_else(|_| Duration::from_secs(0));
    let secs = diff.as_secs();

    if secs < 1 {
        "just now".to_string()
    } else if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

fn colorize_message(msg: &str) -> ColoredString {
    if msg.starts_with("ERROR") {
        msg.red().bold()
    } else if msg.starts_with("WARN") {
        msg.yellow()
    } else if msg.contains("(file)") {
        msg.truecolor(255, 165, 0)
    } else if msg.starts_with("OK")
        || msg.starts_with("WATCH")
        || msg.starts_with("Starting")
        || msg.starts_with("Initial")
        || msg.starts_with("Syncing")
    {
        msg.green()
    } else {
        msg.normal()
    }
}

fn should_show_status_line(line: &str) -> bool {
    !line.trim().is_empty()
}

fn pump_rsync_stream<R: Read>(
    mut reader: R,
    progress_tx: Sender<String>,
    capture: Option<Arc<Mutex<String>>>,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);
                let mut start = 0usize;
                for i in 0..pending.len() {
                    if pending[i] == b'\n' || pending[i] == b'\r' {
                        if i > start {
                            let raw = String::from_utf8_lossy(&pending[start..i]).to_string();
                            let line = raw.trim().to_string();
                            if !line.is_empty() {
                                if should_show_status_line(&line) {
                                    let _ = progress_tx.send(line.clone());
                                }
                                if let Some(cap) = &capture {
                                    if let Ok(mut s) = cap.lock() {
                                        s.push_str(&line);
                                        s.push('\n');
                                    }
                                }
                            }
                        }
                        start = i + 1;
                    }
                }
                if start > 0 {
                    pending.drain(0..start);
                }
            }
            Err(_) => break,
        }
    }
    if !pending.is_empty() {
        let raw = String::from_utf8_lossy(&pending).to_string();
        let line = raw.trim().to_string();
        if !line.is_empty() {
            if should_show_status_line(&line) {
                let _ = progress_tx.send(line.clone());
            }
            if let Some(cap) = &capture {
                if let Ok(mut s) = cap.lock() {
                    s.push_str(&line);
                    s.push('\n');
                }
            }
        }
    }
}

struct ScrollingDisplay {
    max_log_lines: usize,
    logs: VecDeque<(SystemTime, String)>,
    header_lines: Vec<String>,
    rsync_lines: VecDeque<String>,
    rsync_window_active: bool,
    rsync_window_lines: usize,
    total_lines_drawn: usize,
}

impl ScrollingDisplay {
    fn new(max_log_lines: usize) -> Self {
        Self {
            max_log_lines,
            logs: VecDeque::new(),
            header_lines: Vec::new(),
            rsync_lines: VecDeque::new(),
            rsync_window_active: false,
            rsync_window_lines: 5,
            total_lines_drawn: 0,
        }
    }

    fn set_header(&mut self, lines: Vec<String>) {
        self.header_lines = lines;
    }

    fn add_log(&mut self, message: String) {
        self.logs.push_back((SystemTime::now(), message));
        while self.logs.len() > self.max_log_lines {
            self.logs.pop_front();
        }
        self.redraw();
    }

    fn begin_rsync_output(&mut self) {
        self.rsync_window_active = true;
        self.rsync_lines.clear();
        self.redraw();
    }

    fn push_rsync_output(&mut self, line: String) {
        self.rsync_window_active = true;
        self.rsync_lines.push_back(line);
        while self.rsync_lines.len() > self.rsync_window_lines {
            self.rsync_lines.pop_front();
        }
        self.redraw();
    }

    fn end_rsync_output(&mut self) {
        self.rsync_window_active = false;
        self.rsync_lines.clear();
        self.redraw();
    }

    fn redraw(&mut self) {
        if self.total_lines_drawn > 0 {
            print!("\x1b[{}A", self.total_lines_drawn);
            print!("\x1b[J");
        }

        for line in &self.header_lines {
            println!("{}", line);
        }

        println!("{}", "-".repeat(60));

        for (ts, msg) in &self.logs {
            let colored_msg = colorize_message(msg);
            println!("[{:<10}] {}", time_ago(*ts), colored_msg);
        }

        if self.rsync_window_active {
            println!("{}", "-".repeat(60));
            for i in 0..self.rsync_window_lines {
                if let Some(line) = self.rsync_lines.get(i) {
                    println!("{}", line.cyan());
                } else {
                    println!();
                }
            }
        }

        self.total_lines_drawn = self.header_lines.len()
            + 1
            + self.logs.len()
            + if self.rsync_window_active {
                1 + self.rsync_window_lines
            } else {
                0
            };
    }

    fn clear_and_finish(&mut self, sync_count: usize) {
        if self.total_lines_drawn > 0 {
            print!("\x1b[{}A", self.total_lines_drawn);
            print!("\x1b[J");
        }
        println!("\n{}", "=".repeat(60));
        println!("Stopped husync");
        println!("Total syncs: {}", sync_count);
        println!("{}\n", "=".repeat(60));
    }
}

#[derive(Debug, Clone)]
struct FileChange {
    watched_path: String,
    rel_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WatchMode {
    Recursive,
    FilesOnly,
    SingleFile,
}

fn encode_watch_spec(path: &Path, mode: WatchMode) -> String {
    match mode {
        WatchMode::Recursive => path.to_string_lossy().to_string(),
        WatchMode::FilesOnly => format!("files_only:{}", path.to_string_lossy()),
        WatchMode::SingleFile => format!("file:{}", path.to_string_lossy()),
    }
}

fn decode_watch_spec(spec: &str) -> (PathBuf, WatchMode) {
    if let Some(rest) = spec.strip_prefix("files_only:") {
        (PathBuf::from(rest), WatchMode::FilesOnly)
    } else if let Some(rest) = spec.strip_prefix("file:") {
        (PathBuf::from(rest), WatchMode::SingleFile)
    } else {
        (PathBuf::from(spec), WatchMode::Recursive)
    }
}

struct DirectorySync {
    config: SyncConfig,
    display: ScrollingDisplay,
    watched_paths: Vec<PathBuf>,      // recursive
    files_only_paths: Vec<PathBuf>,   // non-recursive file-only sync
    single_file_paths: Vec<PathBuf>,  // file-only sync targets
    root_dir: PathBuf,
    sync_count: usize,
    has_valid_watch: bool,
}

impl DirectorySync {
    fn new(config: SyncConfig) -> Result<Self, String> {
        let root_dir = std::env::current_dir().map_err(|e| format!("failed to read cwd: {}", e))?;
        Ok(Self {
            config,
            display: ScrollingDisplay::new(10),
            watched_paths: Vec::new(),
            files_only_paths: Vec::new(),
            single_file_paths: Vec::new(),
            root_dir,
            sync_count: 0,
            has_valid_watch: false,
        })
    }

    fn log(&mut self, msg: impl Into<String>) {
        self.display.add_log(msg.into());
    }

    fn begin_rsync_output(&mut self) {
        self.display.begin_rsync_output();
    }

    fn push_rsync_output(&mut self, line: String) {
        self.display.push_rsync_output(line);
    }

    fn end_rsync_output(&mut self) {
        self.display.end_rsync_output();
    }

    fn add_watch(&mut self, path: &str, mode: WatchMode) -> bool {
        let abs = match Path::new(path).canonicalize() {
            Ok(p) => p,
            Err(_) => {
                self.log(format!("ERROR path not found: {}", path));
                return false;
            }
        };

        match mode {
            WatchMode::FilesOnly => {
                if !abs.is_dir() {
                    self.log(format!("ERROR not a directory: {}", abs.display()));
                    return false;
                }
                if self.files_only_paths.contains(&abs) {
                    return true;
                }
                self.files_only_paths.push(abs.clone());
                self.has_valid_watch = true;
                true
            }
            WatchMode::Recursive => {
                if !abs.is_dir() {
                    self.log(format!("ERROR not a directory: {}", abs.display()));
                    return false;
                }
                if abs == self.root_dir {
                    return false;
                }
                if self.watched_paths.contains(&abs) {
                    return true;
                }
                self.watched_paths.push(abs.clone());
                self.has_valid_watch = true;
                true
            }
            WatchMode::SingleFile => {
                if !abs.is_file() {
                    self.log(format!("ERROR not a file: {}", abs.display()));
                    return false;
                }
                if self.single_file_paths.contains(&abs) {
                    return true;
                }
                self.single_file_paths.push(abs);
                self.has_valid_watch = true;
                true
            }
        }
    }

    fn remote_target_for(&self, rel: &str) -> String {
        if rel.is_empty() {
            format!(
                "{}@{}:{}/",
                self.config.remote_user, self.config.remote_host, self.config.remote_base
            )
        } else {
            format!(
                "{}@{}:{}/{}/",
                self.config.remote_user, self.config.remote_host, self.config.remote_base, rel
            )
        }
    }

    fn run_rsync(&mut self, local: &str, remote: &str, root_only: bool) -> Result<(i32, f64, String), String> {
        let mut args: Vec<String> = vec!["-avzP".to_string()];

        for pattern in &self.config.exclude_patterns {
            args.push("--exclude".to_string());
            args.push(pattern.clone());
        }
        if root_only {
            args.push("--exclude".to_string());
            args.push("*/".to_string());
        }

        args.push("-e".to_string());
        args.push(format!("ssh -i {} -o BatchMode=yes", self.config.ssh_key));
        args.push(local.to_string());
        args.push(remote.to_string());

        if self.config.verbose {
            self.log(format!("CMD rsync {}", args.join(" ")));
        }

        let start = Instant::now();

        let mut child = Command::new("rsync")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to start rsync: {}", e))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "failed to capture rsync stdout".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "failed to capture rsync stderr".to_string())?;

        let (progress_tx, progress_rx) = mpsc::channel::<String>();
        let progress_tx_out = progress_tx.clone();
        let stderr_capture = Arc::new(Mutex::new(String::new()));
        let stderr_capture_for_thread = Arc::clone(&stderr_capture);
        let stdout_handle = std::thread::spawn(move || {
            pump_rsync_stream(stdout, progress_tx_out, None);
        });
        let stderr_handle = std::thread::spawn(move || {
            pump_rsync_stream(stderr, progress_tx, Some(stderr_capture_for_thread));
        });

        let timeout = Duration::from_secs(self.config.timeout_max_seconds);
        let mut last_notice = Instant::now();
        self.begin_rsync_output();
        let status = loop {
            while let Ok(progress) = progress_rx.try_recv() {
                self.push_rsync_output(format!("RSYNC {}", progress));
            }

            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        self.end_rsync_output();
                        let _ = stdout_handle.join();
                        let _ = stderr_handle.join();
                        let stderr_output = stderr_capture
                            .lock()
                            .map(|s| s.clone())
                            .unwrap_or_default();
                        let err_preview = stderr_output.trim().to_string();
                        return Err(format!(
                            "sync timeout after {}s{}",
                            self.config.timeout_max_seconds,
                            if err_preview.is_empty() {
                                "".to_string()
                            } else {
                                format!("; stderr: {}", err_preview.chars().take(200).collect::<String>())
                            }
                        ));
                    }
                    if last_notice.elapsed() >= Duration::from_secs(15) {
                        self.log(format!("Sync still running ({:.0}s)...", start.elapsed().as_secs_f64()));
                        last_notice = Instant::now();
                    }
                    // Keep rsync output window responsive while still avoiding busy-wait.
                    sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(format!("failed waiting rsync: {}", e)),
            }
        };

        let elapsed = start.elapsed().as_secs_f64();
        let code = status.code().unwrap_or(-1);
        self.end_rsync_output();
        let _ = stdout_handle.join();
        let _ = stderr_handle.join();
        let msg = stderr_capture
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();

        Ok((code, elapsed, msg))
    }

    fn run_rsync_single_file(&mut self, local_file: &str, remote_file: &str) -> Result<(i32, f64, String), String> {
        let args: Vec<String> = vec![
            "-avzP".to_string(),
            "-e".to_string(),
            format!("ssh -i {} -o BatchMode=yes", self.config.ssh_key),
            local_file.to_string(),
            remote_file.to_string(),
        ];

        let start = Instant::now();

        let mut child = Command::new("rsync")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to start rsync: {}", e))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "failed to capture rsync stdout".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "failed to capture rsync stderr".to_string())?;

        let (progress_tx, progress_rx) = mpsc::channel::<String>();
        let progress_tx_out = progress_tx.clone();
        let stderr_capture = Arc::new(Mutex::new(String::new()));
        let stderr_capture_for_thread = Arc::clone(&stderr_capture);
        let stdout_handle = std::thread::spawn(move || {
            pump_rsync_stream(stdout, progress_tx_out, None);
        });
        let stderr_handle = std::thread::spawn(move || {
            pump_rsync_stream(stderr, progress_tx, Some(stderr_capture_for_thread));
        });

        let timeout = Duration::from_secs(self.config.timeout_max_seconds);
        let mut last_notice = Instant::now();
        self.begin_rsync_output();
        let status = loop {
            while let Ok(progress) = progress_rx.try_recv() {
                self.push_rsync_output(format!("RSYNC {}", progress));
            }

            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        self.end_rsync_output();
                        let _ = stdout_handle.join();
                        let _ = stderr_handle.join();
                        let stderr_output = stderr_capture
                            .lock()
                            .map(|s| s.clone())
                            .unwrap_or_default();
                        let err_preview = stderr_output.trim().to_string();
                        return Err(format!(
                            "sync timeout after {}s{}",
                            self.config.timeout_max_seconds,
                            if err_preview.is_empty() {
                                "".to_string()
                            } else {
                                format!("; stderr: {}", err_preview.chars().take(200).collect::<String>())
                            }
                        ));
                    }
                    if last_notice.elapsed() >= Duration::from_secs(15) {
                        self.log(format!("Sync still running ({:.0}s)...", start.elapsed().as_secs_f64()));
                        last_notice = Instant::now();
                    }
                    sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(format!("failed waiting rsync: {}", e)),
            }
        };

        let elapsed = start.elapsed().as_secs_f64();
        let code = status.code().unwrap_or(-1);
        self.end_rsync_output();
        let _ = stdout_handle.join();
        let _ = stderr_handle.join();
        let msg = stderr_capture
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();

        Ok((code, elapsed, msg))
    }

    fn sync_files_only_path(
        &mut self,
        local_path: &Path,
        initial: bool,
        index: Option<usize>,
        total: Option<usize>,
    ) {
        let abs = local_path.to_path_buf();
        let rel_path = abs
            .strip_prefix(&self.root_dir)
            .unwrap_or(&abs)
            .to_string_lossy()
            .to_string();
        let local = format!("{}/", abs.display());
        let remote = self.remote_target_for(&rel_path);
        let display_name = if rel_path.is_empty() {
            "root files".to_string()
        } else {
            format!("{} (files only)", rel_path)
        };
        if initial {
            self.log(format!(
                "Syncing [{}/{}]: {}...",
                index.unwrap_or(0),
                total.unwrap_or(0),
                display_name
            ));
        } else {
            self.log(format!("Syncing {}...", display_name));
        }

        match self.run_rsync(&local, &remote, true) {
            Ok((0, elapsed, _)) | Ok((24, elapsed, _)) => {
                self.sync_count += 1;
                if initial {
                    self.log(format!(
                        "OK synced [{}/{}]: {} ({:.1}s)",
                        index.unwrap_or(0),
                        total.unwrap_or(0),
                        display_name,
                        elapsed
                    ));
                } else {
                    self.log(format!("OK synced {} ({:.1}s)", display_name, elapsed));
                }
            }
            Ok((code, _, msg)) => {
                let preview: String = msg.chars().take(100).collect();
                self.log(format!("ERROR sync failed for {}: {} (code {})", display_name, preview, code));
            }
            Err(e) => {
                self.log(format!("ERROR sync {}: {}", display_name, e));
            }
        }
    }

    fn sync_directory(
        &mut self,
        local_path: &Path,
        changes: Option<&HashSet<String>>,
        initial: bool,
        index: Option<usize>,
        total: Option<usize>,
    ) {
        let abs = local_path.to_path_buf();
        let rel_path = abs
            .strip_prefix(&self.root_dir)
            .unwrap_or(&abs)
            .to_string_lossy()
            .to_string();
        let display_rel = if rel_path.is_empty() {
            ".".to_string()
        } else {
            rel_path.clone()
        };
        let local = format!("{}/", abs.display());
        let remote = self.remote_target_for(&rel_path);
        if initial {
            self.log(format!(
                "Syncing [{}/{}]: {}...",
                index.unwrap_or(0),
                total.unwrap_or(0),
                display_rel
            ));
        } else {
            self.log(format!("Syncing {}...", display_rel));
        }

        match self.run_rsync(&local, &remote, false) {
            Ok((0, elapsed, _)) | Ok((24, elapsed, _)) => {
                self.sync_count += 1;
                if initial {
                    self.log(format!(
                        "OK synced [{}/{}]: {} ({:.1}s)",
                        index.unwrap_or(0),
                        total.unwrap_or(0),
                        display_rel,
                        elapsed
                    ));
                } else {
                    let file_count = changes.map(|c| c.len().to_string()).unwrap_or_else(|| "all".to_string());
                    self.log(format!(
                        "OK synced {} ({} changes, {:.1}s)",
                        display_rel, file_count, elapsed
                    ));
                }
            }
            Ok((code, _, msg)) => {
                let preview: String = msg.chars().take(100).collect();
                self.log(format!("ERROR sync failed for {}: {} (code {})", display_rel, preview, code));
            }
            Err(e) => {
                self.log(format!("ERROR sync error for {}: {}", display_rel, e));
            }
        }
    }

    fn sync_single_file(&mut self, file_path: &Path, initial: bool, index: Option<usize>, total: Option<usize>) {
        let abs = file_path.to_path_buf();
        let rel_path = abs
            .strip_prefix(&self.root_dir)
            .unwrap_or(&abs)
            .to_string_lossy()
            .to_string();
        let local = abs.to_string_lossy().to_string();
        let remote = format!(
            "{}@{}:{}/{}",
            self.config.remote_user, self.config.remote_host, self.config.remote_base, rel_path
        );
        let display_name = format!("{} (file)", rel_path);

        if initial {
            self.log(format!(
                "Syncing [{}/{}]: {}...",
                index.unwrap_or(0),
                total.unwrap_or(0),
                display_name
            ));
        } else {
            self.log(format!("Syncing {}...", display_name));
        }

        match self.run_rsync_single_file(&local, &remote) {
            Ok((0, elapsed, _)) | Ok((24, elapsed, _)) => {
                self.sync_count += 1;
                if initial {
                    self.log(format!(
                        "OK synced [{}/{}]: {} ({:.1}s)",
                        index.unwrap_or(0),
                        total.unwrap_or(0),
                        display_name,
                        elapsed
                    ));
                } else {
                    self.log(format!("OK synced {} ({:.1}s)", display_name, elapsed));
                }
            }
            Ok((code, _, msg)) => {
                let preview: String = msg.chars().take(100).collect();
                self.log(format!("ERROR sync failed for {}: {} (code {})", display_name, preview, code));
            }
            Err(e) => {
                self.log(format!("ERROR sync {}: {}", display_name, e));
            }
        }
    }

    fn header_lines(&self, preparing: bool) -> Vec<String> {
        let total = self.watched_paths.len() + self.files_only_paths.len() + self.single_file_paths.len();
        vec![
            if preparing {
                format!("husync preparing {} targets", total)
            } else {
                format!("husync watching {} targets", total)
            },
            format!(
                "remote: {}@{}:{}",
                self.config.remote_user, self.config.remote_host, self.config.remote_base
            ),
            format!("debounce: {}s | syncs: {}", self.config.debounce_seconds, self.sync_count),
        ]
    }

    fn confirm_initial_sync(&self) -> Result<bool, String> {
        println!("{}", "=".repeat(60));
        println!("Sync plan (local -> remote)");
        println!("{}", "-".repeat(60));

        let mut sorted_files_only = self.files_only_paths.clone();
        sorted_files_only.sort();
        for dir in &sorted_files_only {
            let rel = dir
                .strip_prefix(&self.root_dir)
                .unwrap_or(dir)
                .to_string_lossy()
                .to_string();
            let local = format!("{}/", dir.display());
            let remote = self.remote_target_for(&rel);
            if rel.is_empty() {
                println!("root files only: {} -> {}", local, remote);
            } else {
                println!("files only: {} -> {}", local, remote);
            }
        }

        let mut sorted_dirs = self.watched_paths.clone();
        sorted_dirs.sort();
        for dir in &sorted_dirs {
            let rel = dir
                .strip_prefix(&self.root_dir)
                .unwrap_or(dir)
                .to_string_lossy()
                .to_string();
            let local = format!("{}/", dir.display());
            let remote = self.remote_target_for(&rel);
            println!("recursive dir: {} -> {}", local, remote);
        }

        let mut sorted_files = self.single_file_paths.clone();
        sorted_files.sort();
        for file in &sorted_files {
            let rel = file
                .strip_prefix(&self.root_dir)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string();
            let local = file.to_string_lossy().to_string();
            let remote = format!(
                "{}@{}:{}/{}",
                self.config.remote_user, self.config.remote_host, self.config.remote_base, rel
            );
            println!("single file: {} -> {}", local, remote);
        }

        println!("{}", "-".repeat(60));
        print!("Type 'yes' to continue: ");
        io::stdout()
            .flush()
            .map_err(|e| format!("failed to flush prompt: {}", e))?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("failed to read confirmation: {}", e))?;

        Ok(input.trim() == "yes")
    }

    fn start(&mut self) -> Result<(), String> {
        if !self.has_valid_watch {
            self.log("ERROR no directories to watch");
            return Ok(());
        }

        if !self.confirm_initial_sync()? {
            println!("Aborted: confirmation not received.");
            return Ok(());
        }

        self.display.set_header(self.header_lines(true));
        self.display.redraw();

        let total_items = self.watched_paths.len() + self.files_only_paths.len() + self.single_file_paths.len();
        self.log(format!(
            "Initial sync: {} items",
            total_items,
        ));

        let mut index = 1usize;

        // Sync explicitly selected single files first.
        let mut sorted_files = self.single_file_paths.clone();
        sorted_files.sort();
        for p in &sorted_files {
            self.sync_single_file(p, true, Some(index), Some(total_items));
            index += 1;
        }

        // Then sync "files-only in directory" targets.
        let mut sorted_files_only = self.files_only_paths.clone();
        sorted_files_only.sort();
        for p in &sorted_files_only {
            self.sync_files_only_path(p, true, Some(index), Some(total_items));
            index += 1;
        }

        // Finally sync recursive directories.
        let mut sorted_dirs = self.watched_paths.clone();
        sorted_dirs.sort();
        for p in &sorted_dirs {
            self.sync_directory(p, None, true, Some(index), Some(total_items));
            index += 1;
        }

        let running = Arc::new(AtomicBool::new(true));
        let running_for_signal = Arc::clone(&running);
        ctrlc::set_handler(move || {
            running_for_signal.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("failed to set ctrl-c handler: {}", e))?;

        let (tx, rx) = mpsc::channel::<FileChange>();

        let mut watched_for_cb = self.watched_paths.clone();
        watched_for_cb.extend(self.files_only_paths.clone());
        let root_for_cb = self.root_dir.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    handle_notify_event(event, &root_for_cb, &watched_for_cb, &tx);
                }
            },
            NotifyConfig::default(),
        )
        .map_err(|e| format!("failed to create watcher: {}", e))?;

        for dir in &self.watched_paths {
            watcher
                .watch(dir, RecursiveMode::Recursive)
                .map_err(|e| format!("failed to watch {}: {}", dir.display(), e))?;
        }

        for dir in &self.files_only_paths {
            watcher
                .watch(dir, RecursiveMode::NonRecursive)
                .map_err(|e| format!("failed to watch files-only {}: {}", dir.display(), e))?;
        }
        for file in &self.single_file_paths {
            watcher
                .watch(file, RecursiveMode::NonRecursive)
                .map_err(|e| format!("failed to watch file {}: {}", file.display(), e))?;
        }

        self.log("Starting file monitoring...");
        self.display.set_header(self.header_lines(false));
        self.display.redraw();

        self.event_loop(rx, running);

        self.display.clear_and_finish(self.sync_count);
        Ok(())
    }

    fn event_loop(&mut self, rx: Receiver<FileChange>, running: Arc<AtomicBool>) {
        let debounce = Duration::from_secs_f64(self.config.debounce_seconds);
        let mut pending: HashMap<String, HashSet<String>> = HashMap::new();
        let mut last_change: HashMap<String, Instant> = HashMap::new();
        let mut last_refresh = Instant::now();
        let files_only_keys: HashSet<String> = self
            .files_only_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let single_file_keys: HashSet<String> = self
            .single_file_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        while running.load(Ordering::SeqCst) {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(change) => {
                    pending
                        .entry(change.watched_path.clone())
                        .or_default()
                        .insert(change.rel_path);
                    last_change.insert(change.watched_path, Instant::now());
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }

            let now = Instant::now();
            let ready_keys: Vec<String> = last_change
                .iter()
                .filter(|(_, t)| now.duration_since(**t) >= debounce)
                .map(|(k, _)| k.clone())
                .collect();

            for key in ready_keys {
                let changes = pending.remove(&key).unwrap_or_default();
                last_change.remove(&key);

                if files_only_keys.contains(&key) {
                    self.sync_files_only_path(&PathBuf::from(&key), false, None, None);
                } else if single_file_keys.contains(&key) {
                    self.sync_single_file(&PathBuf::from(&key), false, None, None);
                } else {
                    let p = PathBuf::from(&key);
                    self.sync_directory(&p, Some(&changes), false, None, None);
                }

                self.display.set_header(self.header_lines(false));
                self.display.redraw();
            }

            if last_refresh.elapsed() >= Duration::from_secs(3) {
                self.display.set_header(self.header_lines(false));
                self.display.redraw();
                last_refresh = Instant::now();
            }
        }
    }
}

fn handle_notify_event(event: Event, root: &Path, watched_dirs: &[PathBuf], tx: &Sender<FileChange>) {
    for path in event.paths {
        if should_ignore(&path) {
            continue;
        }

        if let Some(change) = classify_change(&path, root, watched_dirs) {
            let _ = tx.send(change);
        }
    }
}

fn should_ignore(path: &Path) -> bool {
    for comp in path.components() {
        if let Component::Normal(os) = comp {
            let s = os.to_string_lossy();
            if s.starts_with('.') {
                return true;
            }
        }
    }

    let name = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
    name.ends_with(".swp") || name.ends_with(".tmp") || name.ends_with('~')
}

fn classify_change(path: &Path, root: &Path, watched_dirs: &[PathBuf]) -> Option<FileChange> {
    let mut best: Option<&PathBuf> = None;

    for dir in watched_dirs {
        if path.starts_with(dir) {
            match best {
                None => best = Some(dir),
                Some(current) => {
                    if dir.components().count() > current.components().count() {
                        best = Some(dir);
                    }
                }
            }
        }
    }

    if let Some(dir) = best {
        let rel = path.strip_prefix(dir).ok()?.to_string_lossy().to_string();
        return Some(FileChange {
            watched_path: dir.to_string_lossy().to_string(),
            rel_path: rel,
        });
    }

    if path.parent() == Some(root) {
        let rel = path.file_name()?.to_string_lossy().to_string();
        return Some(FileChange {
            watched_path: root.to_string_lossy().to_string(),
            rel_path: rel,
        });
    }

    None
}

#[derive(Parser, Debug)]
#[command(name = "husync")]
#[command(about = "Sync local directories to remote via rsync with file watching")]
struct Args {
    #[arg(num_args = 0.., help = "Local directories to watch and sync")]
    directories: Vec<String>,

    #[arg(long, help = "Remote SSH username")]
    remote_user: Option<String>,

    #[arg(long, help = "Remote host or IP")]
    remote_host: Option<String>,

    #[arg(long, help = "Remote base directory path")]
    remote_base: Option<String>,

    #[arg(long, default_value = "2.0", help = "Debounce seconds before triggering sync")]
    debounce: f64,

    #[arg(long, default_value = "~/.ssh/id_rsa", help = "SSH private key file path")]
    ssh_key: String,

    #[arg(short = 'v', long, help = "Enable verbose rsync logs")]
    verbose: bool,

    #[arg(long, default_value = "300", help = "Maximum rsync timeout in seconds")]
    timeout_max: u64,
}

const PICKER_MAX_CHILD_ENTRIES: usize = 100;

#[derive(Clone, Copy)]
struct PickerPalette {
    text: Color,
    border_primary: Color,
    border_secondary: Color,
    selected: Color,
    partial: Color,
    hint: Color,
}

fn terminal_is_dark_theme() -> bool {
    // COLORFGBG is commonly "fg;bg", where bg 0-6 tends to be dark, 7+ tends to be light.
    if let Ok(v) = std::env::var("COLORFGBG") {
        if let Some(bg) = v.split(';').next_back().and_then(|s| s.parse::<u8>().ok()) {
            return bg <= 6;
        }
    }
    // Default to dark-theme-friendly colors when unknown.
    true
}

fn picker_palette() -> PickerPalette {
    if terminal_is_dark_theme() {
        PickerPalette {
            text: Color::Reset,
            border_primary: Color::Green,
            border_secondary: Color::White,
            selected: Color::Green,
            partial: Color::Yellow,
            hint: Color::Yellow,
        }
    } else {
        PickerPalette {
            text: Color::Reset,
            border_primary: Color::Blue,
            border_secondary: Color::Black,
            selected: Color::Green,
            partial: Color::Rgb(180, 110, 20),
            hint: Color::Rgb(180, 110, 20),
        }
    }
}

#[derive(Clone)]
struct PickerEntry {
    path: PathBuf,
    is_dir: bool,
    collapsed_only: bool,
}

fn count_child_entries_limited(path: &Path, limit: usize) -> Result<usize, String> {
    let mut count = 0usize;
    for entry in fs::read_dir(path).map_err(|e| format!("failed to read {}: {}", path.display(), e))? {
        if entry.is_err() {
            continue;
        }
        count += 1;
        if count > limit {
            break;
        }
    }
    Ok(count)
}

fn list_entries(path: &Path) -> Result<Vec<PickerEntry>, String> {
    let mut items: Vec<PathBuf> = fs::read_dir(path)
        .map_err(|e| format!("failed to read directory {}: {}", path.display(), e))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    items.sort_by(|a, b| {
        let a_is_dir = a.is_dir();
        let b_is_dir = b.is_dir();
        match (a_is_dir, b_is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.cmp(b),
        }
    });

    let mut result = Vec::with_capacity(items.len());
    for p in items {
        let is_dir = p.is_dir();
        let collapsed_only = if is_dir {
            count_child_entries_limited(&p, PICKER_MAX_CHILD_ENTRIES + 1)? > PICKER_MAX_CHILD_ENTRIES
        } else {
            false
        };
        result.push(PickerEntry {
            path: p,
            is_dir,
            collapsed_only,
        });
    }
    Ok(result)
}

fn run_directory_picker(start: PathBuf, preselected: &[String]) -> Result<Vec<String>, String> {
    let mut stdout = io::stdout();
    enable_raw_mode().map_err(|e| format!("failed to enable raw mode: {}", e))?;
    execute!(stdout, EnterAlternateScreen, Hide).map_err(|e| format!("failed to enter screen: {}", e))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| format!("failed to create terminal: {}", e))?;
    terminal.clear().map_err(|e| format!("failed to clear terminal: {}", e))?;

    let mut current = start.canonicalize().map_err(|e| format!("failed to resolve start path: {}", e))?;
    let base_root = current.clone();
    let mut entries = list_entries(&current)?;
    let mut cursor = 0usize;
    let mut selected: HashSet<(PathBuf, WatchMode)> = HashSet::new();
    for spec in preselected {
        let (pb, mode) = decode_watch_spec(spec);
        let resolved = if let Ok(c) = pb.canonicalize() {
            c
        } else if pb.is_absolute() {
            pb
        } else {
            base_root.join(pb)
        };
        selected.insert((resolved, mode));
    }
    let mut hint = String::new();
    let palette = picker_palette();

    let result = (|| -> Result<Vec<String>, String> {
        loop {
            let mut state = ListState::default();
            if !entries.is_empty() {
                state.select(Some(cursor.min(entries.len() - 1)));
            }

            terminal
                .draw(|f| {
                    let size = f.size();
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(3),
                            Constraint::Min(5),
                            Constraint::Length(3),
                        ])
                        .split(size);

                    let header = Paragraph::new(vec![
                        Line::from("SPACE: toggle | ENTER: open | BACKSPACE: up | c: confirm | q: cancel"),
                        Line::from(format!("Current: {}", current.display())),
                    ])
                    .style(Style::default().fg(palette.text))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(palette.border_primary))
                            .title("Directory Picker"),
                    );
                    f.render_widget(header, chunks[0]);

                    let items: Vec<ListItem> = if entries.is_empty() {
                        vec![ListItem::new("(empty directory)")]
                    } else {
                        entries
                            .iter()
                            .map(|entry| {
                                let full_selected = if entry.is_dir {
                                    selected.contains(&(entry.path.clone(), WatchMode::Recursive))
                                } else {
                                    selected.contains(&(entry.path.clone(), WatchMode::SingleFile))
                                };
                                let partial_selected = entry.is_dir
                                    && !full_selected
                                    && selected.iter().any(|(p, _)| p.starts_with(&entry.path));

                                let (icon, icon_style) = if full_selected {
                                    ("✔", Style::default().fg(palette.selected).add_modifier(Modifier::BOLD))
                                } else if partial_selected {
                                    ("●", Style::default().fg(palette.partial))
                                } else {
                                    ("[ ]", Style::default().fg(palette.text))
                                };

                                let name = entry.path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                let mut spans = vec![
                                    Span::styled(format!("{} ", icon), icon_style),
                                    Span::styled(
                                        name,
                                        Style::default().fg(if entry.is_dir { palette.text } else { palette.partial }),
                                    ),
                                ];
                                if entry.is_dir && entry.collapsed_only {
                                    spans.push(Span::styled(
                                        format!(" [large > {}, whole-dir only]", PICKER_MAX_CHILD_ENTRIES),
                                        Style::default().fg(palette.hint),
                                    ));
                                }
                                if !entry.is_dir {
                                    spans.push(Span::styled(" [file]".to_string(), Style::default().fg(palette.hint)));
                                }
                                ListItem::new(Line::from(spans))
                            })
                            .collect()
                    };

                    let list = List::new(items)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(palette.border_secondary))
                                .title("Directories"),
                        )
                        .highlight_style(
                            Style::default()
                                .fg(palette.text)
                                .add_modifier(Modifier::BOLD),
                        )
                        .highlight_symbol("› ");
                    f.render_stateful_widget(list, chunks[1], &mut state);

                    let footer = Paragraph::new(vec![
                        Line::from(vec![
                            Span::styled("Selected: ", Style::default().fg(palette.selected)),
                            Span::styled(format!("{}", selected.len()), Style::default().fg(palette.selected).add_modifier(Modifier::BOLD)),
                        ]),
                        Line::from(vec![
                            Span::styled("Hint: ", Style::default().fg(palette.hint)),
                            Span::styled(
                                if hint.is_empty() { "none".to_string() } else { hint.clone() },
                                Style::default().fg(palette.text),
                            ),
                        ]),
                    ])
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(palette.border_primary))
                            .title("Status"),
                    );
                    f.render_widget(footer, chunks[2]);
                })
                .map_err(|e| format!("render error: {}", e))?;

            if !event::poll(Duration::from_millis(120)).map_err(|e| format!("event poll error: {}", e))? {
                continue;
            }

            let ev = event::read().map_err(|e| format!("event read error: {}", e))?;
            if let CtEvent::Key(key) = ev {
                match key.code {
                    KeyCode::Up => {
                        hint.clear();
                        cursor = cursor.saturating_sub(1);
                    }
                    KeyCode::Down => {
                        hint.clear();
                        if cursor + 1 < entries.len() {
                            cursor += 1;
                        }
                    }
                    KeyCode::Char(' ') => {
                        hint.clear();
                        if let Some(dir) = entries.get(cursor) {
                            let mode = if dir.is_dir {
                                WatchMode::Recursive
                            } else {
                                WatchMode::SingleFile
                            };
                            let key = (dir.path.clone(), mode);
                            if selected.contains(&key) {
                                selected.remove(&key);
                            } else {
                                selected.insert(key);
                            }
                        }
                    }
                    KeyCode::Enter => {
                        hint.clear();
                        if let Some(dir) = entries.get(cursor) {
                            if !dir.is_dir {
                                hint = "This is a file; ENTER only opens folders.".to_string();
                            } else if selected.contains(&(dir.path.clone(), WatchMode::Recursive)) {
                                hint = format!(
                                    "Directory '{}' is selected as a whole; unselect it to enter.",
                                    dir.path.file_name().unwrap_or_default().to_string_lossy()
                                );
                            } else if dir.collapsed_only {
                                hint = format!(
                                    "Directory '{}' is large; only whole-directory sync is allowed.",
                                    dir.path.file_name().unwrap_or_default().to_string_lossy()
                                );
                            } else {
                                current = dir.path.clone();
                                entries = list_entries(&current)?;
                                cursor = 0;
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        hint.clear();
                        if let Some(parent) = current.parent() {
                            current = parent.to_path_buf();
                            entries = list_entries(&current)?;
                            cursor = 0;
                        }
                    }
                    KeyCode::Char('c') => {
                        hint.clear();
                        if selected.is_empty() {
                            hint = "No directory selected yet.".to_string();
                        } else {
                            let mut result: Vec<String> = selected
                                .iter()
                                .map(|(p, mode)| encode_watch_spec(p, *mode))
                                .collect();
                            result.sort();
                            return Ok(result);
                        }
                    }
                    KeyCode::Char('q') => {
                        return Err("directory selection cancelled".to_string());
                    }
                    _ => {}
                }
            }
        }
    })();

    disable_raw_mode().map_err(|e| format!("failed to disable raw mode: {}", e))?;
    execute!(terminal.backend_mut(), Show, LeaveAlternateScreen)
        .map_err(|e| format!("failed to leave screen: {}", e))?;
    terminal.show_cursor().map_err(|e| format!("failed to show cursor: {}", e))?;

    result
}

fn main() {
    colored::control::set_override(true);

    let args = Args::parse();

    let project_root = SavedConfig::current_project_root().unwrap_or_default();
    let history = SavedConfig::load_all().unwrap_or_default();
    let last_for_project = history
        .iter()
        .rev()
        .find(|c| c.project_root == project_root)
        .cloned();

    let remote_user = if let Some(v) = args.remote_user.clone() {
        v
    } else if let Some(cfg) = &last_for_project {
        cfg.remote_user.clone()
    } else {
        eprintln!("Error: --remote-user is required (or available in this project's history)");
        std::process::exit(1);
    };

    let remote_host = if let Some(v) = args.remote_host.clone() {
        v
    } else if let Some(cfg) = &last_for_project {
        cfg.remote_host.clone()
    } else {
        eprintln!("Error: --remote-host is required (or available in this project's history)");
        std::process::exit(1);
    };

    let remote_base = if let Some(v) = args.remote_base.clone() {
        v
    } else if let Some(cfg) = &last_for_project {
        cfg.remote_base.clone()
    } else {
        eprintln!("Error: --remote-base is required (or available in this project's history)");
        std::process::exit(1);
    };

    let preselected_dirs = if !args.directories.is_empty() {
        args.directories.clone()
    } else if let Some(cfg) = &last_for_project {
        cfg.directories.clone()
    } else {
        Vec::new()
    };

    let directories = match run_directory_picker(
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        &preselected_dirs,
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let ssh_key = args.ssh_key;
    let debounce = args.debounce;
    let verbose = args.verbose;
    let timeout_max = args.timeout_max;

    // Save this configuration
    let saved_config = SavedConfig {
        project_root,
        directories: directories.clone(),
        remote_user: remote_user.clone(),
        remote_host: remote_host.clone(),
        remote_base: remote_base.clone(),
        debounce,
        ssh_key: ssh_key.clone(),
        verbose,
        timeout_max,
    };
    
    if let Err(e) = saved_config.save() {
        eprintln!("Warning: failed to save config: {}", e);
    }
    
    // Create a temporary Args-like structure for SyncConfig
    let effective_args = Args {
        directories: directories.clone(),
        remote_user: Some(remote_user),
        remote_host: Some(remote_host),
        remote_base: Some(remote_base),
        ssh_key,
        debounce,
        verbose,
        timeout_max,
    };
    
    let config = SyncConfig::new(&effective_args);

    let mut sync = match DirectorySync::new(config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    for d in &directories {
        let (path, mode) = decode_watch_spec(d);
        let path_str = path.to_string_lossy().to_string();
        sync.add_watch(&path_str, mode);
    }

    if let Err(e) = sync.start() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
