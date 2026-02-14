use clap::Parser;
use colored::*;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedConfig {
    directories: Vec<String>,
    remote_user: String,
    remote_host: String,
    remote_base: String,
    debounce: f64,
    ssh_key: String,
    verbose: bool,
}

impl SavedConfig {
    fn config_file_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".husync")
    }

    fn load_all() -> Result<Vec<Self>, String> {
        let path = Self::config_file_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read config: {}", e))?;
        let configs: Vec<Self> = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse config: {}", e))?;
        Ok(configs)
    }

    fn save(&self) -> Result<(), String> {
        let mut configs = Self::load_all().unwrap_or_default();
        
        // Check if this config already exists
        if !configs.iter().any(|c| {
            c.directories == self.directories
                && c.remote_user == self.remote_user
                && c.remote_host == self.remote_host
                && c.remote_base == self.remote_base
        }) {
            configs.push(self.clone());
        }
        
        let path = Self::config_file_path();
        let content = serde_json::to_string_pretty(&configs)
            .map_err(|e| format!("failed to serialize config: {}", e))?;
        fs::write(&path, content)
            .map_err(|e| format!("failed to write config: {}", e))?;
        Ok(())
    }

    fn display(&self, index: usize) -> String {
        format!(
            "[{}] {} -> {}@{}:{} (dirs: {})",
            index,
            self.directories.join(", "),
            self.remote_user,
            self.remote_host,
            self.remote_base,
            self.directories.len()
        )
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
    } else if msg.starts_with("OK") || msg.starts_with("WATCH") || msg.starts_with("Starting") || msg.starts_with("Initial") || msg.starts_with("Syncing") {
        msg.green()
    } else {
        msg.normal()
    }
}

struct ScrollingDisplay {
    max_log_lines: usize,
    logs: VecDeque<(SystemTime, String)>,
    header_lines: Vec<String>,
    total_lines_drawn: usize,
}

impl ScrollingDisplay {
    fn new(max_log_lines: usize) -> Self {
        Self {
            max_log_lines,
            logs: VecDeque::new(),
            header_lines: Vec::new(),
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

        self.total_lines_drawn = self.header_lines.len() + 1 + self.logs.len();
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

struct DirectorySync {
    config: SyncConfig,
    display: ScrollingDisplay,
    watched_paths: Vec<PathBuf>,
    root_dir: PathBuf,
    sync_count: usize,
    root_selected: bool,
    has_valid_watch: bool,
}

impl DirectorySync {
    fn new(config: SyncConfig) -> Result<Self, String> {
        let root_dir = std::env::current_dir().map_err(|e| format!("failed to read cwd: {}", e))?;
        Ok(Self {
            config,
            display: ScrollingDisplay::new(10),
            watched_paths: Vec::new(),
            root_dir,
            sync_count: 0,
            root_selected: false,
            has_valid_watch: false,
        })
    }

    fn log(&mut self, msg: impl Into<String>) {
        self.display.add_log(msg.into());
    }

    fn add_watch(&mut self, path: &str) -> bool {
        let abs = match Path::new(path).canonicalize() {
            Ok(p) => p,
            Err(_) => {
                self.log(format!("ERROR not a directory: {}", path));
                return false;
            }
        };

        if !abs.is_dir() {
            self.log(format!("ERROR not a directory: {}", abs.display()));
            return false;
        }

        // Root path is synced in file-only mode; do not add it as recursive watch.
        if abs == self.root_dir {
            if self.root_selected {
                self.log(format!("WARN already watching root files: {}", abs.display()));
                return true;
            }
            self.root_selected = true;
            self.has_valid_watch = true;
            self.log(format!("WATCH root files {}", abs.display()));
            return true;
        }

        if self.watched_paths.contains(&abs) {
            self.log(format!("WARN already watching: {}", abs.display()));
            return true;
        }

        self.watched_paths.push(abs.clone());
        self.has_valid_watch = true;
        self.log(format!("WATCH {}", abs.display()));
        true
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
        let mut args: Vec<String> = vec!["-azuv".to_string(), "--progress".to_string()];

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

        let stdout_cfg = if self.config.verbose {
            Stdio::inherit()
        } else {
            Stdio::null()
        };
        let stderr_cfg = if self.config.verbose {
            Stdio::inherit()
        } else {
            Stdio::null()
        };

        let mut child = Command::new("rsync")
            .args(&args)
            .stdout(stdout_cfg)
            .stderr(stderr_cfg)
            .spawn()
            .map_err(|e| format!("failed to start rsync: {}", e))?;

        let timeout = Duration::from_secs(300);
        let mut last_notice = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err("sync timeout".to_string());
                    }
                    if last_notice.elapsed() >= Duration::from_secs(15) {
                        self.log(format!("Sync still running ({:.0}s)...", start.elapsed().as_secs_f64()));
                        last_notice = Instant::now();
                    }
                    sleep(Duration::from_millis(300));
                }
                Err(e) => return Err(format!("failed waiting rsync: {}", e)),
            }
        };

        let elapsed = start.elapsed().as_secs_f64();
        let code = status.code().unwrap_or(-1);
        let msg = String::new();

        Ok((code, elapsed, msg))
    }

    fn sync_root_files(&mut self, initial: bool, index: Option<usize>, total: Option<usize>) {
        let local = format!("{}/", self.root_dir.display());
        let remote = self.remote_target_for("");
        if initial {
            self.log(format!(
                "Syncing [{}/{}]: root files...",
                index.unwrap_or(0),
                total.unwrap_or(0)
            ));
        } else {
            self.log("Syncing root files...".to_string());
        }

        match self.run_rsync(&local, &remote, true) {
            Ok((0, elapsed, _)) | Ok((24, elapsed, _)) => {
                self.sync_count += 1;
                if initial {
                    self.log(format!(
                        "OK synced [{}/{}]: root files ({:.1}s)",
                        index.unwrap_or(0),
                        total.unwrap_or(0),
                        elapsed
                    ));
                } else {
                    self.log(format!("OK synced root files ({:.1}s)", elapsed));
                }
            }
            Ok((code, _, msg)) => {
                let preview: String = msg.chars().take(100).collect();
                self.log(format!("ERROR sync failed for root files: {} (code {})", preview, code));
            }
            Err(e) => {
                self.log(format!("ERROR sync root files: {}", e));
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

    fn header_lines(&self, preparing: bool) -> Vec<String> {
        vec![
            if preparing {
                format!("husync preparing {} directories", self.watched_paths.len())
            } else {
                format!("husync watching {} directories", self.watched_paths.len())
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

        let root_local = format!("{}/", self.root_dir.display());
        let root_remote = self.remote_target_for("");
        println!(
            "root files only: {} -> {}",
            root_local, root_remote
        );

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

        let total_items = self.watched_paths.len() + 1;
        self.log(format!(
            "Initial sync: {} items (root files + {} dirs)",
            total_items,
            self.watched_paths.len()
        ));

        self.sync_root_files(true, Some(1), Some(total_items));

        let mut sorted_dirs = self.watched_paths.clone();
        sorted_dirs.sort();
        for (idx, p) in sorted_dirs.iter().enumerate() {
            self.sync_directory(p, None, true, Some(idx + 2), Some(total_items));
        }

        let running = Arc::new(AtomicBool::new(true));
        let running_for_signal = Arc::clone(&running);
        ctrlc::set_handler(move || {
            running_for_signal.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("failed to set ctrl-c handler: {}", e))?;

        let (tx, rx) = mpsc::channel::<FileChange>();

        let watched_for_cb = self.watched_paths.clone();
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

        watcher
            .watch(&self.root_dir, RecursiveMode::NonRecursive)
            .map_err(|e| format!("failed to watch root {}: {}", self.root_dir.display(), e))?;

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

                if key == self.root_dir.to_string_lossy() {
                    self.sync_root_files(false, None, None);
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

    #[arg(long, help = "Resume from saved configuration")]
    resume: bool,
}

fn select_saved_config() -> Result<SavedConfig, String> {
    let configs = SavedConfig::load_all()?;
    
    if configs.is_empty() {
        return Err("No saved configurations found".to_string());
    }
    
    println!("{}", "=".repeat(60));
    println!("Saved configurations:");
    println!("{}", "-".repeat(60));
    
    for (i, config) in configs.iter().enumerate() {
        println!("{}", config.display(i + 1));
    }
    
    println!("{}", "-".repeat(60));
    print!("Select configuration (1-{}): ", configs.len());
    io::stdout().flush().map_err(|e| format!("failed to flush: {}", e))?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| format!("failed to read input: {}", e))?;
    
    let index: usize = input.trim().parse()
        .map_err(|_| "Invalid selection".to_string())?;
    
    if index < 1 || index > configs.len() {
        return Err("Selection out of range".to_string());
    }
    
    Ok(configs[index - 1].clone())
}

fn main() {
    colored::control::set_override(true);
    
    let args = Args::parse();
    
    let (directories, remote_user, remote_host, remote_base, ssh_key, debounce, verbose) = if args.resume {
        match select_saved_config() {
            Ok(config) => (
                config.directories,
                config.remote_user,
                config.remote_host,
                config.remote_base,
                config.ssh_key,
                config.debounce,
                config.verbose,
            ),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        if args.directories.is_empty() {
            eprintln!("Error: directories are required");
            std::process::exit(1);
        }
        if args.remote_user.is_none() || args.remote_host.is_none() || args.remote_base.is_none() {
            eprintln!("Error: --remote-user, --remote-host, and --remote-base are required");
            std::process::exit(1);
        }
        (
            args.directories,
            args.remote_user.unwrap(),
            args.remote_host.unwrap(),
            args.remote_base.unwrap(),
            args.ssh_key,
            args.debounce,
            args.verbose,
        )
    };
    
    // Save this configuration
    let saved_config = SavedConfig {
        directories: directories.clone(),
        remote_user: remote_user.clone(),
        remote_host: remote_host.clone(),
        remote_base: remote_base.clone(),
        debounce,
        ssh_key: ssh_key.clone(),
        verbose,
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
        resume: false,
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
        sync.add_watch(d);
    }

    if let Err(e) = sync.start() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
