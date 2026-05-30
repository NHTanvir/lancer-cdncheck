//! Native GUI for `lancer-cdncheck` (feature `gui`).
//!
//! Lancer-standard three-pane pattern built on egui/eframe 0.28:
//!   * left  `SidePanel`  — target inputs (typed entry + "Add" + drag-drop of files);
//!   * `CentralPanel`     — results table (input / category / provider / confidence);
//!   * right `SidePanel`  — collapsible detail of the selected row (full `Detection`).
//!
//! A top menu bar (File / Tools / Settings / Help) and a bottom status bar wrap
//! the panes. Detection runs on a background tokio runtime; results stream back
//! over a `crossbeam_channel`, drained each frame so the UI thread never blocks.
//!
//! A tiny hand-rolled HTTP/1.1 server (no extra deps) is bound on launch to
//! `127.0.0.1:0`; its port is written to `<tempdir>/lancer-cdncheck.port` so
//! sibling Lancer tools can push targets in and pull state/results out.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::Result;
use crossbeam_channel::{unbounded, Receiver, Sender};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use egui_notify::Toasts;

use lancer_cdncheck::{Client, Detection, VERSION};

/// One completed (or attempted) check, as shown in the results table.
#[derive(Clone)]
struct ResultRow {
    input: String,
    detection: Option<Detection>,
    /// Error text when the check itself failed (DNS error, etc.).
    error: Option<String>,
}

impl ResultRow {
    fn category(&self) -> String {
        match &self.detection {
            Some(d) => d.category.to_string(),
            None if self.error.is_some() => "error".to_string(),
            None => "none".to_string(),
        }
    }

    fn provider(&self) -> String {
        match &self.detection {
            Some(d) => d.provider.clone(),
            None => self.error.clone().unwrap_or_else(|| "-".to_string()),
        }
    }

    fn confidence(&self) -> String {
        match &self.detection {
            Some(d) => format!("{}%", d.confidence),
            None => "-".to_string(),
        }
    }

    /// JSON envelope used both for the detail pane and the HTTP export.
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "input": self.input,
            "detection": self.detection,
            "error": self.error,
        })
    }
}

/// Messages sent from background tasks back to the UI thread.
enum GuiMsg {
    /// A finished result for the given input.
    Result(ResultRow),
}

/// Shared state the embedded HTTP server reads from / writes to.
struct ServerState {
    /// Inputs pushed in via `POST /v1/import`, awaiting the UI to enqueue them.
    inbox: Mutex<Vec<String>>,
    /// Snapshot of finished results, kept in sync by the UI each frame.
    results: Mutex<Vec<serde_json::Value>>,
    /// Outstanding jobs counter (for `GET /v1/state`).
    jobs: AtomicU64,
    /// Total items seen (for `GET /v1/state`).
    items: AtomicU64,
}

impl ServerState {
    fn new() -> Self {
        ServerState {
            inbox: Mutex::new(Vec::new()),
            results: Mutex::new(Vec::new()),
            jobs: AtomicU64::new(0),
            items: AtomicU64::new(0),
        }
    }
}

/// The eframe application.
pub struct LancerApp {
    /// Detection client, shared into spawned tasks.
    client: Arc<Client>,
    /// Background tokio runtime for async checks.
    rt: tokio::runtime::Runtime,
    /// Result channel (background → UI).
    tx: Sender<GuiMsg>,
    rx: Receiver<GuiMsg>,
    /// Shared HTTP-server state.
    server: Arc<ServerState>,

    // ── UI state ──────────────────────────────────────────────────────────
    input_buf: String,
    targets: Vec<String>,
    results: Vec<ResultRow>,
    selected: Option<usize>,
    running: bool,
    pending: usize,
    dark_mode: bool,
    show_about: bool,
    toasts: Toasts,
}

impl LancerApp {
    /// Build the app: detection client, runtime, channels and the embedded
    /// HTTP server. Never panics — falls back to an empty client on failure so
    /// the window always opens.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Honour the system/default visuals; start in dark mode.
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let client = match Client::new() {
            Ok(c) => Arc::new(c),
            Err(e) => {
                // We still want the window to open; fall back to a client built
                // directly from the embedded dataset with a default resolver.
                tracing::error!("failed to build detection client: {e}; using embedded fallback");
                Arc::new(build_fallback_client())
            }
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .unwrap_or_else(|_| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a current-thread runtime can always be built")
            });

        let (tx, rx) = unbounded::<GuiMsg>();
        let server = Arc::new(ServerState::new());

        // Spin up the local HTTP control server.
        spawn_http_server(Arc::clone(&server));

        LancerApp {
            client,
            rt,
            tx,
            rx,
            server,
            input_buf: String::new(),
            targets: Vec::new(),
            results: Vec::new(),
            selected: None,
            running: false,
            pending: 0,
            dark_mode: true,
            show_about: false,
            toasts: Toasts::default(),
        }
    }

    /// Add one or more whitespace/comma/newline-separated targets.
    fn add_targets(&mut self, raw: &str) {
        for line in raw.split(['\n', '\r', ',', ' ', '\t']) {
            let t = line.trim();
            if !t.is_empty() && !self.targets.contains(&t.to_string()) {
                self.targets.push(t.to_string());
            }
        }
    }

    /// Enqueue every current target as a background check.
    fn run_checks(&mut self) {
        if self.targets.is_empty() {
            self.toasts.warning("No targets to check");
            return;
        }
        self.results.clear();
        self.selected = None;
        self.pending = self.targets.len();
        self.running = true;
        self.server
            .jobs
            .store(self.pending as u64, Ordering::SeqCst);

        for target in self.targets.clone() {
            let client = Arc::clone(&self.client);
            let tx = self.tx.clone();
            self.rt.spawn(async move {
                let row = check_one(&client, &target).await;
                let _ = tx.send(GuiMsg::Result(row));
            });
        }
        // Completion is tracked in the UI via the `pending` counter as each
        // `GuiMsg::Result` drains; no explicit terminator task is required.
    }

    /// Pull any results that arrived since the last frame.
    fn drain_results(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                GuiMsg::Result(row) => {
                    self.results.push(row);
                    if self.pending > 0 {
                        self.pending -= 1;
                    }
                    let remaining = self.pending as u64;
                    self.server.jobs.store(remaining, Ordering::SeqCst);
                    self.server
                        .items
                        .store(self.results.len() as u64, Ordering::SeqCst);
                    if self.pending == 0 {
                        self.running = false;
                    }
                }
            }
        }
    }

    /// Pull any inputs pushed in over HTTP and enqueue them.
    fn drain_inbox(&mut self) {
        let pushed: Vec<String> = {
            match self.server.inbox.lock() {
                Ok(mut g) => std::mem::take(&mut *g),
                Err(_) => Vec::new(),
            }
        };
        if !pushed.is_empty() {
            for p in pushed {
                self.add_targets(&p);
            }
        }
    }

    /// Mirror the current results into the shared server state for `/v1/export`.
    fn sync_server_results(&self) {
        if let Ok(mut g) = self.server.results.lock() {
            *g = self.results.iter().map(ResultRow::to_json).collect();
        }
    }

    /// Serialize all results to a pretty JSON string.
    fn results_json(&self) -> String {
        let arr: Vec<serde_json::Value> = self.results.iter().map(ResultRow::to_json).collect();
        serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    /// Export results via a save dialog.
    fn export_results(&mut self) {
        if self.results.is_empty() {
            self.toasts.warning("No results to export");
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("lancer-cdncheck-results.json")
            .add_filter("JSON", &["json"])
            .save_file()
        {
            match std::fs::write(&path, self.results_json()) {
                Ok(()) => {
                    self.toasts.success("Export complete");
                }
                Err(e) => {
                    self.toasts.error(format!("Export failed: {e}"));
                }
            }
        }
    }

    /// Open a target file via a load dialog and ingest its lines.
    fn open_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Text", &["txt", "lst", "csv"])
            .add_filter("All files", &["*"])
            .pick_file()
        {
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    self.add_targets(&contents);
                    self.toasts.success("File loaded");
                }
                Err(e) => {
                    self.toasts.error(format!("Open failed: {e}"));
                }
            }
        }
    }

    /// Ingest any files dropped onto the window this frame.
    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        for file in dropped {
            if let Some(path) = &file.path {
                if let Ok(contents) = std::fs::read_to_string(path) {
                    self.add_targets(&contents);
                    continue;
                }
            }
            if let Some(bytes) = &file.bytes {
                if let Ok(text) = std::str::from_utf8(bytes) {
                    self.add_targets(text);
                }
            }
        }
    }

    fn clear_all(&mut self) {
        self.targets.clear();
        self.results.clear();
        self.selected = None;
        self.pending = 0;
        self.running = false;
        self.server.jobs.store(0, Ordering::SeqCst);
        self.server.items.store(0, Ordering::SeqCst);
    }
}

impl eframe::App for LancerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Pull background results & HTTP-pushed targets; keep server state fresh.
        self.drain_results();
        self.drain_inbox();
        self.handle_dropped_files(ctx);
        self.sync_server_results();

        // While a run is in flight we want steady repaints to flush the channel.
        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        // 2. Top menu bar.
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open file…").clicked() {
                        self.open_file();
                        ui.close_menu();
                    }
                    if ui.button("Export results…").clicked() {
                        self.export_results();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ui.close_menu();
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Run").clicked() {
                        self.run_checks();
                        ui.close_menu();
                    }
                    if ui.button("Clear").clicked() {
                        self.clear_all();
                        ui.close_menu();
                    }
                });
                ui.menu_button("Settings", |ui| {
                    let label = if self.dark_mode {
                        "Switch to light theme"
                    } else {
                        "Switch to dark theme"
                    };
                    if ui.button(label).clicked() {
                        self.dark_mode = !self.dark_mode;
                        if self.dark_mode {
                            ctx.set_visuals(egui::Visuals::dark());
                        } else {
                            ctx.set_visuals(egui::Visuals::light());
                        }
                        ui.close_menu();
                    }
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                        ui.close_menu();
                    }
                });
            });
        });

        // 3. Bottom status bar.
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let status = if self.running { "running" } else { "idle" };
                ui.label(format!("Status: {status}"));
                ui.separator();
                ui.label(format!("targets: {}", self.targets.len()));
                ui.separator();
                ui.label(format!("results: {}", self.results.len()));
                if self.running {
                    ui.separator();
                    ui.label(format!("pending: {}", self.pending));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export").clicked() {
                        self.export_results();
                    }
                    if ui.button("Run").clicked() {
                        self.run_checks();
                    }
                });
            });
        });

        // 4. Left input pane.
        egui::SidePanel::left("targets_panel")
            .default_width(250.0)
            .show(ctx, |ui| {
                ui.heading("Targets");
                ui.separator();
                ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.input_buf)
                            .hint_text("ip or domain")
                            .desired_width(150.0),
                    );
                    let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (ui.button("Add").clicked() || submit) && !self.input_buf.trim().is_empty() {
                        let buf = std::mem::take(&mut self.input_buf);
                        self.add_targets(&buf);
                    }
                });
                ui.label("Drag & drop a target file here.");
                ui.separator();

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let mut remove: Option<usize> = None;
                        for (i, t) in self.targets.iter().enumerate() {
                            ui.horizontal(|ui| {
                                if ui.small_button("x").clicked() {
                                    remove = Some(i);
                                }
                                ui.label(t);
                            });
                        }
                        if let Some(i) = remove {
                            self.targets.remove(i);
                        }
                    });
            });

        // 5. Right detail pane (collapsible).
        egui::SidePanel::right("detail_panel")
            .default_width(320.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading("Detail");
                ui.separator();
                match self.selected.and_then(|i| self.results.get(i)) {
                    Some(row) => {
                        ui.label(format!("Input: {}", row.input));
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if let Some(err) = &row.error {
                                    ui.colored_label(egui::Color32::LIGHT_RED, format!("Error: {err}"));
                                }
                                if let Some(det) = &row.detection {
                                    ui.label(format!("Provider: {}", det.provider));
                                    ui.label(format!("Category: {}", det.category));
                                    ui.label(format!("Confidence: {}%", det.confidence));
                                    if !det.protection_stack.is_empty() {
                                        ui.label(format!(
                                            "Protection stack: {}",
                                            det.protection_stack.join(" + ")
                                        ));
                                    }
                                    ui.separator();
                                    ui.label("Signals:");
                                    for s in &det.signals {
                                        ui.label(format!(
                                            "  • {} / {} via {} ({}%)",
                                            s.provider,
                                            s.category,
                                            s.signal_type,
                                            s.confidence
                                        ));
                                    }
                                    ui.separator();
                                    ui.label("JSON:");
                                    let json = serde_json::to_string_pretty(det)
                                        .unwrap_or_else(|_| "{}".to_string());
                                    ui.code(json);
                                } else if row.error.is_none() {
                                    ui.label("No CDN/WAF/Cloud detected.");
                                }
                            });
                    }
                    None => {
                        ui.label("Select a result row to inspect it.");
                    }
                }
            });

        // 6. Central results table.
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Results");
            ui.separator();
            let row_height = 22.0;
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(140.0).clip(true))
                .column(Column::auto().at_least(90.0))
                .column(Column::auto().at_least(120.0).clip(true))
                .column(Column::remainder())
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("Input");
                    });
                    header.col(|ui| {
                        ui.strong("Category");
                    });
                    header.col(|ui| {
                        ui.strong("Provider");
                    });
                    header.col(|ui| {
                        ui.strong("Confidence");
                    });
                })
                .body(|mut body| {
                    let rows: Vec<(String, String, String, String)> = self
                        .results
                        .iter()
                        .map(|r| (r.input.clone(), r.category(), r.provider(), r.confidence()))
                        .collect();
                    for (idx, (input, category, provider, confidence)) in
                        rows.into_iter().enumerate()
                    {
                        let selected = self.selected == Some(idx);
                        body.row(row_height, |mut row| {
                            row.set_selected(selected);
                            row.col(|ui| {
                                if ui.selectable_label(selected, input).clicked() {
                                    self.selected = Some(idx);
                                }
                            });
                            row.col(|ui| {
                                ui.label(category);
                            });
                            row.col(|ui| {
                                ui.label(provider);
                            });
                            row.col(|ui| {
                                ui.label(confidence);
                            });
                        });
                    }
                });
        });

        // 7. About window.
        if self.show_about {
            let mut open = true;
            egui::Window::new("About lancer-cdncheck")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("lancer-cdncheck");
                    ui.label(format!("Version {VERSION}"));
                    ui.label("Rust clone of ProjectDiscovery cdncheck.");
                    ui.label("CDN / WAF / Cloud / bot-protection detection.");
                    if let Ok(port) = read_port_file() {
                        ui.separator();
                        ui.label(format!("Control API: http://127.0.0.1:{port}"));
                    }
                });
            self.show_about = open;
        }

        // 8. Render queued toasts.
        self.toasts.show(ctx);
    }
}

/// Run a single check: IP literal → synchronous trie lookup; otherwise treat the
/// input as a domain and resolve with fallback.
async fn check_one(client: &Client, input: &str) -> ResultRow {
    let trimmed = input.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return ResultRow {
            input: trimmed.to_string(),
            detection: client.check(ip),
            error: None,
        };
    }
    match client.check_domain_with_fallback(trimmed).await {
        Ok(detection) => ResultRow {
            input: trimmed.to_string(),
            detection,
            error: None,
        },
        Err(e) => ResultRow {
            input: trimmed.to_string(),
            detection: None,
            error: Some(e.to_string()),
        },
    }
}

/// Last-resort client built directly from the embedded dataset.
fn build_fallback_client() -> Client {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    Client::from_source_data(
        lancer_cdncheck::data::SourceData::embedded(),
        ResolverConfig::default(),
        ResolverOpts::default(),
        false,
    )
    .expect("embedded dataset always yields a client")
}

// ── embedded HTTP control server ──────────────────────────────────────────────

/// The path of the port file shared with sibling tools.
fn port_file_path() -> std::path::PathBuf {
    std::env::temp_dir().join("lancer-cdncheck.port")
}

/// Read the port previously advertised in the port file.
fn read_port_file() -> std::io::Result<u16> {
    let s = std::fs::read_to_string(port_file_path())?;
    s.trim()
        .parse::<u16>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Bind `127.0.0.1:0`, advertise the port, and spawn the accept loop.
fn spawn_http_server(state: Arc<ServerState>) {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("could not bind control server: {e}");
            return;
        }
    };
    if let Ok(addr) = listener.local_addr() {
        if let Err(e) = std::fs::write(port_file_path(), addr.port().to_string()) {
            tracing::warn!("could not write port file: {e}");
        }
        tracing::info!("control server listening on {addr}");
    }

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let st = Arc::clone(&state);
                    // Each connection is tiny; handle on a short-lived thread so a
                    // slow client never stalls the accept loop.
                    thread::spawn(move || {
                        let _ = handle_connection(s, &st);
                    });
                }
                Err(_) => continue,
            }
        }
    });
}

/// Handle one HTTP/1.1 request. Best-effort and intentionally forgiving of
/// malformed input.
fn handle_connection(stream: TcpStream, state: &ServerState) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    // Request line, e.g. "GET /v1/state HTTP/1.1".
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("/").to_string();

    // Headers — we only care about Content-Length for the body.
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }

    // Split path / query.
    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_target.clone(), String::new()),
    };

    let mut stream = stream;
    match (method.as_str(), path.as_str()) {
        ("GET", "/v1/state") => {
            let body = serde_json::json!({
                "jobs": state.jobs.load(Ordering::SeqCst),
                "items": state.items.load(Ordering::SeqCst),
            })
            .to_string();
            write_response(&mut stream, 200, "OK", "application/json", &body)
        }
        ("POST", "/v1/import") => {
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body)?;
            }
            let text = String::from_utf8_lossy(&body);
            let mut count = 0usize;
            if let Ok(mut inbox) = state.inbox.lock() {
                for line in text.split(['\n', '\r', ',', ' ', '\t']) {
                    let t = line.trim();
                    if !t.is_empty() {
                        inbox.push(t.to_string());
                        count += 1;
                    }
                }
            }
            let resp = serde_json::json!({ "imported": count }).to_string();
            write_response(&mut stream, 200, "OK", "application/json", &resp)
        }
        ("GET", "/v1/export") => {
            let wants_json = query.is_empty()
                || query
                    .split('&')
                    .any(|kv| kv == "format=json" || kv == "format=JSON");
            if !wants_json {
                return write_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "text/plain",
                    "only format=json is supported",
                );
            }
            let body = match state.results.lock() {
                Ok(g) => serde_json::to_string_pretty(&*g).unwrap_or_else(|_| "[]".to_string()),
                Err(_) => "[]".to_string(),
            };
            write_response(&mut stream, 200, "OK", "application/json", &body)
        }
        _ => write_response(
            &mut stream,
            404,
            "Not Found",
            "text/plain",
            "not found",
        ),
    }
}

/// Write a minimal HTTP/1.1 response and close the connection.
fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// Launch the native window. Blocks until the user closes it.
pub fn run() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([720.0, 480.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "lancer-cdncheck",
        options,
        Box::new(|cc| Ok(Box::new(LancerApp::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_row_formats_none() {
        let row = ResultRow {
            input: "1.2.3.4".to_string(),
            detection: None,
            error: None,
        };
        assert_eq!(row.category(), "none");
        assert_eq!(row.provider(), "-");
        assert_eq!(row.confidence(), "-");
    }

    #[test]
    fn result_row_formats_error() {
        let row = ResultRow {
            input: "bad".to_string(),
            detection: None,
            error: Some("dns failure".to_string()),
        };
        assert_eq!(row.category(), "error");
        assert_eq!(row.provider(), "dns failure");
    }

    #[test]
    fn result_row_formats_detection() {
        use lancer_cdncheck::{DetectionCategory, SignalType};
        let det = Detection::single("cloudflare", DetectionCategory::Cdn, SignalType::Cidr);
        let row = ResultRow {
            input: "1.1.1.1".to_string(),
            detection: Some(det),
            error: None,
        };
        assert_eq!(row.category(), "cdn");
        assert_eq!(row.provider(), "cloudflare");
        assert_eq!(row.confidence(), "80%");
        // JSON envelope must include the input.
        let v = row.to_json();
        assert_eq!(v["input"], "1.1.1.1");
    }

    #[test]
    fn server_state_roundtrips_inbox() {
        let state = ServerState::new();
        {
            let mut g = state.inbox.lock().unwrap();
            g.push("example.com".to_string());
        }
        let taken: Vec<String> = std::mem::take(&mut *state.inbox.lock().unwrap());
        assert_eq!(taken, vec!["example.com".to_string()]);
    }
}
