//! Shared native presentation controller. Discovery never changes the chosen recipient.
use crate::{
    clipboard::ClipboardManager,
    platform,
    protocol::{
        clean_text, get_or_create_device_id, DeviceType, DiscoveryManager, HistoryEntry,
        HistoryKind, HistoryManager, Peer, TransferEvent, TransferManager, TrustManager,
    },
    settings::{tr, Settings},
    AppState, AppWindow, FilePickerItem, HistoryItem, PeerItem, TransferItem,
};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::{
    collections::HashSet,
    path::PathBuf,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::mpsc;

#[derive(Clone)]
enum Payload {
    Text { content: String, draft: String },
    File(PathBuf),
}
struct Job {
    id: String,
    peer_id: String,
    peer_name: String,
    title: String,
    detail: String,
    status: String,
    direction: String,
    progress: f32,
    cancel: Arc<AtomicBool>,
    payload: Option<Payload>,
}
enum Command {
    Select(String),
    PickFiles,
    #[cfg(not(target_os = "android"))]
    Files(Vec<PathBuf>),
    FilesFor(String, Vec<PathBuf>),
    Text(String),
    Paste,
    PastePairing,
    CloseBrowser,
    OpenBrowserFile(PathBuf),
    Copy,
    CopyPairing,
    Cancel(String),
    Retry(String),
    HistoryAction(String),
    ClearHistory,
    SaveSettings(Settings),
    Pair(String),
    Forget(String),
    OpenDownloads,
    OpenUpdate,
    Dismiss,
    Refresh,
    Browse(PathBuf),
    Up,
    ToggleFile(PathBuf),
    SendSelected,
    StorageAccess,
    Progress(String, u64, u64, f64, u64),
    Finished(String, Result<(), String>),
    Notice(String, bool),
    Verified(String, u64, Result<(), String>),
    Begin(String),
    ClearFeedback,
}
struct Engine {
    ui: slint::Weak<AppWindow>,
    tx: mpsc::UnboundedSender<Command>,
    discovery: Arc<DiscoveryManager>,
    trust: Arc<TrustManager>,
    transfer: Arc<TransferManager>,
    history: HistoryManager,
    settings: Settings,
    data_dir: PathBuf,
    downloads: PathBuf,
    peers: Vec<Peer>,
    jobs: Vec<Job>,
    received: String,
    notice: String,
    notice_error: bool,
    browser_path: PathBuf,
    browser_files: Vec<platform::FileEntry>,
    selected_files: HashSet<PathBuf>,
    browser_read_only: bool,
    verified_peer: Option<String>,
    probing: bool,
    probe_error: Option<String>,
    probe_epoch: u64,
    last_probe: Option<std::time::Instant>,
    manual_peer: Option<Peer>,
    slots: Arc<tokio::sync::Semaphore>,
}

pub fn run(mobile: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Loopback-only instances support UI/integration verification without LAN discovery.
    let local_only = std::env::args().any(|a| a == "--local-only");
    let data_dir = match argument("--data-dir") {
        Some(path) => PathBuf::from(path),
        None => platform::app_data_dir().map_err(std::io::Error::other)?,
    };
    let downloads = match argument("--downloads-dir") {
        Some(path) => PathBuf::from(path),
        None => platform::downloads_dir().map_err(std::io::Error::other)?,
    };
    let (data_dir, downloads) = if cfg!(not(target_os = "android")) && mobile {
        (data_dir.join("mobile-preview"), downloads.join("Mobile"))
    } else {
        (data_dir, downloads)
    };
    std::fs::create_dir_all(&data_dir)?;
    std::fs::create_dir_all(&downloads)?;
    // Preserve the old activity log, but never migrate the former ID-only trust.
    if !data_dir.join("history.json").exists() && downloads.join("history.json").is_file() {
        std::fs::copy(
            downloads.join("history.json"),
            data_dir.join("history.json"),
        )?;
    }
    let mut settings = Settings::load(&data_dir);
    if let Some(lang) = argument("--lang").filter(|v| v == "AR" || v == "EN") {
        settings.lang = lang;
    }
    let id = get_or_create_device_id(&data_dir);
    let name = argument("--name")
        .or_else(|| {
            std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .ok()
        })
        .unwrap_or_else(|| {
            if mobile {
                "Flow phone".into()
            } else {
                "Flow computer".into()
            }
        });
    let listener = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            let mut last = None;
            for port in 54125..54145 {
                match tokio::net::TcpListener::bind((
                    if local_only { "127.0.0.1" } else { "0.0.0.0" },
                    port,
                ))
                .await
                {
                    Ok(listener) => return Ok(listener),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| std::io::Error::other("No listening port available")))
        })
    })?;
    let port = listener.local_addr()?.port();
    let discovery = Arc::new(DiscoveryManager::with_id(
        id.clone(),
        name,
        if mobile {
            DeviceType::Mobile
        } else {
            DeviceType::Desktop
        },
        port,
    ));
    let trust = Arc::new(TrustManager::try_with_self_id(data_dir.clone(), id)?);
    let transfer = Arc::new(TransferManager::with_trust(
        port,
        downloads.clone(),
        trust.clone(),
    ));
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let server = transfer.clone();
    tokio::spawn(async move {
        server.start_with_listener(listener, event_tx).await;
    });
    let (tx, rx) = mpsc::unbounded_channel();
    let disc = discovery.clone();
    let err_tx = tx.clone();
    if !local_only {
        tokio::spawn(async move {
            if let Err(e) = disc.start().await {
                let _ = err_tx.send(Command::Notice(format!("Local discovery: {e}"), true));
            }
        });
    }
    #[cfg(not(target_os = "android"))]
    crate::window_effects::select_backend()?;
    let window = AppWindow::new()?;
    {
        let state = window.global::<AppState>();
        state.set_mobile_mode(mobile);
        state.set_app_version(env!("CARGO_PKG_VERSION").into());
        state.set_lang(settings.lang.clone().into());
        state.set_dark_mode(settings.dark_mode);
        state.set_clean_links(settings.clean_links);
        state.set_auto_copy(settings.auto_copy);
        state.set_download_path(downloads.to_string_lossy().as_ref().into());
    }
    bind_callbacks(&window, tx.clone());
    #[cfg(not(target_os = "android"))]
    {
        use slint::winit_030::{winit, EventResult, WinitWindowAccessor};
        let tx = tx.clone();
        let weak = window.as_weak();
        window.window().on_winit_window_event(move |window, event| {
            if matches!(
                event,
                winit::event::WindowEvent::Resized(_)
                    | winit::event::WindowEvent::Focused(true)
                    | winit::event::WindowEvent::ThemeChanged(_)
            ) {
                if let Some(w) = weak.upgrade() {
                    let state = w.global::<AppState>();
                    let glass = crate::window_effects::apply(w.window(), state.get_dark_mode());
                    state.set_native_glass(glass);
                }
            }
            if let winit::event::WindowEvent::Resized(size) = event {
                if let Some(w) = weak.upgrade() {
                    w.global::<AppState>()
                        .set_compact_mode((size.width as f32 / window.scale_factor()) < 800.0);
                }
            }
            if let winit::event::WindowEvent::DroppedFile(path) = event {
                let _ = tx.send(Command::Files(vec![path.clone()]));
            }
            EventResult::Propagate
        });
    }
    let root = platform::storage_root().unwrap_or_else(|_| downloads.clone());
    let manual_peer = if local_only {
        argument("--peer-port")
            .and_then(|port| port.parse::<u16>().ok())
            .filter(|port| *port > 0)
            .zip(settings.selected_peer_id.clone())
            .map(|(tcp_port, id)| Peer {
                id,
                name: settings.selected_peer_name.clone(),
                device_type: if mobile {
                    DeviceType::Desktop
                } else {
                    DeviceType::Mobile
                },
                ip: std::net::Ipv4Addr::LOCALHOST.into(),
                tcp_port,
                last_seen: std::time::Instant::now(),
            })
    } else {
        None
    };
    let engine = Engine {
        ui: window.as_weak(),
        tx,
        discovery,
        trust,
        transfer,
        history: HistoryManager::with_storage(data_dir.clone()),
        settings,
        data_dir,
        downloads,
        peers: Vec::new(),
        jobs: Vec::new(),
        received: String::new(),
        notice: String::new(),
        notice_error: false,
        browser_path: root,
        browser_files: Vec::new(),
        selected_files: HashSet::new(),
        browser_read_only: false,
        verified_peer: None,
        probing: false,
        probe_error: None,
        probe_epoch: 0,
        last_probe: None,
        manual_peer,
        slots: Arc::new(tokio::sync::Semaphore::new(4)),
    };
    let task = tokio::spawn(engine.run(rx, event_rx));
    let result = window.run();
    task.abort();
    result?;
    Ok(())
}

fn bind_callbacks(window: &AppWindow, tx: mpsc::UnboundedSender<Command>) {
    let s = window.global::<AppState>();
    macro_rules! bind0 {
        ($method:ident,$cmd:expr) => {{
            let tx = tx.clone();
            s.$method(move || {
                let _ = tx.send($cmd);
            });
        }};
    }
    macro_rules! bind1 {
        ($method:ident,$variant:ident) => {{
            let tx = tx.clone();
            s.$method(move |v| {
                let _ = tx.send(Command::$variant(v.to_string()));
            });
        }};
    }
    bind1!(on_select_peer, Select);
    bind1!(on_send_text, Text);
    bind1!(on_cancel_transfer, Cancel);
    bind1!(on_retry_transfer, Retry);
    bind1!(on_history_action, HistoryAction);
    bind1!(on_pair_device, Pair);
    bind1!(on_forget_device, Forget);
    bind0!(on_send_files, Command::PickFiles);
    bind0!(on_paste_text, Command::Paste);
    bind0!(on_paste_pairing_code, Command::PastePairing);
    bind0!(on_close_file_browser, Command::CloseBrowser);
    bind0!(on_copy_received, Command::Copy);
    bind0!(on_copy_pairing_code, Command::CopyPairing);
    bind0!(on_clear_history, Command::ClearHistory);
    bind0!(on_open_downloads, Command::OpenDownloads);
    bind0!(on_open_update, Command::OpenUpdate);
    bind0!(on_dismiss_notice, Command::Dismiss);
    bind0!(on_refresh_devices, Command::Refresh);
    bind0!(on_browse_up, Command::Up);
    bind0!(on_send_selected_files, Command::SendSelected);
    bind0!(on_request_storage_access, Command::StorageAccess);
    let tx_b = tx.clone();
    s.on_open_browser_file(move |v| {
        let _ = tx_b.send(Command::OpenBrowserFile(PathBuf::from(v.as_str())));
    });
    let tx_b = tx.clone();
    s.on_browse_path(move |v| {
        let _ = tx_b.send(Command::Browse(PathBuf::from(v.as_str())));
    });
    let tx_b = tx.clone();
    s.on_toggle_file(move |v| {
        let _ = tx_b.send(Command::ToggleFile(PathBuf::from(v.as_str())));
    });
    let weak = window.as_weak();
    s.on_save_settings(move || {
        if let Some(w) = weak.upgrade() {
            let s = w.global::<AppState>();
            let _ = tx.send(Command::SaveSettings(Settings {
                lang: s.get_lang().to_string(),
                dark_mode: s.get_dark_mode(),
                clean_links: s.get_clean_links(),
                auto_copy: s.get_auto_copy(),
                selected_peer_id: None,
                selected_peer_name: String::new(),
            }));
        }
    });
}

impl Engine {
    fn ar(&self) -> bool {
        self.settings.lang == "AR"
    }
    fn message(&mut self, en: &str, ar: &str, error: bool) {
        self.notice = tr(self.ar(), en, ar).into();
        self.notice_error = error;
    }
    fn ui(&self, f: impl FnOnce(AppState<'_>) + Send + 'static) {
        let _ = self
            .ui
            .upgrade_in_event_loop(move |w| f(w.global::<AppState>()));
    }
    async fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<Command>,
        mut events: mpsc::UnboundedReceiver<TransferEvent>,
    ) {
        let code = self.trust.pairing_code().await;
        self.ui(move |s| s.set_pairing_code(code.into()));
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut render = tokio::time::interval(std::time::Duration::from_millis(100));
        let mut dirty = true;
        loop {
            tokio::select! {
                Some(command)=rx.recv()=>{self.handle(command).await;dirty=true;},
                Some(event)=events.recv()=>{self.incoming(event).await;dirty=true;},
                _=tick.tick()=>{self.peers=self.discovery.active_peers().await;if let Some(peer)=&self.manual_peer{let mut peer=peer.clone();peer.last_seen=std::time::Instant::now();self.peers.push(peer);}self.peers.sort_by(|a,b|a.name.cmp(&b.name).then(a.id.cmp(&b.id)));self.probe().await;dirty=true;},
                _=render.tick()=>{if dirty{self.publish().await;dirty=false;}}
            }
        }
    }
    async fn selected(&self) -> Result<Peer, String> {
        let id = self.settings.selected_peer_id.as_deref().ok_or_else(|| {
            tr(
                self.ar(),
                "Choose a recipient first.",
                "اختر الجهاز المستلم أولًا.",
            )
            .to_string()
        })?;
        let peer = self
            .peers
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| {
                tr(
                    self.ar(),
                    "Your selected device is offline. It has not been replaced.",
                    "الجهاز المختار غير متاح. لم يتم تغيير المستلم.",
                )
                .to_string()
            })?;
        if !self.trust.is_trusted(id).await {
            return Err(tr(
                self.ar(),
                "Exchange pairing codes on both devices first.",
                "تبادل رمزي الاقتران على الجهازين أولًا.",
            )
            .into());
        }
        Ok(peer)
    }
    async fn probe(&mut self) {
        let Some(id) = self.settings.selected_peer_id.clone() else {
            return;
        };
        let Some(peer) = self.peers.iter().find(|p| p.id == id) else {
            self.verified_peer = None;
            return;
        };
        let interval = if self.probe_error.is_some() { 10 } else { 5 };
        if self.probing
            || self
                .last_probe
                .is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(interval))
            || !self.trust.is_trusted(&id).await
        {
            return;
        }
        self.probing = true;
        self.last_probe = Some(std::time::Instant::now());
        let epoch = self.probe_epoch;
        let target = std::net::SocketAddr::new(peer.ip, peer.tcp_port);
        let manager = self.transfer.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let result = match tokio::time::timeout(
                std::time::Duration::from_secs(6),
                manager.verify_peer(target, &id),
            )
            .await
            {
                Ok(result) => result.map_err(|e| e.to_string()),
                Err(_) => Err("Connection timed out".into()),
            };
            let _ = tx.send(Command::Verified(id, epoch, result));
        });
    }
    fn reset_connection(&mut self) {
        self.probe_epoch = self.probe_epoch.wrapping_add(1);
        self.probing = false;
        self.last_probe = None;
        self.probe_error = None;
        self.verified_peer = None;
    }
    async fn publish(&self) {
        let mut peers = Vec::new();
        for p in &self.peers {
            let mut display = p.clone();
            if self
                .peers
                .iter()
                .filter(|other| other.name == p.name)
                .count()
                > 1
            {
                display.name = format!("{} · {}", p.name, p.id.chars().take(6).collect::<String>());
            }
            peers.push((display, self.trust.is_trusted(&p.id).await));
        }
        let mut trusted = self.trust.list_trusted().await;
        trusted.sort_by(|a, b| a.name.cmp(&b.name));
        let selected = self.settings.selected_peer_id.clone().unwrap_or_default();
        let current = peers.iter().find(|(p, _)| p.id == selected);
        let ready = current.is_some_and(|(_, trusted)| *trusted)
            && self.verified_peer.as_deref() == Some(selected.as_str());
        let name = current.map(|(p, _)| p.name.clone()).unwrap_or_else(|| {
            if self.settings.selected_peer_name.is_empty() {
                tr(self.ar(), "Choose a device", "اختر جهازًا").into()
            } else {
                self.settings.selected_peer_name.clone()
            }
        });
        let status = if selected.is_empty() {
            tr(
                self.ar(),
                "Choose a nearby device to get started",
                "اختر جهازًا قريبًا للبدء",
            )
        } else if current.is_none() {
            tr(
                self.ar(),
                "Selected device is offline",
                "الجهاز المختار غير متاح",
            )
        } else if ready {
            tr(
                self.ar(),
                "Connection verified · ready to send",
                "تم التحقق من الاتصال · جاهز للإرسال",
            )
        } else if current.is_some_and(|(_, trusted)| *trusted) {
            tr(
                self.ar(),
                "Verifying pairing · complete it on both devices",
                "جارٍ التحقق من الاقتران · أكمله على الجهازين",
            )
        } else {
            tr(
                self.ar(),
                "Device found · pairing required",
                "تم العثور على الجهاز · يحتاج إلى اقتران",
            )
        }
        .to_string();
        let status = if current.is_some() && !ready {
            self.probe_error
                .as_deref()
                .map(|e| crate::ux::connection_failure(e, self.ar()))
                .unwrap_or(status)
        } else {
            status
        };
        let mut recent_errors = 0;
        let jobs: Vec<_> = self
            .jobs
            .iter()
            .rev()
            .filter(|j| {
                if matches!(j.status.as_str(), "sending" | "receiving" | "queued") {
                    true
                } else if matches!(j.status.as_str(), "failed" | "cancelled") && recent_errors < 2 {
                    recent_errors += 1;
                    true
                } else {
                    false
                }
            })
            .take(50)
            .map(|j| {
                (
                    j.id.clone(),
                    j.title.clone(),
                    j.detail.clone(),
                    j.progress,
                    j.status.clone(),
                    j.direction.clone(),
                    matches!(j.status.as_str(), "sending" | "receiving" | "queued"),
                )
            })
            .collect();
        let entries = self.history.get_all().await;
        let ar = self.ar();
        let notice = self.notice.clone();
        let err = self.notice_error;
        let received = self.received.clone();
        let busy = self
            .jobs
            .iter()
            .any(|j| matches!(j.status.as_str(), "sending" | "queued"));
        let connection_busy = self.probing;
        let connection_failed = self.probe_error.is_some() && current.is_some() && !ready;
        self.ui(move |s| {
            let peer_rows = peers
                .into_iter()
                .map(|(p, trusted)| PeerItem {
                    id: p.id.clone().into(),
                    name: p.name.into(),
                    kind: match p.device_type {
                        DeviceType::Desktop => "desktop",
                        DeviceType::Mobile => "mobile",
                    }
                    .into(),
                    selected: p.id == selected,
                    trusted,
                })
                .collect();
            s.set_peers(sync_model(s.get_peers(), peer_rows, |a, b| a.id == b.id));
            s.set_selected_peer_id(selected.into());
            s.set_peer_name(name.into());
            s.set_connection_status(status.into());
            s.set_is_connected(ready);
            s.set_connection_busy(connection_busy);
            s.set_connection_failed(connection_failed);
            s.set_busy(busy);
            let trusted_rows = trusted
                .into_iter()
                .map(|p| PeerItem {
                    id: p.id.into(),
                    name: p.name.into(),
                    kind: "desktop".into(),
                    selected: false,
                    trusted: true,
                })
                .collect();
            s.set_trusted_devices(sync_model(s.get_trusted_devices(), trusted_rows, |a, b| {
                a.id == b.id
            }));
            let transfer_rows = jobs
                .into_iter()
                .map(
                    |(id, title, detail, progress, status, direction, can_cancel)| TransferItem {
                        id: id.into(),
                        title: title.into(),
                        detail: detail.into(),
                        progress,
                        status: status.into(),
                        direction: direction.into(),
                        can_cancel,
                    },
                )
                .collect();
            s.set_transfers(sync_model(s.get_transfers(), transfer_rows, |a, b| {
                a.id == b.id
            }));
            s.set_history_items(sync_model(
                s.get_history_items(),
                history_rows(entries, ar),
                |a, b| a.id == b.id,
            ));
            s.set_clipboard_text(received.into());
            s.set_notice(notice.into());
            s.set_notice_error(err);
        });
    }
    async fn handle(&mut self, c: Command) {
        match c {
            Command::Select(id) => {
                if self
                    .jobs
                    .iter()
                    .any(|j| matches!(j.status.as_str(), "sending" | "queued"))
                {
                    self.message(
                        "Wait for your outgoing transfers before changing recipient.",
                        "انتظر اكتمال الإرسال قبل تغيير المستلم.",
                        true,
                    );
                    return;
                }
                if !self.peers.iter().any(|p| p.id == id) {
                    return;
                }
                self.settings.selected_peer_name = self
                    .peers
                    .iter()
                    .find(|p| p.id == id)
                    .map(|p| p.name.clone())
                    .unwrap_or_default();
                self.settings.selected_peer_id = Some(id.clone());
                self.reset_connection();
                self.save_preferences();
                self.selected_files.clear();
                self.publish_browser();
                let pairing = !self.trust.is_trusted(&id).await;
                self.ui(move |s| {
                    s.set_show_devices(false);
                    s.set_show_pairing(pairing);
                });
            }
            Command::Pair(secret) => {
                let Some(id) = self.settings.selected_peer_id.clone() else {
                    return;
                };
                let Some(peer) = self.peers.iter().find(|p| p.id == id) else {
                    self.message("Device unavailable.", "الجهاز غير متاح.", true);
                    return;
                };
                self.ui(|s| s.set_pairing_busy(true));
                match self
                    .trust
                    .trust_peer_with_secret(peer.id.clone(), peer.name.clone(), secret.trim())
                    .await
                {
                    Ok(()) => {
                        self.reset_connection();
                        self.ui(|s| {
                            s.set_show_pairing(false);
                            s.set_pair_secret("".into());
                        });
                        self.message(
                            "Code saved. Enter this device's code on the other device too.",
                            "تم حفظ الرمز. أدخل رمز هذا الجهاز على الجهاز الآخر أيضًا.",
                            false,
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => self.message(
                        "Enter the complete 64-character code shown on the other device.",
                        "أدخل الرمز الكامل المكوّن من 64 خانة الظاهر على الجهاز الآخر.",
                        true,
                    ),
                    Err(e) => {
                        self.notice = format!(
                            "{}: {e}",
                            tr(self.ar(), "Could not save pairing", "تعذّر حفظ الاقتران")
                        );
                        self.notice_error = true;
                    }
                }
                self.ui(|s| s.set_pairing_busy(false));
            }
            Command::Forget(id) => {
                if let Err(e) = self.trust.revoke_peer(&id).await {
                    self.notice = e.to_string();
                    self.notice_error = true;
                } else {
                    if self.settings.selected_peer_id.as_deref() == Some(id.as_str()) {
                        self.reset_connection();
                    }
                    self.message("Device pairing removed.", "تم إلغاء اقتران الجهاز.", false);
                }
            }
            Command::PickFiles => {
                let recipient = match self.selected().await {
                    Ok(peer) => peer.id,
                    Err(e) => {
                        self.notice = e;
                        self.notice_error = true;
                        return;
                    }
                };
                self.selected_files.clear();
                self.browser_read_only = false;
                #[cfg(not(target_os = "android"))]
                {
                    let tx = self.tx.clone();
                    tokio::spawn(async move {
                        match platform::pick_files().await {
                            Ok(p) => {
                                let _ = tx.send(Command::FilesFor(recipient, p));
                            }
                            Err(e) => {
                                let _ = tx.send(Command::Notice(e, true));
                            }
                        }
                    });
                }
                #[cfg(target_os = "android")]
                {
                    let _ = recipient;
                    self.browse(self.browser_path.clone());
                    self.ui(|s| {
                        s.set_browser_read_only(false);
                        s.set_show_file_picker(true);
                    });
                }
            }
            #[cfg(not(target_os = "android"))]
            Command::Files(paths) => {
                let Some(recipient) = self.settings.selected_peer_id.clone() else {
                    self.message(
                        "Choose a recipient first.",
                        "اختر الجهاز المستلم أولًا.",
                        true,
                    );
                    return;
                };
                self.send_files_to(recipient, paths).await;
            }
            Command::FilesFor(recipient, paths) => self.send_files_to(recipient, paths).await,
            Command::Text(text) => {
                if text.trim().is_empty() {
                    self.message("Write a message first.", "اكتب رسالة أولًا.", true);
                    return;
                }
                let peer = match self.selected().await {
                    Ok(p) => p,
                    Err(e) => {
                        self.notice = e;
                        self.notice_error = true;
                        return;
                    }
                };
                let content = if self.settings.clean_links {
                    clean_text(&text).0
                } else {
                    text.clone()
                };
                self.start_send(
                    peer,
                    Payload::Text {
                        content,
                        draft: text,
                    },
                )
                .await;
            }
            Command::Paste => match ClipboardManager::try_read_current() {
                Ok(Some(text)) => self.ui(move |s| s.set_draft_text(text.into())),
                Ok(None) => self.message(
                    "The clipboard has no text.",
                    "الحافظة لا تحتوي على نص.",
                    false,
                ),
                Err(e) => {
                    self.notice = e;
                    self.notice_error = true;
                }
            },
            Command::PastePairing => match ClipboardManager::try_read_current() {
                Ok(Some(text)) => self.ui(move |s| s.set_pair_secret(text.trim().into())),
                Ok(None) => self.message(
                    "Copy the other device’s code first.",
                    "انسخ رمز الجهاز الآخر أولًا.",
                    false,
                ),
                Err(e) => {
                    self.notice = e;
                    self.notice_error = true;
                }
            },
            Command::CloseBrowser => {
                self.selected_files.clear();
                self.publish_browser();
                self.ui(|s| s.set_show_file_picker(false));
            }
            Command::OpenBrowserFile(path) => {
                if self.browser_read_only
                    && self
                        .browser_files
                        .iter()
                        .any(|f| f.path == path && !f.is_dir)
                {
                    let tx = self.tx.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = platform::export_and_open_file(&path) {
                            let _ = tx.send(Command::Notice(e, true));
                        }
                    });
                }
            }
            Command::Copy => {
                if self.received.is_empty() {
                    self.message("No received text to copy.", "لا يوجد نص مستلم لنسخه.", false);
                } else {
                    let text = self.received.clone();
                    self.copy_text(&text);
                }
            }
            Command::CopyPairing => {
                let code = self.trust.pairing_code().await;
                self.copy_text(&code);
            }
            Command::Cancel(id) => {
                let ar = self.ar();
                if let Some(job) = self.jobs.iter_mut().find(|j| j.id == id) {
                    job.cancel.store(true, Ordering::SeqCst);
                    job.detail = tr(ar, "Cancelling…", "جارٍ الإلغاء…").into();
                }
                self.transfer.cancel_incoming(&id);
            }
            Command::Retry(id) => {
                if let Some(job) = self.jobs.iter().find(|j| j.id == id) {
                    if let Some(payload) = job.payload.clone() {
                        let target = job.peer_id.clone();
                        let peer = match self.selected().await {
                            Ok(p) if p.id == target => p,
                            _ => {
                                self.message(
                                    "Select the original recipient before retrying.",
                                    "اختر المستلم الأصلي قبل إعادة المحاولة.",
                                    true,
                                );
                                return;
                            }
                        };
                        self.start_send(peer, payload).await;
                    }
                }
            }
            Command::Progress(id, done, total, speed, eta) => {
                let ar = self.ar();
                if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
                    j.progress = if total == 0 {
                        0.0
                    } else {
                        done as f32 / total as f32
                    };
                    j.detail = progress_detail(done, total, speed, eta, ar);
                }
            }
            Command::Finished(id, result) => self.finish_send(id, result).await,
            Command::Begin(id) => {
                let ar = self.ar();
                if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
                    j.status = "sending".into();
                    j.detail = tr(ar, "Preparing…", "جارٍ التحضير…").into();
                }
            }
            Command::Verified(id, epoch, result) => {
                if epoch == self.probe_epoch
                    && self.settings.selected_peer_id.as_deref() == Some(&id)
                {
                    self.probing = false;
                    self.probe_error = result.as_ref().err().cloned();
                    self.verified_peer = if result.is_ok() { Some(id) } else { None };
                }
            }
            Command::HistoryAction(id) => {
                if let Some(entry) = self.history.find(&id).await {
                    if let Some(path) = entry.path {
                        let tx = self.tx.clone();
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = platform::export_and_open_file(&path) {
                                let _ = tx.send(Command::Notice(e, true));
                            }
                        });
                    } else if let Some(text) = entry.text {
                        self.copy_text(&text);
                    } else {
                        self.message(
                            "This older entry has no saved file location.",
                            "هذا السجل القديم لا يحتوي على موقع الملف.",
                            false,
                        );
                    }
                }
            }
            Command::ClearHistory => match self.history.clear().await {
                Ok(()) => self.message(
                    "History cleared. Your files were kept.",
                    "تم مسح السجل مع الاحتفاظ بالملفات.",
                    false,
                ),
                Err(e) => {
                    self.notice = e;
                    self.notice_error = true;
                }
            },
            Command::SaveSettings(mut settings) => {
                settings.selected_peer_id = self.settings.selected_peer_id.clone();
                settings.selected_peer_name = self.settings.selected_peer_name.clone();
                self.settings = settings;
                self.save_preferences();
                let dark = self.settings.dark_mode;
                let _ = self.ui.upgrade_in_event_loop(move |w| {
                    let glass = crate::window_effects::apply(w.window(), dark);
                    w.global::<AppState>().set_native_glass(glass);
                });
            }
            Command::OpenDownloads => {
                #[cfg(not(target_os = "android"))]
                if let Err(e) = platform::open_path(&self.downloads) {
                    self.notice = e;
                    self.notice_error = true;
                }
                #[cfg(target_os = "android")]
                {
                    self.selected_files.clear();
                    self.browser_read_only = true;
                    self.browse(self.downloads.clone());
                    self.ui(|s| {
                        s.set_browser_read_only(true);
                        s.set_show_file_picker(true);
                    });
                }
            }
            Command::OpenUpdate => {
                if let Err(e) = platform::open_url("https://github.com/XRTM8/Flow/releases") {
                    self.notice = e;
                    self.notice_error = true;
                }
            }
            Command::Dismiss => self.notice.clear(),
            Command::Refresh => {
                self.peers = self.discovery.active_peers().await;
                self.reset_connection();
                self.probe().await;
            }
            Command::ClearFeedback => self.ui(|s| {
                s.set_clipboard_copied(false);
                s.set_text_sent(false);
            }),
            Command::Notice(text, error) => {
                self.notice = text;
                self.notice_error = error;
            }
            Command::Browse(path) => self.browse(path),
            Command::Up => {
                if let Some(parent) = self.browser_path.parent() {
                    self.browse(parent.to_path_buf());
                }
            }
            Command::ToggleFile(path) => {
                if self.browser_read_only {
                    return;
                }
                if self
                    .browser_files
                    .iter()
                    .any(|f| f.path == path && !f.is_dir)
                {
                    if !self.selected_files.remove(&path) {
                        self.selected_files.insert(path);
                    }
                    self.publish_browser();
                }
            }
            Command::SendSelected => {
                if self.browser_read_only {
                    return;
                }
                let mut paths: Vec<_> = self.selected_files.drain().collect();
                paths.sort();
                self.ui(|s| s.set_show_file_picker(false));
                if let Some(recipient) = self.settings.selected_peer_id.clone() {
                    let _ = self.tx.send(Command::FilesFor(recipient, paths));
                }
            }
            Command::StorageAccess => {
                if let Err(e) = platform::request_storage_access() {
                    self.notice = e;
                    self.notice_error = true;
                }
            }
        }
    }
    fn save_preferences(&mut self) {
        if let Err(e) = self.settings.save(&self.data_dir) {
            self.notice = format!(
                "{}: {e}",
                tr(self.ar(), "Could not save settings", "تعذر حفظ الإعدادات")
            );
            self.notice_error = true;
        }
    }
    async fn send_files_to(&mut self, recipient: String, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        if self.settings.selected_peer_id.as_deref() != Some(recipient.as_str()) {
            self.message("The recipient changed while choosing files. Choose the files again for the intended device.","تغيّر المستلم أثناء اختيار الملفات. أعد الاختيار للجهاز المقصود.",true);
            return;
        }
        let peer = match self.selected().await {
            Ok(p) => p,
            Err(e) => {
                self.notice = e;
                self.notice_error = true;
                return;
            }
        };
        let active = self
            .jobs
            .iter()
            .filter(|j| matches!(j.status.as_str(), "sending" | "queued"))
            .count();
        if active + paths.len() > 50 {
            self.message(
                "This selection exceeds the 50-file queue. Send a smaller batch.",
                "يتجاوز التحديد سعة الانتظار البالغة 50 ملفًا. اختر مجموعة أصغر.",
                true,
            );
            return;
        }
        for path in paths {
            self.start_send(peer.clone(), Payload::File(path)).await;
        }
    }
    fn copy_text(&mut self, text: &str) {
        match ClipboardManager::set_text(text) {
            Ok(()) => {
                self.message("Copied to clipboard.", "تم النسخ إلى الحافظة.", false);
                self.ui(|s| s.set_clipboard_copied(true));
                self.clear_feedback_later();
            }
            Err(e) => {
                self.notice = e.to_string();
                self.notice_error = true;
            }
        }
    }
    fn clear_feedback_later(&self) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let _ = tx.send(Command::ClearFeedback);
        });
    }
    fn browse(&mut self, path: PathBuf) {
        if self.browser_read_only {
            let allowed = std::fs::canonicalize(&path)
                .ok()
                .zip(std::fs::canonicalize(&self.downloads).ok())
                .is_some_and(|(path, root)| path.starts_with(root));
            if !allowed {
                return;
            }
        }
        match platform::list_files(&path) {
            Ok(files) => {
                self.browser_path = path;
                self.browser_files = files;
                self.publish_browser();
            }
            Err(e) => {
                self.notice = e;
                self.notice_error = true;
            }
        }
    }
    fn publish_browser(&self) {
        let path = self.browser_path.to_string_lossy().to_string();
        let up = self.browser_path.parent().is_some()
            && (!self.browser_read_only || self.browser_path != self.downloads);
        let count = self.selected_files.len() as i32;
        let files: Vec<_> = self
            .browser_files
            .iter()
            .map(|f| {
                (
                    f.path.to_string_lossy().to_string(),
                    f.name.clone(),
                    f.is_dir,
                    f.size,
                    self.selected_files.contains(&f.path),
                )
            })
            .collect();
        self.ui(move |s| {
            s.set_browser_path(path.into());
            s.set_browser_can_up(up);
            s.set_browser_selection_count(count);
            s.set_browser_items(
                Rc::new(VecModel::from(
                    files
                        .into_iter()
                        .map(|(path, name, is_dir, size, selected)| FilePickerItem {
                            path: path.into(),
                            name: name.into(),
                            detail: if is_dir {
                                "".into()
                            } else {
                                crate::protocol::format_bytes(size).into()
                            },
                            is_dir,
                            selected,
                        })
                        .collect::<Vec<_>>(),
                ))
                .into(),
            );
        });
    }
    async fn start_send(&mut self, peer: Peer, payload: Payload) {
        if self
            .jobs
            .iter()
            .filter(|j| matches!(j.status.as_str(), "sending" | "queued"))
            .count()
            >= 50
        {
            self.message(
                "The queue is full. Wait for some transfers to finish.",
                "قائمة الانتظار ممتلئة. انتظر اكتمال بعض العمليات.",
                true,
            );
            return;
        }
        self.prune_jobs();
        let id = uuid::Uuid::new_v4().to_string();
        let cancel = Arc::new(AtomicBool::new(false));
        let title = match &payload {
            Payload::Text { content, .. } => preview(content, 80),
            Payload::File(path) => path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        };
        self.jobs.push(Job {
            id: id.clone(),
            peer_id: peer.id.clone(),
            peer_name: peer.name.clone(),
            title,
            detail: tr(self.ar(), "Queued", "في الانتظار").into(),
            status: "queued".into(),
            direction: "sent".into(),
            progress: 0.0,
            cancel: cancel.clone(),
            payload: Some(payload.clone()),
        });
        let manager = self.transfer.clone();
        let tx = self.tx.clone();
        let target = std::net::SocketAddr::new(peer.ip, peer.tcp_port);
        let slots = self.slots.clone();
        tokio::spawn(async move {
            let permit = tokio::select! {p=slots.acquire_owned()=>p.ok(),_=wait_cancel(cancel.clone())=>None};
            let Some(_permit) = permit else {
                let _ = tx.send(Command::Finished(id, Err("Cancelled".into())));
                return;
            };
            if cancel.load(Ordering::Acquire) {
                let _ = tx.send(Command::Finished(id, Err("Cancelled".into())));
                return;
            }
            let _ = tx.send(Command::Begin(id.clone()));
            let operation = async {
                match payload {
                    Payload::Text { content, .. } => {
                        manager
                            .send_secure_text(target, &peer.id, content, &id)
                            .await
                    }
                    Payload::File(path) => {
                        let progress_tx = tx.clone();
                        let progress_id = id.clone();
                        manager
                            .send_secure_file(
                                target,
                                &peer.id,
                                &path,
                                &id,
                                cancel.clone(),
                                move |done, total, speed, eta| {
                                    let _ = progress_tx.send(Command::Progress(
                                        progress_id.clone(),
                                        done,
                                        total,
                                        speed,
                                        eta,
                                    ));
                                },
                            )
                            .await
                    }
                }
            };
            let result = tokio::select! {r=operation=>r,_=wait_cancel(cancel.clone())=>Err(std::io::Error::new(std::io::ErrorKind::Interrupted,"Cancelled"))};
            let _ = tx.send(Command::Finished(id, result.map_err(|e| e.to_string())));
        });
    }
    async fn finish_send(&mut self, id: String, result: Result<(), String>) {
        let ar = self.ar();
        let Some(job) = self.jobs.iter_mut().find(|j| j.id == id) else {
            return;
        };
        let success = result.is_ok();
        let cancelled = job.cancel.load(Ordering::SeqCst) && !success;
        job.status = if success {
            "complete"
        } else if cancelled {
            "cancelled"
        } else {
            "failed"
        }
        .into();
        job.detail = match result {
            Ok(()) => tr(
                ar,
                "Received and verified by the other device",
                "تم الاستلام والتحقق على الجهاز الآخر",
            )
            .into(),
            Err(e) => format!("{}: {e}", tr(ar, "Transfer stopped", "توقفت العملية")),
        };
        if success {
            job.progress = 1.0;
        }
        let mut entry = HistoryEntry::new(
            match job.payload {
                Some(Payload::File(_)) => HistoryKind::File,
                _ => HistoryKind::Clipboard,
            },
            job.title.clone(),
            job.detail.clone(),
            success,
        );
        entry.peer_id = job.peer_id.clone();
        entry.peer_name = job.peer_name.clone();
        entry.direction = "sent".into();
        match &job.payload {
            Some(Payload::File(path)) => entry.path = Some(path.clone()),
            Some(Payload::Text { content, .. }) => entry.text = Some(content.clone()),
            None => {}
        }
        let submitted = match &job.payload {
            Some(Payload::Text { draft, .. }) => Some(draft.clone()),
            _ => None,
        };
        if let Err(e) = self.history.record(entry).await {
            self.notice = e;
            self.notice_error = true;
        }
        if success && submitted.is_some() {
            self.ui(move |s| {
                if let Some(submitted) = submitted {
                    if crate::ux::may_clear_draft(s.get_draft_text().as_str(), &submitted) {
                        s.set_draft_text("".into());
                    }
                }
                s.set_text_sent(true);
            });
            self.clear_feedback_later();
        }
    }
    async fn incoming(&mut self, event: TransferEvent) {
        match event {
            TransferEvent::PeerDiscovered(peer) => {
                if peer.id == self.discovery.self_id
                    || uuid::Uuid::parse_str(&peer.id).is_err()
                    || peer.tcp_port == 0
                {
                    return;
                }
                let mut peers = self.discovery.peers.write().await;
                if peers.len() < crate::protocol::discovery::MAX_DISCOVERED_PEERS
                    || peers.contains_key(&peer.id)
                {
                    peers.insert(peer.id.clone(), peer);
                }
            }
            TransferEvent::IncomingStarted {
                id,
                peer_id,
                name,
                total_bytes: _,
                kind: _,
            } => {
                let peer_name = self
                    .peers
                    .iter()
                    .find(|p| p.id == peer_id)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| peer_id.chars().take(8).collect());
                self.prune_jobs();
                self.jobs.push(Job {
                    id,
                    peer_id,
                    peer_name,
                    title: name,
                    detail: tr(self.ar(), "Receiving…", "جارٍ الاستلام…").into(),
                    status: "receiving".into(),
                    direction: "receive".into(),
                    progress: 0.0,
                    cancel: Arc::new(AtomicBool::new(false)),
                    payload: None,
                });
            }
            TransferEvent::IncomingProgress {
                id,
                current_bytes,
                total_bytes,
                speed_mb_s,
                eta_secs,
            } => {
                let ar = self.ar();
                if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
                    j.progress = if total_bytes == 0 {
                        0.0
                    } else {
                        current_bytes as f32 / total_bytes as f32
                    };
                    j.detail =
                        progress_detail(current_bytes, total_bytes, speed_mb_s, eta_secs, ar);
                }
            }
            TransferEvent::IncomingComplete {
                id,
                peer_id,
                name,
                path,
                text,
                total_bytes: _,
            } => {
                let ar = self.ar();
                let peer_name = self
                    .peers
                    .iter()
                    .find(|p| p.id == peer_id)
                    .map(|p| p.name.clone())
                    .unwrap_or_default();
                if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
                    j.status = "complete".into();
                    j.progress = 1.0;
                    j.detail = tr(ar, "Received and verified", "تم الاستلام والتحقق").into();
                }
                let mut entry = HistoryEntry::new(
                    if path.is_some() {
                        HistoryKind::File
                    } else {
                        HistoryKind::Clipboard
                    },
                    name,
                    tr(ar, "Received and verified", "تم الاستلام والتحقق").into(),
                    true,
                );
                entry.path = path;
                entry.peer_id = peer_id;
                entry.peer_name = peer_name;
                entry.direction = "received".into();
                entry.text = text.clone();
                if let Some(text) = text {
                    self.received = text.clone();
                    if self.settings.auto_copy {
                        if let Err(e) = ClipboardManager::set_text(&text) {
                            self.notice = e.to_string();
                            self.notice_error = true;
                        }
                    }
                }
                if let Err(e) = self.history.record(entry).await {
                    self.notice = e;
                    self.notice_error = true;
                }
            }
            TransferEvent::IncomingFailed {
                id,
                peer_id,
                name,
                message,
            } => {
                let ar = self.ar();
                if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
                    j.status = "failed".into();
                    j.detail = message.clone();
                }
                let mut entry = HistoryEntry::new(
                    HistoryKind::File,
                    name,
                    format!("{}: {message}", tr(ar, "Receive failed", "تعذر الاستلام")),
                    false,
                );
                entry.peer_id = peer_id;
                entry.direction = "received".into();
                let _ = self.history.record(entry).await;
                self.notice = format!("{}: {message}", tr(ar, "Receive failed", "تعذر الاستلام"));
                self.notice_error = true;
            }
        }
    }
    fn prune_jobs(&mut self) {
        while self.jobs.len() >= 200 {
            if let Some(i) = self
                .jobs
                .iter()
                .position(|j| !matches!(j.status.as_str(), "sending" | "receiving" | "queued"))
            {
                self.jobs.remove(i);
            } else {
                break;
            }
        }
    }
}

fn preview(text: &str, max: usize) -> String {
    let mut value: String = text.chars().take(max).collect();
    if text.chars().count() > max {
        value.push('…');
    }
    value
}
fn argument(name: &str) -> Option<String> {
    let args: Vec<_> = std::env::args().collect();
    args.windows(2).find(|a| a[0] == name).map(|a| a[1].clone())
}
async fn wait_cancel(cancel: Arc<AtomicBool>) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
}
fn progress_detail(done: u64, total: u64, speed: f64, eta: u64, ar: bool) -> String {
    format!(
        "{} / {} · {:.1} MB/s · {} {}",
        crate::protocol::format_bytes(done),
        crate::protocol::format_bytes(total),
        speed,
        eta,
        tr(ar, "s left", "ث متبقية")
    )
}
/// Preserve repeater instances (and their keyboard focus) while identities stay in place.
/// Slint models must be created and changed on the UI thread, not stored in Engine.
fn sync_model<T: Clone + PartialEq + 'static>(
    current: ModelRc<T>,
    rows: Vec<T>,
    same_identity: impl Fn(&T, &T) -> bool,
) -> ModelRc<T> {
    if let Some(model) = current.as_any().downcast_ref::<VecModel<T>>() {
        if model.row_count() == rows.len() {
            let mut updates = Vec::new();
            let mut compatible = true;
            for (index, row) in rows.iter().enumerate() {
                let Some(previous) = model.row_data(index) else {
                    compatible = false;
                    break;
                };
                if !same_identity(&previous, row) {
                    compatible = false;
                    break;
                }
                if previous != *row {
                    updates.push((index, row.clone()));
                }
            }
            if compatible {
                for (index, row) in updates {
                    model.set_row_data(index, row);
                }
                return current;
            }
        }
    }
    Rc::new(VecModel::from(rows)).into()
}

fn history_rows(entries: Vec<HistoryEntry>, ar: bool) -> Vec<HistoryItem> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    entries
        .into_iter()
        .map(|e| {
            let seconds = now.saturating_sub(e.timestamp_secs);
            let timestamp = if seconds < 60 {
                tr(ar, "Just now", "الآن").into()
            } else if seconds < 3600 {
                format!("{} {}", seconds / 60, tr(ar, "min ago", "دقيقة مضت"))
            } else if seconds < 86400 {
                format!("{} {}", seconds / 3600, tr(ar, "hours ago", "ساعة مضت"))
            } else {
                format!("{} {}", seconds / 86400, tr(ar, "days ago", "يوم مضى"))
            };
            let action_label = if e.path.is_some() {
                if cfg!(target_os = "android") {
                    tr(ar, "Save copy", "حفظ نسخة")
                } else {
                    tr(ar, "Open", "فتح")
                }
            } else if e.text.is_some() {
                tr(ar, "Copy", "نسخ")
            } else {
                ""
            }
            .into();
            let direction = if e.direction == "sent" {
                tr(ar, "Sent", "مُرسل")
            } else {
                tr(ar, "Received", "مستلم")
            };
            let subtitle = format!(
                "{}{}{} · {}",
                direction,
                if e.peer_name.is_empty() { "" } else { " · " },
                e.peer_name,
                e.subtitle
            );
            HistoryItem {
                id: e.id.into(),
                kind: if e.kind == HistoryKind::File {
                    "file"
                } else {
                    "text"
                }
                .into(),
                title: e.title.into(),
                subtitle: subtitle.into(),
                timestamp: timestamp.into(),
                success: e.success,
                action_label,
            }
        })
        .collect()
}

#[cfg(test)]
mod model_tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct Row {
        id: &'static str,
        value: i32,
    }

    #[test]
    fn progress_updates_keep_the_existing_model_and_unchanged_rows() {
        let model: ModelRc<Row> = Rc::new(VecModel::from(vec![
            Row {
                id: "first",
                value: 10,
            },
            Row {
                id: "second",
                value: 20,
            },
        ]))
        .into();
        let updated = sync_model(
            model.clone(),
            vec![
                Row {
                    id: "first",
                    value: 35,
                },
                Row {
                    id: "second",
                    value: 20,
                },
            ],
            |a, b| a.id == b.id,
        );
        assert_eq!(
            model, updated,
            "A progress tick must not replace the repeater's model"
        );
        assert_eq!(model.row_data(0).unwrap().value, 35);
        assert_eq!(model.row_data(1).unwrap().value, 20);
        let unchanged = sync_model(
            updated.clone(),
            vec![
                Row {
                    id: "first",
                    value: 35,
                },
                Row {
                    id: "second",
                    value: 20,
                },
            ],
            |a, b| a.id == b.id,
        );
        assert_eq!(updated, unchanged);
    }

    #[test]
    fn identity_changes_replace_the_model_instead_of_retargeting_focused_rows() {
        let model: ModelRc<Row> = Rc::new(VecModel::from(vec![Row {
            id: "old",
            value: 1,
        }]))
        .into();
        let updated = sync_model(
            model.clone(),
            vec![Row {
                id: "new",
                value: 1,
            }],
            |a, b| a.id == b.id,
        );
        assert_ne!(model, updated);
        assert_eq!(model.row_data(0).unwrap().id, "old");
        assert_eq!(updated.row_data(0).unwrap().id, "new");
    }
}
