use otium_flow::clipboard;
use otium_flow::protocol::{
    clean_text, get_or_create_device_id, DeviceType, DiscoveryManager, HistoryEntry, HistoryKind,
    HistoryManager, Peer, TransferEvent, TransferManager, TrustManager,
};
use slint::{ComponentHandle, ModelRc, VecModel};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

slint::include_modules!();

fn format_clipboard_preview(text: &str) -> String {
    let char_count = text.chars().count();
    if char_count > 250 {
        let preview: String = text.chars().take(230).collect();
        format!("{}... ({} chars)", preview.trim_end(), char_count)
    } else {
        text.to_string()
    }
}

fn history_entries_to_slint_model(entries: &[HistoryEntry]) -> ModelRc<HistoryItem> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let slint_items: Vec<HistoryItem> = entries
        .iter()
        .map(|e| {
            let diff = now.saturating_sub(e.timestamp_secs);
            let time_str = if diff < 60 {
                "Just now".to_string()
            } else if diff < 3600 {
                format!("{}m ago", diff / 60)
            } else {
                format!("{}h ago", diff / 3600)
            };

            HistoryItem {
                id: e.id.clone().into(),
                kind: match e.kind {
                    HistoryKind::File => "file".into(),
                    HistoryKind::Clipboard => "clip".into(),
                },
                title: e.title.clone().into(),
                subtitle: e.subtitle.clone().into(),
                timestamp: time_str.into(),
                success: e.success,
            }
        })
        .collect();

    Rc::new(VecModel::from(slint_items)).into()
}

async fn find_available_tcp_port(start_port: u16) -> (u16, tokio::net::TcpListener) {
    for port in start_port..(start_port + 20) {
        if let Ok(listener) = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            return (port, listener);
        }
    }
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (port, listener)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let is_mobile_mode = args.contains(&"--mobile".to_string());

    let device_name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "Desktop PC".to_string());

    let download_dir = dirs_or_fallback();
    let (tcp_port, tcp_listener) = find_available_tcp_port(54125).await;

    // استخراج أو توليد معرف دائم للجهاز مثبت على القرص لضمان ثبات الثقة
    let persistent_device_id = get_or_create_device_id(&download_dir);

    // 1. إدارة الاكتشاف التلقائي عبر الشبكة المحلية بمعرف دائم (Multi-Subnet & Hotspot Ready)
    let discovery = Arc::new(DiscoveryManager::with_id(
        persistent_device_id.clone(),
        device_name.clone(),
        if is_mobile_mode {
            DeviceType::Mobile
        } else {
            DeviceType::Desktop
        },
        tcp_port,
    ));
    discovery.clone().start().await?;

    // 2. نظام الثقة وإدارة استقبال الملفات والحافظة مع دعم الإلغاء اللحظي
    let trust_manager = Arc::new(TrustManager::new(download_dir.clone()));
    let cancel_token = Arc::new(AtomicBool::new(false));

    let (event_tx, event_rx) = mpsc::unbounded_channel::<TransferEvent>();
    let transfer = Arc::new(
        TransferManager::with_trust(tcp_port, download_dir.clone(), trust_manager.clone())
            .with_cancellation(cancel_token.clone()),
    );
    transfer.clone().start_with_listener(tcp_listener, event_tx).await;

    // 3. تخزين الهدف النشط وسجل النشاطات الدائم
    let active_peer: Arc<RwLock<Option<Peer>>> = Arc::new(RwLock::new(None));
    let history = Arc::new(HistoryManager::with_storage(download_dir.clone()));

    if is_mobile_mode {
        run_mobile(
            discovery,
            active_peer,
            download_dir,
            event_rx,
            history,
            trust_manager,
            cancel_token,
            persistent_device_id,
        )
        .await?;
    } else {
        run_desktop(
            discovery,
            active_peer,
            download_dir,
            event_rx,
            history,
            trust_manager,
            cancel_token,
            persistent_device_id,
        )
        .await?;
    }

    Ok(())
}

fn dirs_or_fallback() -> PathBuf {
    #[cfg(target_os = "android")]
    {
        let android_pub = PathBuf::from("/storage/emulated/0/Download/OtiumFlow");
        if let Some(parent) = android_pub.parent() {
            if parent.exists() {
                return android_pub;
            }
        }
        let sdcard_pub = PathBuf::from("/sdcard/Download/OtiumFlow");
        if let Some(parent) = sdcard_pub.parent() {
            if parent.exists() {
                return sdcard_pub;
            }
        }
    }
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        PathBuf::from(user_profile).join("Downloads").join("OtiumFlow")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join("Downloads").join("OtiumFlow")
    } else {
        PathBuf::from("./Downloads")
    }
}

/// تشغيل واجهة الحاسوب
async fn run_desktop(
    discovery: Arc<DiscoveryManager>,
    active_peer: Arc<RwLock<Option<Peer>>>,
    download_dir: PathBuf,
    mut event_rx: mpsc::UnboundedReceiver<TransferEvent>,
    history: Arc<HistoryManager>,
    trust_manager: Arc<TrustManager>,
    cancel_token: Arc<AtomicBool>,
    persistent_device_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = DesktopApp::new()?;
    let app_weak = app.as_weak();

    let last_received_text = Arc::new(RwLock::new(String::new()));
    let full_clipboard_text = Arc::new(RwLock::new(String::new()));
    let remote_echo_guard = Arc::new(RwLock::new(String::new()));
    let active_transfers_count = Arc::new(AtomicUsize::new(0));

    // تشغيل مراقبة الحافظة المحلية وتطهير الروابط تلقائياً
    let clipboard_mgr = Arc::new(clipboard::ClipboardManager::new());
    let (clip_tx, mut clip_rx) = mpsc::unbounded_channel::<String>();
    clipboard_mgr.start_monitoring(clip_tx);

    let ui_clip = app_weak.clone();
    let echo_guard = last_received_text.clone();
    let remote_echo_check = remote_echo_guard.clone();
    let full_clip_watch = full_clipboard_text.clone();
    tokio::spawn(async move {
        while let Some(text) = clip_rx.recv().await {
            // حماية صارمة لمنع حلقة الصدى اللانهائية للحافظة
            let remote_last = remote_echo_check.read().await.clone();
            if text == remote_last || text == *echo_guard.read().await {
                continue;
            }

            let (cleaned, was_cleaned) = clean_text(&text);
            *full_clip_watch.write().await = cleaned.clone();
            let preview = format_clipboard_preview(&cleaned);

            let _ = ui_clip.upgrade_in_event_loop(move |ui| {
                ui.set_clipboard_text(preview.into());
                ui.set_clipboard_cleaned(was_cleaned);
            });
        }
    });

    // مهمة دورية لتحديث وتثبيت الجهاز المتصل لمنع التخبط العشوائي في الشبكات متعددة الأجهزة
    let d_clone = discovery.clone();
    let p_clone = active_peer.clone();
    let ui_handle = app_weak.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            let mut peers = d_clone.active_peers().await;
            peers.sort_by(|a, b| a.name.cmp(&b.name));
            let mut active = p_clone.write().await;

            let selected = if let Some(current) = active.as_ref() {
                peers.iter().find(|p| p.id == current.id).cloned().or_else(|| peers.first().cloned())
            } else {
                peers.first().cloned()
            };

            if let Some(peer) = selected {
                *active = Some(peer.clone());
                // تمييز الأجهزة المتشابهة في الاسم بإضافة جزء فريد من المعرف
                let name = if peers.iter().filter(|p| p.name == peer.name).count() > 1 {
                    let suffix = if peer.id.len() >= 4 { &peer.id[..4] } else { &peer.id };
                    format!("{} (#{}) • Connected", peer.name, suffix)
                } else {
                    format!("{} • Connected", peer.name)
                };
                let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                    ui.set_is_connected(true);
                    ui.set_peer_name(name.into());
                });
            } else {
                *active = None;
                let _ = ui_handle.upgrade_in_event_loop(|ui| {
                    ui.set_is_connected(false);
                    ui.set_peer_name("Scanning Wi-Fi...".into());
                });
            }
        }
    });

    // مهمة معالجة الأحداث الواردة (نصوص وملفات) مع السرعة الحية والوقت المتبقي ومنع ارتعاش التقدم
    let ui_handle2 = app_weak.clone();
    let echo_receive = last_received_text.clone();
    let remote_echo_set = remote_echo_guard.clone();
    let full_clip_recv = full_clipboard_text.clone();
    let hist_receive = history.clone();
    let active_count_recv = active_transfers_count.clone();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                TransferEvent::ClipboardReceived(text) => {
                    let (cleaned, was_cleaned) = clean_text(&text);
                    *echo_receive.write().await = cleaned.clone();
                    *full_clip_recv.write().await = cleaned.clone();
                    *remote_echo_set.write().await = cleaned.clone();
                    let preview = format_clipboard_preview(&cleaned);
                    let _ = clipboard::ClipboardManager::set_text(&cleaned);

                    let hist = hist_receive.clone();
                    let preview_copy = preview.clone();
                    tokio::spawn(async move {
                        hist.add_entry(
                            HistoryKind::Clipboard,
                            preview_copy,
                            if was_cleaned { "Received (Cleaned)" } else { "Received" }.to_string(),
                            true,
                        )
                        .await;
                    });

                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_clipboard_text(preview.into());
                        ui.set_clipboard_cleaned(was_cleaned);
                    });
                }
                TransferEvent::ClipboardImageReceived { width, height, data } => {
                    let _ = arboard::Clipboard::new().and_then(|mut cb| {
                        cb.set_image(arboard::ImageData {
                            width,
                            height,
                            bytes: std::borrow::Cow::Borrowed(&data),
                        })
                    });

                    let hist = hist_receive.clone();
                    tokio::spawn(async move {
                        hist.add_entry(
                            HistoryKind::Clipboard,
                            format!("🖼️ Image ({}x{} px)", width, height),
                            "Received Screenshot".to_string(),
                            true,
                        )
                        .await;
                    });

                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_clipboard_text(format!("🖼️ Screenshot Synced ({}x{} px)", width, height).into());
                        ui.set_clipboard_cleaned(false);
                    });
                }
                TransferEvent::FileStart { name, total_bytes: _ } => {
                    active_count_recv.fetch_add(1, Ordering::SeqCst);
                    let fname = name.clone();
                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_transfer_active(true);
                        ui.set_transfer_name(fname.into());
                        ui.set_transfer_progress(0.0);
                        ui.set_transfer_status("Connecting...".into());
                    });
                }
                TransferEvent::FileProgress { name: _, current_bytes, total_bytes, speed_mb_s, eta_secs } => {
                    let progress = current_bytes as f32 / total_bytes as f32;
                    let mb_done = current_bytes as f64 / (1024.0 * 1024.0);
                    let mb_total = total_bytes as f64 / (1024.0 * 1024.0);
                    let status = format!("{:.1}/{:.1} MB • {:.1} MB/s ({}s)", mb_done, mb_total, speed_mb_s, eta_secs);

                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_transfer_progress(progress);
                        ui.set_transfer_status(status.into());
                    });
                }
                TransferEvent::FileComplete { name, path: _ } => {
                    let hist = hist_receive.clone();
                    let fname = name.clone();
                    tokio::spawn(async move {
                        hist.add_entry(HistoryKind::File, fname, "Received via Wi-Fi".to_string(), true).await;
                    });

                    let _remaining = active_count_recv.fetch_sub(1, Ordering::SeqCst);
                    let ui_done = ui_handle2.clone();
                    let count_check = active_count_recv.clone();
                    tokio::spawn(async move {
                        let _ = ui_done.upgrade_in_event_loop(|ui| {
                            ui.set_transfer_status("Complete ✓".into());
                        });
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                        if count_check.load(Ordering::SeqCst) == 0 {
                            let _ = ui_done.upgrade_in_event_loop(|ui| {
                                ui.set_transfer_active(false);
                            });
                        }
                    });
                }
                TransferEvent::Error(err) => {
                    eprintln!("[Transfer Error] {:?}", err);
                    active_count_recv.store(0, Ordering::SeqCst);
                    let err_display = format!("Error: {}", err);
                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_transfer_status(err_display.into());
                    });
                    tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
                    let _ = ui_handle2.upgrade_in_event_loop(|ui| {
                        ui.set_transfer_active(false);
                    });
                }
            }
        }
    });

    // أزرار الواجهة
    let full_clip_copy = full_clipboard_text.clone();
    app.on_copy_clipboard_clicked(move || {
        let text_arc = full_clip_copy.clone();
        tokio::spawn(async move {
            let text = text_arc.read().await.clone();
            if !text.is_empty() {
                let _ = clipboard::ClipboardManager::set_text(&text);
            }
        });
    });

    let p_send = active_peer.clone();
    let full_clip_push = full_clipboard_text.clone();
    let hist_push = history.clone();
    let trust_clip = trust_manager.clone();
    let dev_id_clip = persistent_device_id.clone();
    app.on_send_clipboard_clicked(move || {
        let p_arc = p_send.clone();
        let clip_arc = full_clip_push.clone();
        let hist = hist_push.clone();
        let trust = trust_clip.clone();
        let dev_id = dev_id_clip.clone();
        tokio::spawn(async move {
            let peer = { p_arc.read().await.clone() };
            if let Some(peer) = peer {
                let current = {
                    let in_mem = clip_arc.read().await.clone();
                    if in_mem.is_empty() {
                        clipboard::ClipboardManager::read_current().unwrap_or_default()
                    } else {
                        in_mem
                    }
                };

                if !current.is_empty() {
                    let (cleaned, _) = clean_text(&current);
                    let target = SocketAddr::new(peer.ip, peer.tcp_port);
                    let master_key = trust.get_master_key().await;
                    // إرسال الحافظة بتشفير عسكري ChaCha20-Poly1305 E2EE مع مفتاح معتمد وتوثيق هوية
                    let res = TransferManager::send_encrypted_clipboard_with_auth(
                        target,
                        cleaned.clone(),
                        Some(dev_id),
                        Some(master_key),
                    ).await;
                    if res.is_ok() {
                        let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                        hist.add_entry(HistoryKind::Clipboard, format_clipboard_preview(&cleaned), "Pushed (E2EE)".to_string(), true).await;
                    }
                } else if let Some((w, h, data)) = clipboard::ClipboardManager::read_current_image_bytes() {
                    let target = SocketAddr::new(peer.ip, peer.tcp_port);
                    let res = TransferManager::send_clipboard_image(target, w, h, data, Some(dev_id)).await;
                    if res.is_ok() {
                        let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                        hist.add_entry(HistoryKind::Clipboard, format!("🖼️ Image ({}x{} px)", w, h), "Pushed Screenshot".to_string(), true).await;
                    }
                }
            }
        });
    });

    let p_file = active_peer.clone();
    let ui_send_file = app_weak.clone();
    let hist_file_send = history.clone();
    let trust_file = trust_manager.clone();
    let cancel_file_send = cancel_token.clone();
    let dev_id_file = persistent_device_id.clone();
    let active_send_cnt = active_transfers_count.clone();
    app.on_send_file_clicked(move || {
        let p_arc = p_file.clone();
        let ui_handle = ui_send_file.clone();
        let hist = hist_file_send.clone();
        let trust = trust_file.clone();
        let cancel_tok = cancel_file_send.clone();
        let dev_id = dev_id_file.clone();
        let count_tracker = active_send_cnt.clone();

        tokio::spawn(async move {
            let files_opt = rfd::AsyncFileDialog::new()
                .set_title("Select Files to Send via Otium Flow")
                .pick_files()
                .await;

            if let Some(file_handles) = files_opt {
                if file_handles.is_empty() {
                    return;
                }

                cancel_tok.store(false, Ordering::SeqCst);
                count_tracker.store(file_handles.len(), Ordering::SeqCst);

                let paths: Vec<PathBuf> = file_handles.into_iter().map(|f| f.path().to_path_buf()).collect();
                let peer = { p_arc.read().await.clone() };

                if let Some(peer) = peer {
                    let target = SocketAddr::new(peer.ip, peer.tcp_port);

                    let _ = ui_handle.upgrade_in_event_loop(|ui| {
                        ui.set_transfer_active(true);
                        ui.set_transfer_progress(0.0);
                        ui.set_transfer_status("Preparing...".into());
                    });

                    let ui_prog = ui_handle.clone();
                    let paths_clone = paths.clone();
                    let send_res = TransferManager::send_multiple_files_cancellable(
                        target,
                        &paths,
                        Some(dev_id),
                        Some(cancel_tok.clone()),
                        move |idx, total_count, sent, total, speed, eta| {
                            let prog = sent as f32 / total as f32;
                            let mb_done = sent as f64 / (1024.0 * 1024.0);
                            let mb_total = total as f64 / (1024.0 * 1024.0);
                            let status = format!("[{}/{}] {:.1}/{:.1} MB • {:.1} MB/s ({}s)", idx, total_count, mb_done, mb_total, speed, eta);

                            let _ = ui_prog.upgrade_in_event_loop(move |ui| {
                                ui.set_transfer_progress(prog);
                                ui.set_transfer_status(status.into());
                            });
                        },
                    ).await;

                    match send_res {
                        Ok(()) => {
                            count_tracker.store(0, Ordering::SeqCst);
                            let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                            for path in paths_clone {
                                let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
                                let meta_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                                let mb = meta_size as f64 / (1024.0 * 1024.0);
                                hist.add_entry(HistoryKind::File, fname, format!("{:.1} MB • Sent", mb), true).await;
                            }

                            let _ = ui_handle.upgrade_in_event_loop(|ui| {
                                ui.set_transfer_status("All Sent ✓".into());
                            });
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                            let _ = ui_handle.upgrade_in_event_loop(|ui| {
                                ui.set_transfer_active(false);
                            });
                        }
                        Err(e) => {
                            count_tracker.store(0, Ordering::SeqCst);
                            eprintln!("[Send File Error] {:?}", e);
                            let err_msg = format!("Failed: {}", e);
                            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                                ui.set_transfer_status(err_msg.into());
                            });
                            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
                            let _ = ui_handle.upgrade_in_event_loop(|ui| {
                                ui.set_transfer_active(false);
                            });
                        }
                    }
                }
            }
        });
    });

    let ui_cancel = app_weak.clone();
    let cancel_trigger = cancel_token.clone();
    let counter_cancel = active_transfers_count.clone();
    app.on_cancel_transfer_clicked(move || {
        cancel_trigger.store(true, Ordering::SeqCst);
        counter_cancel.store(0, Ordering::SeqCst);
        let _ = ui_cancel.upgrade_in_event_loop(|ui| {
            ui.set_transfer_status("Cancelling... ✕".into());
        });
        let ui_delayed = ui_cancel.clone();
        let cancel_reset = cancel_trigger.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
            cancel_reset.store(false, Ordering::SeqCst);
            let _ = ui_delayed.upgrade_in_event_loop(|ui| {
                ui.set_transfer_active(false);
                ui.set_transfer_status("Cancelled ✕".into());
            });
        });
    });

    let dir_copy = download_dir.clone();
    app.on_open_downloads_clicked(move || {
        let _ = std::fs::create_dir_all(&dir_copy);
        #[cfg(target_os = "windows")]
        let _ = std::process::Command::new("explorer").arg(&dir_copy).spawn();
        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("open").arg(&dir_copy).spawn();
        #[cfg(target_os = "linux")]
        let _ = std::process::Command::new("xdg-open").arg(&dir_copy).spawn();
    });

    // معالجة فتح وإغلاق ومسح سجل النشاطات في الحاسوب
    let ui_hist_toggle = app_weak.clone();
    let hist_toggle_ref = history.clone();
    app.on_toggle_history(move || {
        let hist_c = hist_toggle_ref.clone();
        let _ = ui_hist_toggle.upgrade_in_event_loop(move |ui| {
            let next_val = !ui.get_show_history();
            ui.set_show_history(next_val);
            if next_val {
                let ui_inner = ui.as_weak();
                tokio::spawn(async move {
                    let items = hist_c.get_all().await;
                    let _ = ui_inner.upgrade_in_event_loop(move |u| {
                        let model = history_entries_to_slint_model(&items);
                        u.set_history_items(model);
                    });
                });
            }
        });
    });

    let ui_hist_clear = app_weak.clone();
    let hist_clear_ref = history.clone();
    app.on_clear_history(move || {
        let hist_c = hist_clear_ref.clone();
        let ui_inner = ui_hist_clear.clone();
        tokio::spawn(async move {
            hist_c.clear().await;
            let _ = ui_inner.upgrade_in_event_loop(move |u| {
                let empty_model = history_entries_to_slint_model(&[]);
                u.set_history_items(empty_model);
            });
        });
    });

    app.run()?;
    Ok(())
}

/// تشغيل واجهة الهاتف (مع مراعاة البردة وشريط الإيماءات)
async fn run_mobile(
    discovery: Arc<DiscoveryManager>,
    active_peer: Arc<RwLock<Option<Peer>>>,
    download_dir: PathBuf,
    mut event_rx: mpsc::UnboundedReceiver<TransferEvent>,
    history: Arc<HistoryManager>,
    trust_manager: Arc<TrustManager>,
    cancel_token: Arc<AtomicBool>,
    persistent_device_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = MobileApp::new()?;
    let app_weak = app.as_weak();

    let last_received_text = Arc::new(RwLock::new(String::new()));
    let full_clipboard_text = Arc::new(RwLock::new(String::new()));
    let remote_echo_guard = Arc::new(RwLock::new(String::new()));
    let active_transfers_count = Arc::new(AtomicUsize::new(0));

    let clipboard_mgr = Arc::new(clipboard::ClipboardManager::new());
    let (clip_tx, mut clip_rx) = mpsc::unbounded_channel::<String>();
    clipboard_mgr.start_monitoring(clip_tx);

    let ui_clip = app_weak.clone();
    let echo_guard = last_received_text.clone();
    let remote_echo_check = remote_echo_guard.clone();
    let full_clip_watch = full_clipboard_text.clone();
    tokio::spawn(async move {
        while let Some(text) = clip_rx.recv().await {
            // حظر حلقة صدى الحافظة في الهاتف
            let remote_last = remote_echo_check.read().await.clone();
            if text == remote_last || text == *echo_guard.read().await {
                continue;
            }
            let (cleaned, was_cleaned) = clean_text(&text);
            *full_clip_watch.write().await = cleaned.clone();
            let preview = format_clipboard_preview(&cleaned);

            let _ = ui_clip.upgrade_in_event_loop(move |ui| {
                ui.set_last_received_text(preview.into());
                ui.set_text_cleaned(was_cleaned);
            });
        }
    });

    // مهمة دورية لتحديث وتثبيت الجهاز المتصل لمنع التخبط العشوائي في الهاتف
    let d_clone = discovery.clone();
    let p_clone = active_peer.clone();
    let ui_handle = app_weak.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            let mut peers = d_clone.active_peers().await;
            peers.sort_by(|a, b| a.name.cmp(&b.name));
            let mut active = p_clone.write().await;

            let selected = if let Some(current) = active.as_ref() {
                peers.iter().find(|p| p.id == current.id).cloned().or_else(|| peers.first().cloned())
            } else {
                peers.first().cloned()
            };

            if let Some(peer) = selected {
                *active = Some(peer.clone());
                // تمييز الأجهزة المتشابهة في الاسم بإضافة جزء فريد من المعرف
                let name = if peers.iter().filter(|p| p.name == peer.name).count() > 1 {
                    let suffix = if peer.id.len() >= 4 { &peer.id[..4] } else { &peer.id };
                    format!("{} (#{}) • Connected", peer.name, suffix)
                } else {
                    format!("{} • Connected", peer.name)
                };
                let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                    ui.set_is_connected(true);
                    ui.set_peer_name(name.into());
                });
            } else {
                *active = None;
                let _ = ui_handle.upgrade_in_event_loop(|ui| {
                    ui.set_is_connected(false);
                    ui.set_peer_name("Scanning Wi-Fi...".into());
                });
            }
        }
    });

    let ui_handle2 = app_weak.clone();
    let echo_receive = last_received_text.clone();
    let remote_echo_set = remote_echo_guard.clone();
    let full_clip_recv = full_clipboard_text.clone();
    let hist_receive = history.clone();
    let active_count_recv = active_transfers_count.clone();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                TransferEvent::ClipboardReceived(text) => {
                    let (cleaned, was_cleaned) = clean_text(&text);
                    *echo_receive.write().await = cleaned.clone();
                    *full_clip_recv.write().await = cleaned.clone();
                    *remote_echo_set.write().await = cleaned.clone();
                    let preview = format_clipboard_preview(&cleaned);
                    let _ = clipboard::ClipboardManager::set_text(&cleaned);

                    let hist = hist_receive.clone();
                    let preview_copy = preview.clone();
                    tokio::spawn(async move {
                        hist.add_entry(
                            HistoryKind::Clipboard,
                            preview_copy,
                            if was_cleaned { "Received (Cleaned)" } else { "Received" }.to_string(),
                            true,
                        )
                        .await;
                    });

                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_last_received_text(preview.into());
                        ui.set_text_cleaned(was_cleaned);
                    });
                }
                TransferEvent::ClipboardImageReceived { width, height, data } => {
                    let _ = arboard::Clipboard::new().and_then(|mut cb| {
                        cb.set_image(arboard::ImageData {
                            width,
                            height,
                            bytes: std::borrow::Cow::Borrowed(&data),
                        })
                    });

                    let hist = hist_receive.clone();
                    tokio::spawn(async move {
                        hist.add_entry(
                            HistoryKind::Clipboard,
                            format!("🖼️ Image ({}x{} px)", width, height),
                            "Received Screenshot".to_string(),
                            true,
                        )
                        .await;
                    });

                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_last_received_text(format!("🖼️ Screenshot Synced ({}x{} px)", width, height).into());
                        ui.set_text_cleaned(false);
                    });
                }
                TransferEvent::FileStart { name, total_bytes: _ } => {
                    active_count_recv.fetch_add(1, Ordering::SeqCst);
                    let fname = name.clone();
                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_transfer_active(true);
                        ui.set_transfer_name(fname.into());
                        ui.set_transfer_progress(0.0);
                        ui.set_transfer_status("Receiving...".into());
                    });
                }
                TransferEvent::FileProgress { name: _, current_bytes, total_bytes, speed_mb_s, eta_secs } => {
                    let progress = current_bytes as f32 / total_bytes as f32;
                    let mb_done = current_bytes as f64 / (1024.0 * 1024.0);
                    let mb_total = total_bytes as f64 / (1024.0 * 1024.0);
                    let status = format!("{:.1}/{:.1} MB • {:.1} MB/s ({}s)", mb_done, mb_total, speed_mb_s, eta_secs);

                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_transfer_progress(progress);
                        ui.set_transfer_status(status.into());
                    });
                }
                TransferEvent::FileComplete { name, path: _ } => {
                    let hist = hist_receive.clone();
                    let fname = name.clone();
                    tokio::spawn(async move {
                        hist.add_entry(HistoryKind::File, fname, "Saved to Downloads".to_string(), true).await;
                    });

                    let _remaining = active_count_recv.fetch_sub(1, Ordering::SeqCst);
                    let ui_done = ui_handle2.clone();
                    let count_check = active_count_recv.clone();
                    tokio::spawn(async move {
                        let _ = ui_done.upgrade_in_event_loop(|ui| {
                            ui.set_transfer_status("Saved to Downloads ✓".into());
                        });
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                        if count_check.load(Ordering::SeqCst) == 0 {
                            let _ = ui_done.upgrade_in_event_loop(|ui| {
                                ui.set_transfer_active(false);
                            });
                        }
                    });
                }
                TransferEvent::Error(err) => {
                    eprintln!("[Mobile Transfer Error] {:?}", err);
                    active_count_recv.store(0, Ordering::SeqCst);
                    let err_display = format!("Error: {}", err);
                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_transfer_status(err_display.into());
                    });
                    tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
                    let _ = ui_handle2.upgrade_in_event_loop(|ui| {
                        ui.set_transfer_active(false);
                    });
                }
            }
        }
    });

    let full_clip_copy = full_clipboard_text.clone();
    app.on_copy_received_clicked(move || {
        let text_arc = full_clip_copy.clone();
        tokio::spawn(async move {
            let text = text_arc.read().await.clone();
            if !text.is_empty() {
                let _ = clipboard::ClipboardManager::set_text(&text);
            }
        });
    });

    let p_send = active_peer.clone();
    let full_clip_push = full_clipboard_text.clone();
    let hist_push = history.clone();
    let trust_clip = trust_manager.clone();
    let dev_id_clip = persistent_device_id.clone();
    app.on_push_clipboard_clicked(move || {
        let p_arc = p_send.clone();
        let clip_arc = full_clip_push.clone();
        let hist = hist_push.clone();
        let trust = trust_clip.clone();
        let dev_id = dev_id_clip.clone();
        tokio::spawn(async move {
            let peer = { p_arc.read().await.clone() };
            if let Some(peer) = peer {
                let current = {
                    let in_mem = clip_arc.read().await.clone();
                    if in_mem.is_empty() {
                        clipboard::ClipboardManager::read_current().unwrap_or_default()
                    } else {
                        in_mem
                    }
                };

                if !current.is_empty() {
                    let (cleaned, _) = clean_text(&current);
                    let target = SocketAddr::new(peer.ip, peer.tcp_port);
                    let master_key = trust.get_master_key().await;
                    // إرسال الحافظة بتشفير عسكري ChaCha20-Poly1305 E2EE مع مفتاح معتمد وتوثيق هوية
                    let res = TransferManager::send_encrypted_clipboard_with_auth(
                        target,
                        cleaned.clone(),
                        Some(dev_id),
                        Some(master_key),
                    ).await;
                    if res.is_ok() {
                        let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                        hist.add_entry(HistoryKind::Clipboard, format_clipboard_preview(&cleaned), "Pushed (E2EE)".to_string(), true).await;
                    }
                } else if let Some((w, h, data)) = clipboard::ClipboardManager::read_current_image_bytes() {
                    let target = SocketAddr::new(peer.ip, peer.tcp_port);
                    let res = TransferManager::send_clipboard_image(target, w, h, data, Some(dev_id)).await;
                    if res.is_ok() {
                        let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                        hist.add_entry(HistoryKind::Clipboard, format!("🖼️ Image ({}x{} px)", w, h), "Pushed Screenshot".to_string(), true).await;
                    }
                }
            }
        });
    });

    let p_file = active_peer.clone();
    let ui_send_file = app_weak.clone();
    let hist_file_send = history.clone();
    let trust_file = trust_manager.clone();
    let cancel_file_send = cancel_token.clone();
    let dev_id_file = persistent_device_id.clone();
    let active_send_cnt = active_transfers_count.clone();
    app.on_share_file_clicked(move || {
        let p_arc = p_file.clone();
        let ui_handle = ui_send_file.clone();
        let hist = hist_file_send.clone();
        let trust = trust_file.clone();
        let cancel_tok = cancel_file_send.clone();
        let dev_id = dev_id_file.clone();
        let count_tracker = active_send_cnt.clone();

        tokio::spawn(async move {
            let files_opt = rfd::AsyncFileDialog::new()
                .set_title("Select Files or Photos to Send to PC")
                .pick_files()
                .await;

            if let Some(file_handles) = files_opt {
                if file_handles.is_empty() {
                    return;
                }

                cancel_tok.store(false, Ordering::SeqCst);
                count_tracker.store(file_handles.len(), Ordering::SeqCst);

                let paths: Vec<PathBuf> = file_handles.into_iter().map(|f| f.path().to_path_buf()).collect();
                let peer = { p_arc.read().await.clone() };

                if let Some(peer) = peer {
                    let target = SocketAddr::new(peer.ip, peer.tcp_port);

                    let _ = ui_handle.upgrade_in_event_loop(|ui| {
                        ui.set_transfer_active(true);
                        ui.set_transfer_progress(0.0);
                        ui.set_transfer_status("Preparing...".into());
                    });

                    let ui_prog = ui_handle.clone();
                    let paths_clone = paths.clone();
                    let send_res = TransferManager::send_multiple_files_cancellable(
                        target,
                        &paths,
                        Some(dev_id),
                        Some(cancel_tok.clone()),
                        move |idx, total_count, sent, total, speed, eta| {
                            let prog = sent as f32 / total as f32;
                            let mb_done = sent as f64 / (1024.0 * 1024.0);
                            let mb_total = total as f64 / (1024.0 * 1024.0);
                            let status = format!("[{}/{}] {:.1}/{:.1} MB • {:.1} MB/s ({}s)", idx, total_count, mb_done, mb_total, speed, eta);

                            let _ = ui_prog.upgrade_in_event_loop(move |ui| {
                                ui.set_transfer_progress(prog);
                                ui.set_transfer_status(status.into());
                            });
                        },
                    ).await;

                    match send_res {
                        Ok(()) => {
                            count_tracker.store(0, Ordering::SeqCst);
                            let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                            for path in paths_clone {
                                let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
                                let meta_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                                let mb = meta_size as f64 / (1024.0 * 1024.0);
                                hist.add_entry(HistoryKind::File, fname, format!("{:.1} MB • Sent", mb), true).await;
                            }

                            let _ = ui_handle.upgrade_in_event_loop(|ui| {
                                ui.set_transfer_status("All Sent ✓".into());
                            });
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                            let _ = ui_handle.upgrade_in_event_loop(|ui| {
                                ui.set_transfer_active(false);
                            });
                        }
                        Err(e) => {
                            count_tracker.store(0, Ordering::SeqCst);
                            eprintln!("[Mobile Send Error] {:?}", e);
                            let err_msg = format!("Failed: {}", e);
                            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                                ui.set_transfer_status(err_msg.into());
                            });
                            tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
                            let _ = ui_handle.upgrade_in_event_loop(|ui| {
                                ui.set_transfer_active(false);
                            });
                        }
                    }
                }
            }
        });
    });

    let ui_cancel_mobile = app_weak.clone();
    let cancel_trigger = cancel_token.clone();
    let counter_cancel = active_transfers_count.clone();
    app.on_cancel_transfer_clicked(move || {
        cancel_trigger.store(true, Ordering::SeqCst);
        counter_cancel.store(0, Ordering::SeqCst);
        let _ = ui_cancel_mobile.upgrade_in_event_loop(|ui| {
            ui.set_transfer_status("Cancelling... ✕".into());
        });
        let ui_delayed = ui_cancel_mobile.clone();
        let cancel_reset = cancel_trigger.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
            cancel_reset.store(false, Ordering::SeqCst);
            let _ = ui_delayed.upgrade_in_event_loop(|ui| {
                ui.set_transfer_active(false);
                ui.set_transfer_status("Cancelled ✕".into());
            });
        });
    });

    // معالجة فتح وإغلاق ومسح سجل النشاطات في الهاتف
    let ui_hist_toggle = app_weak.clone();
    let hist_toggle_ref = history.clone();
    app.on_toggle_history(move || {
        let hist_c = hist_toggle_ref.clone();
        let _ = ui_hist_toggle.upgrade_in_event_loop(move |ui| {
            let next_val = !ui.get_show_history();
            ui.set_show_history(next_val);
            if next_val {
                let ui_inner = ui.as_weak();
                tokio::spawn(async move {
                    let items = hist_c.get_all().await;
                    let _ = ui_inner.upgrade_in_event_loop(move |u| {
                        let model = history_entries_to_slint_model(&items);
                        u.set_history_items(model);
                    });
                });
            }
        });
    });

    let ui_hist_clear = app_weak.clone();
    let hist_clear_ref = history.clone();
    app.on_clear_history(move || {
        let hist_c = hist_clear_ref.clone();
        let ui_inner = ui_hist_clear.clone();
        tokio::spawn(async move {
            hist_c.clear().await;
            let _ = ui_inner.upgrade_in_event_loop(move |u| {
                let empty_model = history_entries_to_slint_model(&[]);
                u.set_history_items(empty_model);
            });
        });
    });

    let _ = download_dir;
    app.run()?;
    Ok(())
}
