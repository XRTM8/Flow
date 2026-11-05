use crate::clipboard;
use crate::protocol::{
    clean_text, compute_sas_code, format_transfer_status, get_or_create_device_id,
    updater, DeviceType, DiscoveryManager, HistoryEntry, HistoryKind, HistoryManager,
    Peer, TransferEvent, TransferManager, TrustManager,
};
use crate::{FilePickerItem, HistoryItem, MobileApp};
use slint::{ComponentHandle, ModelRc, VecModel};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

pub fn format_clipboard_preview(text: &str) -> String {
    let char_count = text.chars().count();
    if char_count > 250 {
        let preview: String = text.chars().take(230).collect();
        format!("{}... ({} chars)", preview.trim_end(), char_count)
    } else {
        text.to_string()
    }
}

pub fn history_entries_to_slint_model(entries: &[HistoryEntry]) -> ModelRc<HistoryItem> {
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

fn scan_dir_recursive(
    dir: &std::path::Path,
    depth: usize,
    max_depth: usize,
    files: &mut Vec<(std::time::SystemTime, String, String, String)>,
) {
    if depth > max_depth {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            if name.starts_with('.') || name == "Android" {
                continue;
            }
            if path.is_dir() {
                scan_dir_recursive(&path, depth + 1, max_depth, files);
            } else if path.is_file() {
                let meta = entry.metadata().ok();
                let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let mtime = meta.as_ref().and_then(|m| m.modified().ok()).unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                let size_str = if len < 1024 * 1024 {
                    format!("{:.1} KB", len as f64 / 1024.0)
                } else {
                    format!("{:.1} MB", len as f64 / (1024.0 * 1024.0))
                };
                files.push((mtime, path.to_string_lossy().to_string(), name, size_str));
            }
        }
    }
}

pub fn scan_storage_files() -> Vec<(String, String, String)> {
    let mut files = Vec::new();
    let dirs = [
        PathBuf::from("/storage/emulated/0/Download"),
        PathBuf::from("/storage/emulated/0/Download/OtiumFlow"),
        PathBuf::from("/storage/emulated/0/Documents"),
        PathBuf::from("/storage/emulated/0/DCIM"),
        PathBuf::from("/storage/emulated/0/Pictures"),
        PathBuf::from("/storage/emulated/0/Movies"),
        PathBuf::from("/storage/emulated/0/Music"),
        PathBuf::from("/storage/emulated/0"),
        PathBuf::from("/sdcard/Download"),
        PathBuf::from("/sdcard/Documents"),
        PathBuf::from("/sdcard/DCIM"),
        PathBuf::from("/sdcard/Pictures"),
    ];

    for dir in &dirs {
        scan_dir_recursive(dir, 0, 2, &mut files);
    }

    // ترتيب تنازلي حسب الأحدث تعديلاً
    files.sort_by(|a, b| b.0.cmp(&a.0));
    // إزالة التكرارات
    files.dedup_by(|a, b| a.1 == b.1);
    files.truncate(80);

    files
        .into_iter()
        .map(|(_, path, name, size_str)| (path, name, size_str))
        .collect()
}

#[cfg(target_os = "android")]
pub fn open_android_url(url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ctx = ndk_context::android_context();
    if !ctx.vm().is_null() && !ctx.context().is_null() {
        if let Ok(vm) = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) } {
            if let Ok(mut env) = vm.attach_current_thread() {
                let activity = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
                if let Ok(url_jstring) = env.new_string(url) {
                    if let Ok(uri_class) = env.find_class("android/net/Uri") {
                        if let Ok(uri) = env.call_static_method(
                            uri_class,
                            "parse",
                            "(Ljava/lang/String;)Landroid/net/Uri;",
                            &[jni::objects::JValue::Object(&url_jstring)],
                        ).and_then(|v| v.l()) {
                            if let Ok(intent_action) = env.new_string("android.intent.action.VIEW") {
                                if let Ok(intent_class) = env.find_class("android/content/Intent") {
                                    if let Ok(intent) = env.new_object(
                                        intent_class,
                                        "(Ljava/lang/String;Landroid/net/Uri;)V",
                                        &[
                                            jni::objects::JValue::Object(&intent_action),
                                            jni::objects::JValue::Object(&uri),
                                        ],
                                    ) {
                                        let _ = env.call_method(
                                            activity,
                                            "startActivity",
                                            "(Landroid/content/Intent;)V",
                                            &[jni::objects::JValue::Object(&intent)],
                                        );
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let _ = std::process::Command::new("/system/bin/am")
        .args(["start", "-a", "android.intent.action.VIEW", "-d", url])
        .spawn();

    Ok(())
}

#[cfg(target_os = "android")]
pub fn open_android_file_picker_intent() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ctx = ndk_context::android_context();
    if !ctx.vm().is_null() && !ctx.context().is_null() {
        if let Ok(vm) = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) } {
            if let Ok(mut env) = vm.attach_current_thread() {
                let activity = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
                if let Ok(action_str) = env.new_string("android.intent.action.GET_CONTENT") {
                    if let Ok(intent_class) = env.find_class("android/content/Intent") {
                        if let Ok(intent) = env.new_object(
                            intent_class,
                            "(Ljava/lang/String;)V",
                            &[jni::objects::JValue::Object(&action_str)],
                        ) {
                            if let Ok(type_str) = env.new_string("*/*") {
                                let _ = env.call_method(
                                    &intent,
                                    "setType",
                                    "(Ljava/lang/String;)Landroid/content/Intent;",
                                    &[jni::objects::JValue::Object(&type_str)],
                                );
                                let _ = env.call_method(
                                    activity,
                                    "startActivity",
                                    "(Landroid/content/Intent;)V",
                                    &[jni::objects::JValue::Object(&intent)],
                                );
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = std::process::Command::new("/system/bin/am")
        .args(["start", "-a", "android.intent.action.GET_CONTENT", "-t", "*/*"])
        .spawn();
    Ok(())
}

#[cfg(target_os = "android")]
pub fn open_android_storage_settings() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ctx = ndk_context::android_context();
    if !ctx.vm().is_null() && !ctx.context().is_null() {
        if let Ok(vm) = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) } {
            if let Ok(mut env) = vm.attach_current_thread() {
                let activity = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
                if let Ok(action_str) = env.new_string("android.settings.APPLICATION_DETAILS_SETTINGS") {
                    if let Ok(uri_str) = env.new_string("package:org.otium.flow") {
                        if let Ok(uri_class) = env.find_class("android/net/Uri") {
                            if let Ok(uri) = env.call_static_method(
                                uri_class,
                                "parse",
                                "(Ljava/lang/String;)Landroid/net/Uri;",
                                &[jni::objects::JValue::Object(&uri_str)],
                            ).and_then(|v| v.l()) {
                                if let Ok(intent_class) = env.find_class("android/content/Intent") {
                                    if let Ok(intent) = env.new_object(
                                        intent_class,
                                        "(Ljava/lang/String;Landroid/net/Uri;)V",
                                        &[
                                            jni::objects::JValue::Object(&action_str),
                                            jni::objects::JValue::Object(&uri),
                                        ],
                                    ) {
                                        let _ = env.call_method(
                                            activity,
                                            "startActivity",
                                            "(Landroid/content/Intent;)V",
                                            &[jni::objects::JValue::Object(&intent)],
                                        );
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = std::process::Command::new("/system/bin/am")
        .args(["start", "-a", "android.settings.APPLICATION_DETAILS_SETTINGS", "-d", "package:org.otium.flow"])
        .spawn();
    Ok(())
}

#[cfg(not(target_os = "android"))]
pub fn open_android_file_picker_intent() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Ok(())
}

#[cfg(not(target_os = "android"))]
pub fn open_android_storage_settings() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Ok(())
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

fn get_mobile_download_dir() -> PathBuf {
    #[cfg(target_os = "android")]
    {
        let pub_dir = PathBuf::from("/storage/emulated/0/Download/OtiumFlow");
        let _ = std::fs::create_dir_all(&pub_dir);
        let sample = pub_dir.join("Flow_Transfer_Ready.txt");
        if !sample.exists() {
            let _ = std::fs::write(&sample, "FLOW by Otium - Pure Native Rust P2P Sync. Ready to stream.");
        }
        if let Some(parent) = pub_dir.parent() {
            if parent.exists() {
                return pub_dir;
            }
        }
        let sd_dir = PathBuf::from("/sdcard/Download/OtiumFlow");
        let _ = std::fs::create_dir_all(&sd_dir);
        return sd_dir;
    }
    #[cfg(not(target_os = "android"))]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let p = PathBuf::from(profile).join("Downloads").join("OtiumFlow");
            let _ = std::fs::create_dir_all(&p);
            let sample = p.join("Flow_Transfer_Ready.txt");
            if !sample.exists() {
                let _ = std::fs::write(&sample, "FLOW by Otium - Ready to stream.");
            }
            return p;
        }
        let p = PathBuf::from("downloads");
        let _ = std::fs::create_dir_all(&p);
        p
    }
}

pub fn start_mobile_engine() -> Result<(), Box<dyn std::error::Error>> {
    let download_dir = get_mobile_download_dir();
    let persistent_device_id = get_or_create_device_id(&download_dir);

    let device_name = std::env::var("DEVICE_NAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "Mobile Phone".to_string());

    let (tcp_port, tcp_listener) = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(find_available_tcp_port(54125))
    });

    let discovery = Arc::new(DiscoveryManager::with_id(
        persistent_device_id.clone(),
        device_name,
        DeviceType::Mobile,
        tcp_port,
    ));

    let disc_clone = discovery.clone();
    tokio::spawn(async move {
        if let Err(e) = disc_clone.start().await {
            eprintln!("[Mobile Discovery] Failed to start: {:?}", e);
        }
    });

    let trust_manager = Arc::new(TrustManager::with_self_id(download_dir.clone(), persistent_device_id.clone()));
    let cancel_token = Arc::new(AtomicBool::new(false));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<TransferEvent>();
    let transfer = Arc::new(
        TransferManager::with_trust(tcp_port, download_dir.clone(), trust_manager.clone())
            .with_cancellation(cancel_token.clone()),
    );
    let trans_clone = transfer.clone();
    tokio::spawn(async move {
        trans_clone.start_with_listener(tcp_listener, event_tx).await;
    });

    let active_peer: Arc<RwLock<Option<Peer>>> = Arc::new(RwLock::new(None));
    let history = Arc::new(HistoryManager::with_storage(download_dir.clone()));

    // تهيئة واجهة Slint للهاتف
    let app = MobileApp::new()?;
    let app_weak = app.as_weak();

    let last_received_text = Arc::new(RwLock::new(String::new()));
    let full_clipboard_text = Arc::new(RwLock::new(String::new()));
    let remote_echo_guard = Arc::new(RwLock::new(String::new()));
    let active_transfers_count = Arc::new(AtomicUsize::new(0));

    let clipboard_mgr = Arc::new(clipboard::ClipboardManager::new());
    let (clip_tx, mut clip_rx) = mpsc::unbounded_channel::<String>();
    clipboard_mgr.start_monitoring(clip_tx);

    // التحقق الصامت من التحديثات
    let update_info: Arc<RwLock<Option<updater::AvailableUpdate>>> = Arc::new(RwLock::new(None));
    let ui_up = app_weak.clone();
    let update_store = update_info.clone();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        if let Ok(Some(upd)) = updater::check_latest_release().await {
            *update_store.write().await = Some(upd.clone());
            let _ = ui_up.upgrade_in_event_loop(move |ui| {
                ui.set_update_available(true);
                ui.set_update_version(upd.version.into());
            });
        }
    });

    let ui_apply = app_weak.clone();
    let update_apply_store = update_info.clone();
    app.on_apply_update_clicked(move || {
        let _ui_c = ui_apply.clone();
        let store = update_apply_store.clone();
        tokio::spawn(async move {
            let upd_opt = store.read().await.clone();
            let _target_url = if let Some(upd) = &upd_opt {
                upd.download_url.clone()
            } else {
                "https://github.com/XRTM8/Flow/releases/latest".to_string()
            };

            #[cfg(target_os = "android")]
            {
                let _ = open_android_url(&_target_url);
            }

            #[cfg(not(target_os = "android"))]
            {
                if let Some(upd) = upd_opt {
                    let _ = _ui_c.upgrade_in_event_loop(|ui| {
                        ui.set_update_in_progress(true);
                    });
                    let _ = updater::apply_update_in_place(&upd).await;
                    let _ = _ui_c.upgrade_in_event_loop(|ui| {
                        ui.set_update_in_progress(false);
                    });
                }
            }
        });
    });

    let ui_clip = app_weak.clone();
    let echo_guard = last_received_text.clone();
    let remote_echo_check = remote_echo_guard.clone();
    let full_clip_watch = full_clipboard_text.clone();
    tokio::spawn(async move {
        while let Some(text) = clip_rx.recv().await {
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

    // مهمة دورية لمراقبة واكتشاف الأجهزة المتصلة
    let d_clone = discovery.clone();
    let p_clone = active_peer.clone();
    let ui_handle = app_weak.clone();
    let my_id_mobile = persistent_device_id.clone();
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
                let sas = compute_sas_code(&my_id_mobile, &peer.id);
                let name = if peers.iter().filter(|p| p.name == peer.name).count() > 1 {
                    let suffix = if peer.id.len() >= 4 { &peer.id[..4] } else { &peer.id };
                    format!("{} (#{})", peer.name, suffix)
                } else {
                    peer.name.clone()
                };
                let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                    ui.set_is_connected(true);
                    ui.set_peer_name(name.into());
                    ui.set_sas_code(sas.into());
                });
            } else {
                *active = None;
                let _ = ui_handle.upgrade_in_event_loop(|ui| {
                    ui.set_is_connected(false);
                    ui.set_peer_name("Scanning Wi-Fi...".into());
                    ui.set_sas_code("".into());
                });
            }
        }
    });

    // استقبال أحداث النقل الواردة
    let ui_handle2 = app_weak.clone();
    let echo_receive = last_received_text.clone();
    let remote_echo_set = remote_echo_guard.clone();
    let full_clip_recv = full_clipboard_text.clone();
    let hist_receive = history.clone();
    let active_count_recv = active_transfers_count.clone();
    let disc_events = discovery.clone();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                TransferEvent::PeerDiscovered(peer) => {
                    disc_events.peers.write().await.insert(peer.id.clone(), peer);
                }
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
                    let _ = clipboard::ClipboardManager::set_image(width, height, &data);

                    let hist = hist_receive.clone();
                    tokio::spawn(async move {
                        hist.add_entry(
                            HistoryKind::Clipboard,
                            format!("Image ({}x{} px)", width, height),
                            "Received Screenshot".to_string(),
                            true,
                        )
                        .await;
                    });

                    let _ = ui_handle2.upgrade_in_event_loop(move |ui| {
                        ui.set_last_received_text(format!("Screenshot Synced ({}x{} px)", width, height).into());
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
                    let status = format_transfer_status(current_bytes, total_bytes, speed_mb_s, eta_secs);

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

                    let _ = active_count_recv.fetch_sub(1, Ordering::SeqCst);
                    let ui_done = ui_handle2.clone();
                    let count_check = active_count_recv.clone();
                    tokio::spawn(async move {
                        let _ = ui_done.upgrade_in_event_loop(|ui| {
                            ui.set_transfer_status("Saved to Downloads".into());
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

    // نسخ الحافظة المستلمة إلى ذاكرة الهاتف
    let full_clip_copy = full_clipboard_text.clone();
    let ui_copy_mobile = app_weak.clone();
    app.on_copy_received_clicked(move || {
        let text_arc = full_clip_copy.clone();
        let ui_c = ui_copy_mobile.clone();
        tokio::spawn(async move {
            let text = text_arc.read().await.clone();
            if !text.is_empty() && clipboard::ClipboardManager::set_text(&text).is_ok() {
                let _ = ui_c.upgrade_in_event_loop(|ui| {
                    ui.set_clipboard_copied(true);
                });
                tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                let _ = ui_c.upgrade_in_event_loop(|ui| {
                    ui.set_clipboard_copied(false);
                });
            }
        });
    });

    // إرسال حافظة الهاتف إلى الحاسوب
    let p_send = active_peer.clone();
    let full_clip_push = full_clipboard_text.clone();
    let hist_push = history.clone();
    let trust_clip = trust_manager.clone();
    let dev_id_clip = persistent_device_id.clone();
    let ui_push_mobile = app_weak.clone();
    app.on_push_clipboard_clicked(move || {
        let p_arc = p_send.clone();
        let clip_arc = full_clip_push.clone();
        let hist = hist_push.clone();
        let trust = trust_clip.clone();
        let dev_id = dev_id_clip.clone();
        let ui_btn = ui_push_mobile.clone();
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
                    let pairwise_key = trust.get_key_for_peer(&peer.id).await;
                    let res = TransferManager::send_encrypted_clipboard_with_auth(
                        target,
                        cleaned.clone(),
                        Some(dev_id),
                        Some(pairwise_key),
                    ).await;
                    if res.is_ok() {
                        let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                        hist.add_entry(HistoryKind::Clipboard, format_clipboard_preview(&cleaned), "Pushed (E2EE)".to_string(), true).await;
                        let _ = ui_btn.upgrade_in_event_loop(|ui| {
                            ui.set_clipboard_pushed(true);
                        });
                        let ui_revert = ui_btn.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                            let _ = ui_revert.upgrade_in_event_loop(|ui| {
                                ui.set_clipboard_pushed(false);
                            });
                        });
                    }
                } else if let Some((w, h, data)) = clipboard::ClipboardManager::read_current_image_bytes() {
                    let target = SocketAddr::new(peer.ip, peer.tcp_port);
                    let res = TransferManager::send_clipboard_image(target, w, h, data, Some(dev_id)).await;
                    if res.is_ok() {
                        let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                        hist.add_entry(HistoryKind::Clipboard, format!("Image ({}x{} px)", w, h), "Pushed Screenshot".to_string(), true).await;
                        let _ = ui_btn.upgrade_in_event_loop(|ui| {
                            ui.set_clipboard_pushed(true);
                        });
                        let ui_revert = ui_btn.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                            let _ = ui_revert.upgrade_in_event_loop(|ui| {
                                ui.set_clipboard_pushed(false);
                            });
                        });
                    }
                }
            }
        });
    });

    // عند النقر على زر إرسال ملف / صورة في الهاتف: مسح المجلدات وفتح نافذة الاختيار
    let ui_share_btn = app_weak.clone();
    app.on_share_file_clicked(move || {
        let ui_handle = ui_share_btn.clone();
        tokio::spawn(async move {
            let files = scan_storage_files();
            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                let slint_items: Vec<FilePickerItem> = files
                    .into_iter()
                    .map(|(path, name, size_str)| FilePickerItem {
                        path: path.into(),
                        name: name.into(),
                        size_str: size_str.into(),
                    })
                    .collect();
                let model: ModelRc<FilePickerItem> = Rc::new(VecModel::from(slint_items)).into();
                ui.set_picker_files(model);
                ui.set_show_file_picker(true);
            });
        });
    });

    // إغلاق نافذة اختيار الملفات
    let ui_close_picker = app_weak.clone();
    app.on_close_file_picker(move || {
        let _ = ui_close_picker.upgrade_in_event_loop(|ui| {
            ui.set_show_file_picker(false);
        });
    });

    // إنشاء ملف تجريبي وإرساله فوراً للحاسوب
    let ui_test_file = app_weak.clone();
    let p_test = active_peer.clone();
    let trust_test = trust_manager.clone();
    let dev_id_test = persistent_device_id.clone();
    let hist_test = history.clone();
    app.on_create_test_file(move || {
        let ui_handle = ui_test_file.clone();
        let p_arc = p_test.clone();
        let trust = trust_test.clone();
        let dev_id = dev_id_test.clone();
        let hist = hist_test.clone();

        tokio::spawn(async move {
            let download_dir = get_mobile_download_dir();
            let test_file = download_dir.join("OtiumFlow_Instant_Test.txt");
            let _ = std::fs::write(&test_file, format!("FLOW by Otium high-speed P2P Wi-Fi transfer test at {:?}", std::time::SystemTime::now()));

            let _ = ui_handle.upgrade_in_event_loop(|ui| {
                ui.set_show_file_picker(false);
            });

            let peer = { p_arc.read().await.clone() };
            if let Some(peer) = peer {
                let target = SocketAddr::new(peer.ip, peer.tcp_port);
                let _ = ui_handle.upgrade_in_event_loop(|ui| {
                    ui.set_transfer_active(true);
                    ui.set_transfer_progress(0.0);
                    ui.set_transfer_status("Sending test file...".into());
                });

                let paths = vec![test_file.clone()];
                let ui_prog = ui_handle.clone();
                let send_res = TransferManager::send_multiple_files_cancellable(
                    target,
                    &paths,
                    Some(dev_id),
                    None,
                    move |idx, total_count, sent, total, speed, _eta| {
                        let prog = sent as f32 / total.max(1) as f32;
                        let status = format!("[{}/{}] Sent • {:.1} MB/s", idx, total_count, speed);
                        let _ = ui_prog.upgrade_in_event_loop(move |ui| {
                            ui.set_transfer_progress(prog);
                            ui.set_transfer_status(status.into());
                        });
                    },
                ).await;

                if send_res.is_ok() {
                    let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                    hist.add_entry(HistoryKind::File, "OtiumFlow_Instant_Test.txt".into(), "Sent Test File".into(), true).await;
                    let _ = ui_handle.upgrade_in_event_loop(|ui| {
                        ui.set_transfer_status("Test File Sent Successfully!".into());
                    });
                    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                    let _ = ui_handle.upgrade_in_event_loop(|ui| {
                        ui.set_transfer_active(false);
                    });
                }
            }
        });
    });

    // إرسال الملف المختار إلى الحاسوب
    let p_file = active_peer.clone();
    let ui_selected = app_weak.clone();
    let hist_file_send = history.clone();
    let trust_file = trust_manager.clone();
    let cancel_file_send = cancel_token.clone();
    let dev_id_file = persistent_device_id.clone();
    let active_send_cnt = active_transfers_count.clone();
    app.on_file_selected(move |file_path_slint| {
        let path_str = file_path_slint.to_string();
        let path = PathBuf::from(&path_str);
        let p_arc = p_file.clone();
        let ui_handle = ui_selected.clone();
        let hist = hist_file_send.clone();
        let trust = trust_file.clone();
        let cancel_tok = cancel_file_send.clone();
        let dev_id = dev_id_file.clone();
        let count_tracker = active_send_cnt.clone();

        tokio::spawn(async move {
            let _ = ui_handle.upgrade_in_event_loop(|ui| {
                ui.set_show_file_picker(false);
            });

            if !path.exists() {
                eprintln!("[Mobile File Send] Path does not exist: {:?}", path);
                return;
            }

            cancel_tok.store(false, Ordering::SeqCst);
            count_tracker.store(1, Ordering::SeqCst);

            let peer = { p_arc.read().await.clone() };
            if let Some(peer) = peer {
                let target = SocketAddr::new(peer.ip, peer.tcp_port);
                let _ = ui_handle.upgrade_in_event_loop(|ui| {
                    ui.set_transfer_active(true);
                    ui.set_transfer_progress(0.0);
                    ui.set_transfer_status("Preparing...".into());
                });

                let ui_prog = ui_handle.clone();
                let path_clone = path.clone();
                let paths = vec![path];
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
                        let fname = path_clone.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
                        let meta_size = std::fs::metadata(&path_clone).map(|m| m.len()).unwrap_or(0);
                        let mb = meta_size as f64 / (1024.0 * 1024.0);
                        hist.add_entry(HistoryKind::File, fname, format!("{:.1} MB • Sent", mb), true).await;

                        let _ = ui_handle.upgrade_in_event_loop(|ui| {
                            ui.set_transfer_status("Sent Successfully ✓".into());
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
        });
    });

    // إلغاء النقل الجاري
    let ui_cancel_mobile = app_weak.clone();
    let cancel_trigger = cancel_token.clone();
    let counter_cancel = active_transfers_count.clone();
    app.on_cancel_transfer_clicked(move || {
        cancel_trigger.store(true, Ordering::SeqCst);
        counter_cancel.store(0, Ordering::SeqCst);
        let _ = ui_cancel_mobile.upgrade_in_event_loop(|ui| {
            ui.set_transfer_status("Cancelling...".into());
        });
        let ui_delayed = ui_cancel_mobile.clone();
        let cancel_reset = cancel_trigger.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
            cancel_reset.store(false, Ordering::SeqCst);
            let _ = ui_delayed.upgrade_in_event_loop(|ui| {
                ui.set_transfer_active(false);
                ui.set_transfer_status("Cancelled".into());
            });
        });
    });

    // فتح وإغلاق السجل
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

    // مسح السجل
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

    // 4. محرر الملاحظات والنصوص المباشر للهاتف: كتابة وإرسال أي رسالة أو ملاحظة فوراً للحاسوب
    let p_custom = active_peer.clone();
    let hist_custom = history.clone();
    let trust_custom = trust_manager.clone();
    let dev_id_custom = persistent_device_id.clone();
    let ui_send_custom = app_weak.clone();
    app.on_send_custom_text(move |text_slint| {
        let text = text_slint.to_string();
        if text.trim().is_empty() {
            return;
        }
        let p_arc = p_custom.clone();
        let hist = hist_custom.clone();
        let trust = trust_custom.clone();
        let dev_id = dev_id_custom.clone();
        let ui_btn = ui_send_custom.clone();

        tokio::spawn(async move {
            let peer = { p_arc.read().await.clone() };
            if let Some(peer) = peer {
                let (cleaned, _) = clean_text(&text);
                let target = SocketAddr::new(peer.ip, peer.tcp_port);
                let pairwise_key = trust.get_key_for_peer(&peer.id).await;
                let res = TransferManager::send_encrypted_clipboard_with_auth(
                    target,
                    cleaned.clone(),
                    Some(dev_id),
                    Some(pairwise_key),
                ).await;

                if res.is_ok() {
                    let _ = trust.trust_peer(peer.id.clone(), peer.name.clone()).await;
                    hist.add_entry(
                        HistoryKind::Clipboard,
                        format_clipboard_preview(&cleaned),
                        "Beamed Note (E2EE)".to_string(),
                        true,
                    ).await;

                    let all_hist = hist.get_all().await;
                    let _ = ui_btn.upgrade_in_event_loop(move |ui| {
                        let hist_model = history_entries_to_slint_model(&all_hist);
                        ui.set_text_sent(true);
                        ui.set_history_items(hist_model);
                    });

                    let ui_revert = ui_btn.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                        let _ = ui_revert.upgrade_in_event_loop(|ui| {
                            ui.set_text_sent(false);
                        });
                    });
                }
            }
        });
    });

    let ui_paste_draft = app_weak.clone();
    app.on_paste_to_draft(move || {
        let ui_c = ui_paste_draft.clone();
        tokio::spawn(async move {
            if let Some(text) = clipboard::ClipboardManager::read_current() {
                if !text.is_empty() {
                    let _ = ui_c.upgrade_in_event_loop(move |ui| {
                        ui.set_draft_text(text.into());
                    });
                }
            }
        });
    });

    let ui_clear_draft = app_weak.clone();
    app.on_clear_draft(move || {
        let _ = ui_clear_draft.upgrade_in_event_loop(|ui| {
            ui.set_draft_text("".into());
        });
    });

    app.on_open_system_picker_clicked(move || {
        let _ = open_android_file_picker_intent();
    });

    app.on_open_storage_settings_clicked(move || {
        let _ = open_android_storage_settings();
    });

    app.run()?;
    Ok(())
}
