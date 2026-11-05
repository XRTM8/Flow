use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use super::trust::TrustManager;

pub const DEFAULT_TCP_PORT: u16 = 54125;
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB streaming buffer
const MAX_HEADER_SIZE: usize = 32 * 1024 * 1024; // 32 MB حماية ضد هجمات DoS مع السماح بصور الحافظة عالية الدقة
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024 * 1024; // 50 GB سقف أمان أقصى لحجم الملف المنقول لمنع استنزاف القرص
const NETWORK_TIMEOUT: Duration = Duration::from_secs(15); // مهلة أمان قصوى لمنع هجمات Slowloris والتعليق الشبكي

const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    "CLOCK$", "CONIN$", "CONOUT$",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketHeader {
    PingAnnounce {
        id: String,
        name: String,
        device_type: super::discovery::DeviceType,
        tcp_port: u16,
    },
    ClipboardText {
        content: String,
        #[serde(default)]
        sender_id: Option<String>,
    },
    ClipboardImage {
        width: usize,
        height: usize,
        data: Vec<u8>,
        #[serde(default)]
        sender_id: Option<String>,
    },
    FileOffer {
        name: String,
        size: u64,
        sha256: Option<String>,
        #[serde(default)]
        sender_id: Option<String>,
        #[serde(default)]
        file_id: Option<String>,
        #[serde(default)]
        offset: u64,
    },
    ResumeQuery {
        file_id: String,
        name: String,
        total_size: u64,
        #[serde(default)]
        sender_id: Option<String>,
    },
    ResumeResponse {
        file_id: String,
        offset: u64,
        accepted: bool,
    },
    EncryptedPayload {
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
        #[serde(default)]
        sender_id: Option<String>,
        #[serde(default)]
        timestamp_secs: u64,
    },
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum TransferEvent {
    PeerDiscovered(super::discovery::Peer),
    ClipboardReceived(String),
    ClipboardImageReceived {
        width: usize,
        height: usize,
        data: Vec<u8>,
    },
    FileStart { name: String, total_bytes: u64 },
    FileProgress {
        name: String,
        current_bytes: u64,
        total_bytes: u64,
        speed_mb_s: f64,
        eta_secs: u64,
    },
    FileComplete { name: String, path: PathBuf },
    Error(String),
}

/// تنسيق الحجم بطريقة أنيقة تتكيف تلقائياً مع حجم الملف (Bytes, KB, MB, GB)
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// تنسيق حالة النقل اللحظية مع عداد السرعة والوقت المتبقي بدقة
pub fn format_transfer_status(current_bytes: u64, total_bytes: u64, speed_mb_s: f64, eta_secs: u64) -> String {
    let cur_str = format_bytes(current_bytes);
    let tot_str = format_bytes(total_bytes);
    if total_bytes == 0 {
        return "Complete".to_string();
    }
    if eta_secs > 0 && speed_mb_s > 0.05 {
        if eta_secs >= 60 {
            let mins = eta_secs / 60;
            let secs = eta_secs % 60;
            format!("{}/{}  {:.1} MB/s ({}m{}s)", cur_str, tot_str, speed_mb_s, mins, secs)
        } else {
            format!("{}/{}  {:.1} MB/s ({}s)", cur_str, tot_str, speed_mb_s, eta_secs)
        }
    } else if speed_mb_s > 0.05 {
        format!("{}/{}  {:.1} MB/s", cur_str, tot_str, speed_mb_s)
    } else {
        format!("{}/{}", cur_str, tot_str)
    }
}

/// استعلام مباشر من نظام التشغيل عن السعة التخزينية المتاحة قبل قبول أي ملف
#[cfg(target_os = "windows")]
pub fn get_available_disk_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let mut free_bytes_available: u64 = 0;
    let mut total_number_of_bytes: u64 = 0;
    let mut total_number_of_free_bytes: u64 = 0;
    let dir = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    let wide_path: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    extern "system" {
        fn GetDiskFreeSpaceExW(
            lpDirectoryName: *const u16,
            lpFreeBytesAvailableToCaller: *mut u64,
            lpTotalNumberOfBytes: *mut u64,
            lpTotalNumberOfFreeBytes: *mut u64,
        ) -> i32;
    }

    let res = unsafe {
        GetDiskFreeSpaceExW(
            wide_path.as_ptr(),
            &mut free_bytes_available,
            &mut total_number_of_bytes,
            &mut total_number_of_free_bytes,
        )
    };
    if res != 0 {
        Some(free_bytes_available)
    } else {
        None
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_available_disk_space(_path: &Path) -> Option<u64> {
    None
}

/// فحص صارم لصندوق الرمل لمنع هجمات الروابط الرمزية (Symlink Traversal Attacks)
pub fn verify_path_sandbox(base_dir: &Path, target_path: &Path) -> Result<PathBuf, String> {
    if let (Ok(can_base), Ok(can_parent)) = (base_dir.canonicalize(), target_path.parent().unwrap_or(base_dir).canonicalize()) {
        if !can_parent.starts_with(&can_base) {
            return Err("Security Alert: Path escapes download sandbox (Symlink/Junction traversal blocked)".into());
        }
    }
    Ok(target_path.to_path_buf())
}

pub struct TransferManager {
    pub port: u16,
    pub download_dir: PathBuf,
    pub connection_limiter: Arc<tokio::sync::Semaphore>,
    pub trust_manager: Option<Arc<TrustManager>>,
    pub cancel_token: Option<Arc<AtomicBool>>,
}

impl TransferManager {
    /// تنظيف وحذف الملفات المؤقتة اليتيمة (.flowpart) المتخلفة عن جلسات سابقة أو انهيارات غير متوقعة
    pub fn purge_orphaned_flowparts(download_dir: &Path) {
        if let Ok(entries) = std::fs::read_dir(download_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if ext == "flowpart" {
                            let _ = std::fs::remove_file(path);
                        }
                    }
                }
            }
        }
    }

    pub fn new(port: u16, download_dir: PathBuf) -> Self {
        Self::purge_orphaned_flowparts(&download_dir);
        Self {
            port,
            download_dir,
            connection_limiter: Arc::new(tokio::sync::Semaphore::new(16)),
            trust_manager: None,
            cancel_token: None,
        }
    }

    pub fn with_trust(port: u16, download_dir: PathBuf, trust: Arc<TrustManager>) -> Self {
        Self::purge_orphaned_flowparts(&download_dir);
        Self {
            port,
            download_dir,
            connection_limiter: Arc::new(tokio::sync::Semaphore::new(16)),
            trust_manager: Some(trust),
            cancel_token: None,
        }
    }

    pub fn with_cancellation(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel_token = Some(cancel);
        self
    }

    /// يبدأ سيرفر استقبال الملفات والحافظة المباشر
    pub async fn start_receiver(
        self: Arc<Self>,
        event_sender: mpsc::UnboundedSender<TransferEvent>,
    ) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        self.start_with_listener(listener, event_sender).await;
        Ok(())
    }

    /// يبدأ السيرفر باستخدام مستمع منفذ جاهز (مفيد للمنافذ الديناميكية ومنع تعارض الأجهزة وتحديد سقف الاتصالات)
    pub async fn start_with_listener(
        self: Arc<Self>,
        listener: TcpListener,
        event_sender: mpsc::UnboundedSender<TransferEvent>,
    ) {
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let _ = stream.set_nodelay(true);
                        let manager = self.clone();
                        let sender = event_sender.clone();
                        let permit = match manager.connection_limiter.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                eprintln!("[Transfer] Connection rejected: maximum concurrent transfers reached (DoS protection)");
                                continue;
                            }
                        };
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = manager.handle_incoming(stream, sender).await {
                                eprintln!("[Transfer] Connection error: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[Transfer] Accept error: {:?}", e);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        });
    }

    pub async fn handle_incoming(
        &self,
        mut stream: TcpStream,
        sender: mpsc::UnboundedSender<TransferEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let peer_addr = stream.peer_addr()?;
        // 1. قراءة طول الهيدر مع فحص أمني ضد هجمات DoS مع مهلة شبكية
        let header_len = tokio::time::timeout(NETWORK_TIMEOUT, stream.read_u32())
            .await
            .map_err(|_| "Network Timeout: Connection timed out waiting for packet header")?? as usize;

        if header_len > MAX_HEADER_SIZE {
            return Err("Security Alert: Header exceeds maximum allowed size (DoS protection)".into());
        }

        let mut header_buf = vec![0u8; header_len];
        tokio::time::timeout(NETWORK_TIMEOUT, stream.read_exact(&mut header_buf))
            .await
            .map_err(|_| "Network Timeout: Connection timed out reading packet header bytes")??;

        let header: PacketHeader = serde_json::from_slice(&header_buf)?;

        // 2. التحقق من الثقة والاقتران الأمني
        if let Some(ref tm) = self.trust_manager {
            if !tm.auto_accept().await {
                let is_trusted = match &header {
                    PacketHeader::FileOffer { sender_id, .. } => {
                        if let Some(sid) = sender_id {
                            tm.is_trusted(sid).await
                        } else {
                            false
                        }
                    }
                    PacketHeader::ResumeQuery { sender_id, .. } => {
                        if let Some(sid) = sender_id {
                            tm.is_trusted(sid).await
                        } else {
                            false
                        }
                    }
                    PacketHeader::EncryptedPayload { sender_id, .. } => {
                        if let Some(sid) = sender_id {
                            tm.is_trusted(sid).await
                        } else {
                            false
                        }
                    }
                    PacketHeader::ClipboardText { sender_id, .. } => {
                        if let Some(sid) = sender_id {
                            tm.is_trusted(sid).await
                        } else {
                            false
                        }
                    }
                    PacketHeader::ClipboardImage { sender_id, .. } => {
                        if let Some(sid) = sender_id {
                            tm.is_trusted(sid).await
                        } else {
                            false
                        }
                    }
                    PacketHeader::PingAnnounce { .. } => true,
                    PacketHeader::ResumeResponse { .. } => true,
                };

                if !is_trusted {
                    let _ = sender.send(TransferEvent::Error("Incoming transfer rejected: Untrusted peer".into()));
                    return Err("Security Alert: Connection rejected from untrusted peer".into());
                }
            }
        }

        match header {
            PacketHeader::PingAnnounce { id, name, device_type, tcp_port } => {
                let peer_ip = peer_addr.ip();
                let peer = super::discovery::Peer {
                    id,
                    name,
                    device_type,
                    ip: peer_ip,
                    tcp_port,
                    last_seen: Instant::now(),
                };
                let _ = sender.send(TransferEvent::PeerDiscovered(peer));
                return Ok(());
            }
            PacketHeader::ClipboardText { content, .. } => {
                let _ = sender.send(TransferEvent::ClipboardReceived(content));
            }
            PacketHeader::ClipboardImage { width, height, data, .. } => {
                let _ = sender.send(TransferEvent::ClipboardImageReceived {
                    width,
                    height,
                    data,
                });
            }
            PacketHeader::ResumeQuery { file_id, name, total_size, .. } => {
                let raw_filename = Path::new(&name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("received_file");
                let part_pattern = format!("{}.{}.flowpart", raw_filename, file_id);
                let part_path = self.download_dir.join(&part_pattern);

                let existing_offset = if part_path.exists() {
                    tokio::fs::metadata(&part_path).await.map(|m| m.len()).unwrap_or(0)
                } else {
                    0
                };

                let response = PacketHeader::ResumeResponse {
                    file_id,
                    offset: existing_offset,
                    accepted: existing_offset > 0 && existing_offset < total_size,
                };
                let resp_bytes = serde_json::to_vec(&response)?;
                tokio::time::timeout(NETWORK_TIMEOUT, stream.write_u32(resp_bytes.len() as u32)).await??;
                tokio::time::timeout(NETWORK_TIMEOUT, stream.write_all(&resp_bytes)).await??;
                tokio::time::timeout(NETWORK_TIMEOUT, stream.flush()).await??;
                return Ok(());
            }
            PacketHeader::ResumeResponse { .. } => {
                return Ok(());
            }
            PacketHeader::EncryptedPayload { nonce, ciphertext, timestamp_secs, sender_id } => {
                // حماية ضد هجمات إعادة الإرسال (Anti-Replay Attack Protection) بمهلة 120 ثانية
                if timestamp_secs > 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now.abs_diff(timestamp_secs) > 120 {
                        return Err("Security Alert: Expired or replayed encrypted payload (TTL > 120s)".into());
                    }
                }

                let nonce_ref = Nonce::from(nonce);
                let mut decrypted_opt = None;

                // 1. محاولة فك التشفير بمفتاح النظير الثنائي (Pairwise E2EE Key) إذا توفر sender_id
                if let Some(ref sid) = sender_id {
                    if let Some(ref tm) = self.trust_manager {
                        let pairwise_key = tm.get_key_for_peer(sid).await;
                        let cipher = ChaCha20Poly1305::new(&pairwise_key.into());
                        if let Ok(dec) = cipher.decrypt(&nonce_ref, ciphertext.as_ref()) {
                            decrypted_opt = Some(dec);
                        }
                    }
                }

                // 2. المحاولة البديلة عبر Master Key أو المفتاح المرجعي
                if decrypted_opt.is_none() {
                    let key = if let Some(ref tm) = self.trust_manager {
                        tm.get_master_key().await
                    } else {
                        [0x42u8; 32]
                    };
                    let cipher = ChaCha20Poly1305::new(&key.into());
                    if let Ok(dec) = cipher.decrypt(&nonce_ref, ciphertext.as_ref()) {
                        decrypted_opt = Some(dec);
                    }
                }

                if let Some(decrypted) = decrypted_opt {
                    if let Ok(text) = String::from_utf8(decrypted) {
                        let _ = sender.send(TransferEvent::ClipboardReceived(text));
                    }
                }
            }
            PacketHeader::FileOffer { name, size, sha256, file_id, offset, .. } => {
                // فحص الحجم الأقصى للملف لحماية القرص من الاستنزاف
                if size > MAX_FILE_SIZE {
                    return Err("Security Alert: Offered file exceeds maximum allowed transfer size of 50 GB (Disk exhaustion protection)".into());
                }

                // فحص السعة الشاغرة في القرص مسبقاً لمنع ملء وحدة التخزين (Pre-flight Disk Check)
                if let Some(free_space) = get_available_disk_space(&self.download_dir) {
                    let required = size.saturating_sub(offset);
                    if free_space < required {
                        let err = format!(
                            "Storage Alert: Insufficient disk space on target drive (required {:.1} MB, available {:.1} MB)",
                            required as f64 / (1024.0 * 1024.0),
                            free_space as f64 / (1024.0 * 1024.0)
                        );
                        let _ = sender.send(TransferEvent::Error(err.clone()));
                        return Err(err.into());
                    }
                }

                // حماية قصوى ضد ثغرة Path Traversal وحظر المحارف غير القانونية لأنظمة التشغيل
                let raw_filename = Path::new(&name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("received_file");

                let filtered: String = raw_filename
                    .chars()
                    .filter(|c| {
                        !c.is_control()
                            && *c != '/'
                            && *c != '\\'
                            && *c != ':'
                            && *c != '*'
                            && *c != '?'
                            && *c != '"'
                            && *c != '<'
                            && *c != '>'
                            && *c != '|'
                            && *c != '\0'
                    })
                    .collect();

                let trimmed = filtered.trim().trim_matches('.').to_string();

                // حماية ضد أسماء أجهزة نظام ويندوز المحجوزة (DOS Device Names مثل CON, PRN, AUX, NUL)
                let file_stem = Path::new(&trimmed)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");

                let is_reserved = WINDOWS_RESERVED_NAMES
                    .iter()
                    .any(|&res| res.eq_ignore_ascii_case(file_stem));

                let safe_name = if is_reserved {
                    format!("safe_{}", trimmed)
                } else if trimmed.is_empty() {
                    "received_file".to_string()
                } else if trimmed.len() > 100 {
                    let ext = Path::new(&trimmed)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");
                    if ext.is_empty() {
                        trimmed.chars().take(100).collect()
                    } else {
                        let stem: String = trimmed.chars().take(90).collect();
                        format!("{}.{}", stem, ext)
                    }
                } else {
                    trimmed
                };

                let _ = sender.send(TransferEvent::FileStart {
                    name: safe_name.clone(),
                    total_bytes: size,
                });

                std::fs::create_dir_all(&self.download_dir)?;

                // منع الكتابة فوق ملفات موجودة بتوليد اسم فريد
                let mut dest_path = self.download_dir.join(&safe_name);
                if dest_path.exists() && offset == 0 {
                    let stem = Path::new(&safe_name)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("file");
                    let ext = Path::new(&safe_name)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");

                    let mut counter = 1;
                    loop {
                        let new_name = if ext.is_empty() {
                            format!("{}_{}", stem, counter)
                        } else {
                            format!("{}_{}.{}", stem, counter, ext)
                        };
                        let candidate = self.download_dir.join(new_name);
                        if !candidate.exists() {
                            dest_path = candidate;
                            break;
                        }
                        counter += 1;
                    }
                }

                // تدقيق أمان صندوق الرمل للمسار الهدف
                let dest_path = verify_path_sandbox(&self.download_dir, &dest_path)?;

                let final_name = dest_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&safe_name)
                    .to_string();

                // الحفظ الذري واستئناف النقل الذكي (Resumable Part File Engine)
                let fid = file_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()[..8].to_string());
                let part_path = self.download_dir.join(format!("{}.{}.flowpart", final_name, fid));

                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .read(true)
                    .open(&part_path)
                    .await?;

                let mut hasher = Sha256::new();
                let mut received: u64 = 0;

                // إذا كان هناك استئناف من offset محدد
                if offset > 0 {
                    let meta_len = file.metadata().await?.len();
                    let actual_offset = std::cmp::min(offset, meta_len);
                    file.seek(std::io::SeekFrom::Start(actual_offset)).await?;
                    received = actual_offset;

                    // احتساب هاش البايتات المحملة مسبقاً
                    if sha256.is_some() {
                        let mut check_f = tokio::fs::File::open(&part_path).await?;
                        let mut check_buf = vec![0u8; CHUNK_SIZE];
                        let mut checked = 0u64;
                        while checked < actual_offset {
                            let to_read = std::cmp::min(check_buf.len() as u64, actual_offset - checked) as usize;
                            let n = check_f.read(&mut check_buf[..to_read]).await?;
                            if n == 0 {
                                break;
                            }
                            hasher.update(&check_buf[..n]);
                            checked += n as u64;
                        }
                    }
                }

                let mut buf = vec![0u8; CHUNK_SIZE];
                let transfer_start = Instant::now();

                let stream_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
                    while received < size {
                        // فحص إشارة الإلغاء اللحظية
                        if let Some(ref cancel) = self.cancel_token {
                            if cancel.load(Ordering::Relaxed) {
                                return Err("Transfer cancelled by user".into());
                            }
                        }

                        let to_read = std::cmp::min(buf.len() as u64, size - received) as usize;
                        let n = tokio::time::timeout(NETWORK_TIMEOUT, stream.read(&mut buf[..to_read]))
                            .await
                            .map_err(|_| "Network Timeout: File transfer stalled for more than 15 seconds")??;
                        if n == 0 {
                            return Err("Connection severed unexpectedly mid-transfer (EOF)".into());
                        }
                        file.write_all(&buf[..n]).await?;
                        hasher.update(&buf[..n]);
                        received += n as u64;

                        // حساب السرعة الحية والوقت المتبقي
                        let elapsed_secs = transfer_start.elapsed().as_secs_f64().max(0.001);
                        let transferred_now = received.saturating_sub(offset);
                        let speed_mb_s = (transferred_now as f64 / (1024.0 * 1024.0)) / elapsed_secs;
                        let remaining_bytes = size - received;
                        let speed_bytes_s = (transferred_now as f64) / elapsed_secs;
                        let eta_secs = if speed_bytes_s > 0.0 {
                            (remaining_bytes as f64 / speed_bytes_s) as u64
                        } else {
                            0
                        };

                        let _ = sender.send(TransferEvent::FileProgress {
                            name: final_name.clone(),
                            current_bytes: received,
                            total_bytes: size,
                            speed_mb_s,
                            eta_secs,
                        });
                    }
                    file.flush().await?;

                    // التحقق من البصمة التشفيرية SHA-256
                    if let Some(expected_sha) = sha256 {
                        let hash_bytes = hasher.finalize();
                        let actual_sha: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        if actual_sha != expected_sha {
                            return Err(format!(
                                "Cryptographic Integrity Error: Checksum mismatch (expected {}, got {})",
                                expected_sha, actual_sha
                            ).into());
                        }
                    }

                    Ok(())
                }.await;

                drop(file);

                match stream_result {
                    Ok(()) => {
                        // حماية إضافية ضد سباق التسمية في ويندوز (Windows TOCTOU Rename Collision Fix)
                        let mut final_target = dest_path.clone();
                        if final_target.exists() && offset == 0 {
                            let stem = Path::new(&safe_name)
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("file");
                            let ext = Path::new(&safe_name)
                                .extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or("");
                            let mut counter = 1;
                            loop {
                                let new_name = if ext.is_empty() {
                                    format!("{}_{}", stem, counter)
                                } else {
                                    format!("{}_{}.{}", stem, counter, ext)
                                };
                                let candidate = self.download_dir.join(new_name);
                                if !candidate.exists() {
                                    final_target = candidate;
                                    break;
                                }
                                counter += 1;
                            }
                        }

                        std::fs::rename(&part_path, &final_target)?;
                        let final_saved_name = final_target
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&safe_name)
                            .to_string();

                        let _ = sender.send(TransferEvent::FileComplete {
                            name: final_saved_name,
                            path: final_target,
                        });
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        // إذا تم الإلغاء من المستخدم أو لم يكن الملف معلماً كجلسة استئناف، ننظف الملف المؤقت
                        if err_str.contains("cancelled by user") || file_id.is_none() {
                            let _ = std::fs::remove_file(&part_path);
                        }
                        let _ = sender.send(TransferEvent::Error(format!("Transfer aborted: {:?}", e)));
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// إرسال نص الحافظة إلى جهاز آخر
    pub async fn send_clipboard(
        target: SocketAddr,
        text: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Self::send_clipboard_with_sender(target, text, None).await
    }

    pub async fn send_clipboard_with_sender(
        target: SocketAddr,
        text: String,
        sender_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = TcpStream::connect(target).await?;
        let _ = stream.set_nodelay(true);
        let header = PacketHeader::ClipboardText { content: text, sender_id };
        let header_bytes = serde_json::to_vec(&header)?;

        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_u32(header_bytes.len() as u32))
            .await
            .map_err(|_| "Network Timeout: Failed to write clipboard header length")??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_all(&header_bytes))
            .await
            .map_err(|_| "Network Timeout: Failed to write clipboard header bytes")??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.flush())
            .await
            .map_err(|_| "Network Timeout: Failed to flush clipboard stream")??;
        Ok(())
    }

    /// إرسال صورة الحافظة / لقطة شاشة مباشرة عبر الشبكة
    pub async fn send_clipboard_image(
        target: SocketAddr,
        width: usize,
        height: usize,
        data: Vec<u8>,
        sender_id: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = TcpStream::connect(target).await?;
        let _ = stream.set_nodelay(true);
        let header = PacketHeader::ClipboardImage {
            width,
            height,
            data,
            sender_id,
        };
        let header_bytes = serde_json::to_vec(&header)?;

        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_u32(header_bytes.len() as u32))
            .await
            .map_err(|_| "Network Timeout: Failed to write image header length")??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_all(&header_bytes))
            .await
            .map_err(|_| "Network Timeout: Failed to write image header bytes")??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.flush())
            .await
            .map_err(|_| "Network Timeout: Failed to flush image stream")??;
        Ok(())
    }

    /// إرسال إعلان اكتشاف مباشر عبر TCP لتجاوز حظر البث اللاسلكي في موجهات وبطاقات هواتف أندرويد
    pub async fn send_tcp_ping(
        target: SocketAddr,
        self_id: String,
        self_name: String,
        self_type: super::discovery::DeviceType,
        self_port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect(target)).await??;
        let _ = stream.set_nodelay(true);
        let header = PacketHeader::PingAnnounce {
            id: self_id,
            name: self_name,
            device_type: self_type,
            tcp_port: self_port,
        };
        let bytes = serde_json::to_vec(&header)?;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_u32(bytes.len() as u32)).await??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_all(&bytes)).await??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.flush()).await??;
        Ok(())
    }

    /// إرسال نص مشفر بـ ChaCha20-Poly1305 مع توليد Nonce عشوائي غير مكرر وحماية ضد هجمات Replay
    pub async fn send_encrypted_clipboard(
        target: SocketAddr,
        text: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Self::send_encrypted_clipboard_with_auth(target, text, None, None).await
    }

    pub async fn send_encrypted_clipboard_with_auth(
        target: SocketAddr,
        text: String,
        sender_id: Option<String>,
        key_opt: Option<[u8; 32]>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = key_opt.unwrap_or([0x42u8; 32]);
        let cipher = ChaCha20Poly1305::new(&key.into());

        let uuid_bytes = uuid::Uuid::new_v4();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&uuid_bytes.as_bytes()[0..12]);
        let nonce_ref = Nonce::from(nonce);

        let ciphertext = cipher
            .encrypt(&nonce_ref, text.as_bytes())
            .map_err(|e| format!("Encryption error: {:?}", e))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut stream = TcpStream::connect(target).await?;
        let _ = stream.set_nodelay(true);
        let header = PacketHeader::EncryptedPayload {
            nonce,
            ciphertext,
            sender_id,
            timestamp_secs: now,
        };
        let header_bytes = serde_json::to_vec(&header)?;

        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_u32(header_bytes.len() as u32))
            .await
            .map_err(|_| "Network Timeout: Failed to write encrypted header length")??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_all(&header_bytes))
            .await
            .map_err(|_| "Network Timeout: Failed to write encrypted header bytes")??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.flush())
            .await
            .map_err(|_| "Network Timeout: Failed to flush encrypted stream")??;
        Ok(())
    }

    /// إرسال ملف مباشرة مع احتساب البصمة التشفيرية المسبقة SHA-256 للملفات مع مهلة كتابة شبكية
    pub async fn send_file<F>(
        target: SocketAddr,
        file_path: &Path,
        progress_cb: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(u64, u64, f64, u64) + Send + 'static,
    {
        Self::send_file_cancellable(target, file_path, None, None, progress_cb).await
    }

    pub async fn send_file_cancellable<F>(
        target: SocketAddr,
        file_path: &Path,
        sender_id: Option<String>,
        cancel_token: Option<Arc<AtomicBool>>,
        progress_cb: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(u64, u64, f64, u64) + Send + 'static,
    {
        Self::send_file_resumable(target, file_path, sender_id, cancel_token, progress_cb).await
    }

    /// إرسال ملف مع دعم الاستئناف التلقائي الذكي من البايت المتبقي
    pub async fn send_file_resumable<F>(
        target: SocketAddr,
        file_path: &Path,
        sender_id: Option<String>,
        cancel_token: Option<Arc<AtomicBool>>,
        progress_cb: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(u64, u64, f64, u64) + Send + 'static,
    {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin")
            .to_string();
        let metadata = tokio::fs::metadata(file_path).await?;
        let total_size = metadata.len();

        let file_id = {
            let mut h = Sha256::new();
            h.update(filename.as_bytes());
            h.update(total_size.to_le_bytes());
            let hash = h.finalize();
            hash[..8].iter().map(|b| format!("{:02x}", b)).collect::<String>()
        };

        let mut offset = 0u64;

        // إذا كان الملف أكبر من 5 ميجابايت، نستعلم أولاً هل لدى المستقبل جزء محمل مسبقاً لاستئنافه
        if total_size > 5 * 1024 * 1024 {
            if let Ok(mut query_stream) = TcpStream::connect(target).await {
                let _ = query_stream.set_nodelay(true);
                let query = PacketHeader::ResumeQuery {
                    file_id: file_id.clone(),
                    name: filename.clone(),
                    total_size,
                    sender_id: sender_id.clone(),
                };
                if let Ok(query_bytes) = serde_json::to_vec(&query) {
                    let _ = query_stream.write_u32(query_bytes.len() as u32).await;
                    let _ = query_stream.write_all(&query_bytes).await;
                    let _ = query_stream.flush().await;

                    if let Ok(Ok(resp_len)) = tokio::time::timeout(Duration::from_secs(2), query_stream.read_u32()).await {
                        let mut resp_buf = vec![0u8; resp_len as usize];
                        if tokio::time::timeout(Duration::from_secs(2), query_stream.read_exact(&mut resp_buf)).await.is_ok() {
                            if let Ok(PacketHeader::ResumeResponse { offset: existing, accepted, .. }) = serde_json::from_slice(&resp_buf) {
                                if accepted && existing > 0 && existing < total_size {
                                    offset = existing;
                                }
                            }
                        }
                    }
                }
            }
        }

        Self::send_file_at_offset(target, file_path, sender_id, Some(file_id), offset, cancel_token, progress_cb).await
    }

    pub async fn send_file_at_offset<F>(
        target: SocketAddr,
        file_path: &Path,
        sender_id: Option<String>,
        file_id: Option<String>,
        offset: u64,
        cancel_token: Option<Arc<AtomicBool>>,
        progress_cb: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(u64, u64, f64, u64) + Send + 'static,
    {
        let mut file = tokio::fs::File::open(file_path).await?;
        let metadata = file.metadata().await?;
        let total_size = metadata.len();
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin")
            .to_string();

        let sha256_hash = if total_size <= 100 * 1024 * 1024 {
            let mut hasher = Sha256::new();
            let mut check_file = tokio::fs::File::open(file_path).await?;
            let mut check_buf = vec![0u8; CHUNK_SIZE];
            loop {
                let n = check_file.read(&mut check_buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&check_buf[..n]);
            }
            let hash_bytes = hasher.finalize();
            Some(hash_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
        } else {
            None
        };

        let mut stream = TcpStream::connect(target).await?;
        let _ = stream.set_nodelay(true);
        let header = PacketHeader::FileOffer {
            name: filename,
            size: total_size,
            sha256: sha256_hash,
            sender_id,
            file_id,
            offset,
        };
        let header_bytes = serde_json::to_vec(&header)?;

        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_u32(header_bytes.len() as u32))
            .await
            .map_err(|_| "Network Timeout: Failed to write file offer header size within 15s")??;
        tokio::time::timeout(NETWORK_TIMEOUT, stream.write_all(&header_bytes))
            .await
            .map_err(|_| "Network Timeout: Failed to write file offer header bytes within 15s")??;

        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(offset)).await?;
        }

        let mut sent: u64 = offset;
        let mut buf = vec![0u8; CHUNK_SIZE];
        let start_time = Instant::now();

        while sent < total_size {
            if let Some(ref cancel) = cancel_token {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Send operation cancelled by user".into());
                }
            }

            let to_read = std::cmp::min(buf.len() as u64, total_size - sent) as usize;
            let n = file.read(&mut buf[..to_read]).await?;
            if n == 0 {
                break;
            }
            tokio::time::timeout(NETWORK_TIMEOUT, stream.write_all(&buf[..n]))
                .await
                .map_err(|_| "Network Timeout: Sender stalled writing file chunk for more than 15 seconds")??;
            sent += n as u64;

            let elapsed_secs = start_time.elapsed().as_secs_f64().max(0.001);
            let transferred_now = sent.saturating_sub(offset);
            let speed_mb_s = (transferred_now as f64 / (1024.0 * 1024.0)) / elapsed_secs;
            let remaining_bytes = total_size - sent;
            let speed_bytes_s = (transferred_now as f64) / elapsed_secs;
            let eta_secs = if speed_bytes_s > 0.0 {
                (remaining_bytes as f64 / speed_bytes_s) as u64
            } else {
                0
            };

            progress_cb(sent, total_size, speed_mb_s, eta_secs);
        }

        tokio::time::timeout(NETWORK_TIMEOUT, stream.flush())
            .await
            .map_err(|_| "Network Timeout: Sender stalled flushing file stream for more than 15 seconds")??;
        Ok(())
    }

    /// إرسال حزمة ملفات متعددة بالتتابع مع متابعة تقدم كل ملف ومجموع الحزمة ودعم الإلغاء اللحظي
    pub async fn send_multiple_files<F>(
        target: SocketAddr,
        file_paths: &[PathBuf],
        progress_cb: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(usize, usize, u64, u64, f64, u64) + Send + Clone + 'static,
    {
        Self::send_multiple_files_cancellable(target, file_paths, None, None, progress_cb).await
    }

    pub async fn send_multiple_files_cancellable<F>(
        target: SocketAddr,
        file_paths: &[PathBuf],
        sender_id: Option<String>,
        cancel_token: Option<Arc<AtomicBool>>,
        progress_cb: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(usize, usize, u64, u64, f64, u64) + Send + Clone + 'static,
    {
        let total_files = file_paths.len();
        for (idx, path) in file_paths.iter().enumerate() {
            if let Some(ref cancel) = cancel_token {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Batch transfer cancelled by user".into());
                }
            }
            let cb = progress_cb.clone();
            let c_tok = cancel_token.clone();
            let s_id = sender_id.clone();
            Self::send_file_resumable(target, path, s_id, c_tok, move |sent, total, speed, eta| {
                cb(idx + 1, total_files, sent, total, speed, eta);
            }).await?;
        }
        Ok(())
    }
}
