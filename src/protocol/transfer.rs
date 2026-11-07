//! Protocol 3: mutually paired, challenge-bound authenticated frames.
//! Plain discovery is allowed; user data never has a plaintext/downgrade path.
use super::discovery::{BeaconMessage, DeviceType, Peer};
use super::trust::TrustManager;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

pub const DEFAULT_TCP_PORT: u16 = 54125;
const MAGIC: &[u8; 8] = b"FLOWSEC3";
const PING_MAGIC: &[u8; 8] = b"FLOWPING";
const CHUNK_SIZE: usize = 64 * 1024;
const MAX_TEXT_SIZE: usize = 1024 * 1024;
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Default)]
struct GateState {
    paused: bool,
    active: usize,
}

/// Owns an update pause without holding a mutex across installation or I/O.
/// Dropping it reopens the transfer gate on failure or Android installer handoff.
#[derive(Debug)]
pub struct UpdatePause {
    gate: Arc<Mutex<GateState>>,
}

impl UpdatePause {
    fn acquire(gate: &Arc<Mutex<GateState>>) -> io::Result<Self> {
        let mut state = gate.lock().unwrap_or_else(|e| e.into_inner());
        if state.paused {
            return Err(error(
                io::ErrorKind::AlreadyExists,
                "An update is already in progress",
            ));
        }
        if state.active != 0 {
            return Err(error(
                io::ErrorKind::WouldBlock,
                "Wait for all transfers to finish before installing",
            ));
        }
        state.paused = true;
        Ok(Self { gate: gate.clone() })
    }
}

impl Drop for UpdatePause {
    fn drop(&mut self) {
        self.gate.lock().unwrap_or_else(|e| e.into_inner()).paused = false;
    }
}

struct TransferLease {
    gate: Arc<Mutex<GateState>>,
}

impl TransferLease {
    fn acquire(gate: &Arc<Mutex<GateState>>) -> io::Result<Self> {
        let mut state = gate.lock().unwrap_or_else(|e| e.into_inner());
        if state.paused {
            return Err(error(
                io::ErrorKind::WouldBlock,
                "Flow is updating. Try sending again after the update finishes",
            ));
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| error(io::ErrorKind::WouldBlock, "Too many active transfers"))?;
        Ok(Self { gate: gate.clone() })
    }
}

impl Drop for TransferLease {
    fn drop(&mut self) {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        state.active = state.active.saturating_sub(1);
    }
}

#[derive(Debug, Clone)]
pub enum TransferEvent {
    PeerDiscovered(Peer),
    IncomingStarted {
        id: String,
        peer_id: String,
        name: String,
        total_bytes: u64,
        kind: String,
    },
    IncomingProgress {
        id: String,
        current_bytes: u64,
        total_bytes: u64,
        speed_mb_s: f64,
        eta_secs: u64,
    },
    IncomingComplete {
        id: String,
        peer_id: String,
        name: String,
        path: Option<PathBuf>,
        text: Option<String>,
        total_bytes: u64,
    },
    IncomingFailed {
        id: String,
        peer_id: String,
        name: String,
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    sender_id: String,
    recipient_id: String,
    transfer_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum Command {
    Probe,
    Text {
        text: String,
    },
    File {
        name: String,
        size: u64,
        sha256: [u8; 32],
    },
    Ack,
}

fn error(kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
    io::Error::new(kind, message.into())
}
fn invalid(message: impl Into<String>) -> io::Error {
    error(io::ErrorKind::InvalidData, message)
}
fn auth_error() -> io::Error {
    error(
        io::ErrorKind::PermissionDenied,
        "Pairing could not be verified. Exchange the codes on both devices again",
    )
}
fn cancelled_error() -> io::Error {
    error(io::ErrorKind::Interrupted, "Transfer cancelled")
}

async fn bounded<F, T>(future: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    tokio::time::timeout(TIMEOUT, future).await.map_err(|_| {
        error(
            io::ErrorKind::TimedOut,
            "The other device did not respond in time",
        )
    })?
}

async fn wait_cancelled(token: &AtomicBool) {
    loop {
        if token.load(Ordering::Acquire) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    // The first four UUID bytes contain no fixed version/variant bits.
    let mut bytes = [0u8; N];
    for chunk in bytes.chunks_mut(4) {
        let uuid = uuid::Uuid::new_v4();
        chunk.copy_from_slice(&uuid.as_bytes()[..chunk.len()]);
    }
    bytes
}

struct SecureChannel {
    stream: TcpStream,
    cipher: ChaCha20Poly1305,
    context: Vec<u8>,
    tx_sequence: u64,
    rx_sequence: u64,
    sender_side: bool,
}

impl SecureChannel {
    fn new(
        stream: TcpStream,
        psk: &[u8; 32],
        challenge: &[u8; 32],
        hello_bytes: &[u8],
        sender_side: bool,
    ) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"FLOW-3-SESSION\0");
        hash.update(psk);
        hash.update(challenge);
        hash.update((hello_bytes.len() as u32).to_be_bytes());
        hash.update(hello_bytes);
        let key: [u8; 32] = hash.finalize().into();
        let mut context = Vec::from(&b"FLOW-3-FRAME\0"[..]);
        context.extend_from_slice(challenge);
        context.extend_from_slice(hello_bytes);
        Self {
            stream,
            cipher: ChaCha20Poly1305::new((&key).into()),
            context,
            tx_sequence: 0,
            rx_sequence: 0,
            sender_side,
        }
    }
    fn aad(&self, direction: bool, sequence: u64) -> Vec<u8> {
        let mut aad = self.context.clone();
        aad.push(u8::from(direction));
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad
    }
    async fn write(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let nonce = random_bytes::<12>();
        let aad = self.aad(self.sender_side, self.tx_sequence);
        let ciphertext = self
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| auth_error())?;
        self.tx_sequence = self
            .tx_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("Frame counter exhausted"))?;
        bounded(async {
            self.stream
                .write_u32((ciphertext.len() + nonce.len()) as u32)
                .await?;
            self.stream.write_all(&nonce).await?;
            self.stream.write_all(&ciphertext).await
        })
        .await
    }
    async fn read(&mut self, maximum_plaintext: usize) -> io::Result<Vec<u8>> {
        let (nonce, ciphertext) = bounded(async {
            let len = self.stream.read_u32().await? as usize;
            if len < 28 || len > maximum_plaintext + 28 {
                return Err(invalid("Invalid encrypted frame size"));
            }
            let mut nonce = [0u8; 12];
            self.stream.read_exact(&mut nonce).await?;
            let mut ciphertext = vec![0u8; len - 12];
            self.stream.read_exact(&mut ciphertext).await?;
            Ok((nonce, ciphertext))
        })
        .await?;
        let aad = self.aad(!self.sender_side, self.rx_sequence);
        let plaintext = self
            .cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| auth_error())?;
        self.rx_sequence = self
            .rx_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("Frame counter exhausted"))?;
        Ok(plaintext)
    }
    async fn command(&mut self, command: &Command) -> io::Result<()> {
        self.write(&serde_json::to_vec(command).map_err(io::Error::other)?)
            .await
    }
    async fn ack(&mut self) -> io::Result<()> {
        match serde_json::from_slice::<Command>(&self.read(512).await?)
            .map_err(|_| invalid("Invalid completion acknowledgement"))?
        {
            Command::Ack => Ok(()),
            _ => Err(invalid("The receiver did not confirm completion")),
        }
    }
}

pub struct TransferManager {
    pub port: u16,
    pub download_dir: PathBuf,
    pub trust_manager: Arc<TrustManager>,
    connection_limiter: Arc<Semaphore>,
    incoming: Mutex<HashMap<String, Arc<AtomicBool>>>,
    reserved_bytes: Mutex<u64>,
    transfer_gate: Arc<Mutex<GateState>>,
}

impl TransferManager {
    pub fn with_trust(port: u16, download_dir: PathBuf, trust: Arc<TrustManager>) -> Self {
        Self {
            port,
            download_dir,
            trust_manager: trust,
            connection_limiter: Arc::new(Semaphore::new(16)),
            incoming: Mutex::new(HashMap::new()),
            reserved_bytes: Mutex::new(0),
            transfer_gate: Arc::new(Mutex::new(GateState::default())),
        }
    }

    /// Atomically prevents new data transfers only when every active one is done.
    /// Authenticated reachability probes and discovery remain available.
    pub fn pause_for_update(&self) -> io::Result<UpdatePause> {
        UpdatePause::acquire(&self.transfer_gate)
    }

    pub fn cancel_incoming(&self, id: &str) -> bool {
        if let Some(token) = self
            .incoming
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
        {
            token.store(true, Ordering::Release);
            true
        } else {
            false
        }
    }

    pub async fn start_receiver(
        self: Arc<Self>,
        sender: mpsc::UnboundedSender<TransferEvent>,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", self.port)).await?;
        self.start_with_listener(listener, sender).await;
        Ok(())
    }

    pub async fn start_with_listener(
        self: Arc<Self>,
        listener: TcpListener,
        sender: mpsc::UnboundedSender<TransferEvent>,
    ) {
        tokio::spawn(async move {
            while let Ok((stream, address)) = listener.accept().await {
                let permit = match self.connection_limiter.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let manager = self.clone();
                let events = sender.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // Unauthenticated network noise must not create false activity rows.
                    let _ = manager.handle_connection(stream, address, events).await;
                });
            }
        });
    }

    async fn open_channel(
        &self,
        target: SocketAddr,
        peer_id: &str,
        transfer_id: &str,
    ) -> io::Result<SecureChannel> {
        if uuid::Uuid::parse_str(transfer_id).is_err() {
            return Err(invalid("Invalid transfer identifier"));
        }
        let psk = self.trust_manager.get_key_for_peer(peer_id).await?;
        let mut stream = connect_with_retry(target, 3).await?;
        let hello = Hello {
            sender_id: self.trust_manager.self_id().into(),
            recipient_id: peer_id.into(),
            transfer_id: transfer_id.into(),
        };
        let hello_bytes = serde_json::to_vec(&hello).map_err(io::Error::other)?;
        bounded(async {
            stream.write_all(MAGIC).await?;
            stream.write_u32(hello_bytes.len() as u32).await?;
            stream.write_all(&hello_bytes).await
        })
        .await?;
        let mut challenge = [0u8; 32];
        bounded(stream.read_exact(&mut challenge)).await?;
        Ok(SecureChannel::new(
            stream,
            &psk,
            &challenge,
            &hello_bytes,
            true,
        ))
    }

    /// A successful challenge/ACK verifies pairing and reachability, not mere discovery.
    pub async fn verify_peer(&self, target: SocketAddr, peer_id: &str) -> io::Result<()> {
        let mut channel = self
            .open_channel(target, peer_id, &uuid::Uuid::new_v4().to_string())
            .await?;
        channel.command(&Command::Probe).await?;
        channel.ack().await
    }

    pub async fn send_secure_text(
        &self,
        target: SocketAddr,
        peer_id: &str,
        text: String,
        transfer_id: &str,
    ) -> io::Result<()> {
        let _activity = TransferLease::acquire(&self.transfer_gate)?;
        if text.trim().is_empty() {
            return Err(invalid("Enter text before sending"));
        }
        if text.len() > MAX_TEXT_SIZE {
            return Err(invalid("Text is limited to 1 MB"));
        }
        let mut channel = self.open_channel(target, peer_id, transfer_id).await?;
        channel.command(&Command::Text { text }).await?;
        channel.ack().await
    }

    pub async fn send_secure_file<F>(
        &self,
        target: SocketAddr,
        peer_id: &str,
        path: &Path,
        transfer_id: &str,
        cancel: Arc<AtomicBool>,
        progress: F,
    ) -> io::Result<()>
    where
        F: Fn(u64, u64, f64, u64) + Send,
    {
        let _activity = TransferLease::acquire(&self.transfer_gate)?;
        tokio::select! {
            result = self.send_file_inner(target, peer_id, path, transfer_id, &cancel, progress) => result,
            _ = wait_cancelled(&cancel) => Err(cancelled_error()),
        }
    }

    async fn send_file_inner<F>(
        &self,
        target: SocketAddr,
        peer_id: &str,
        path: &Path,
        transfer_id: &str,
        cancel: &AtomicBool,
        progress: F,
    ) -> io::Result<()>
    where
        F: Fn(u64, u64, f64, u64) + Send,
    {
        if cancel.load(Ordering::Acquire) {
            return Err(cancelled_error());
        }
        let mut file = tokio::fs::File::open(path).await?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            return Err(invalid("Select a regular file"));
        }
        let total = metadata.len();
        if total > MAX_FILE_SIZE {
            return Err(invalid("Files larger than 50 GB are not supported"));
        }
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| invalid("The filename is not valid Unicode"))?
            .to_owned();
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; CHUNK_SIZE];
        loop {
            if cancel.load(Ordering::Acquire) {
                return Err(cancelled_error());
            }
            let count = file.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        use tokio::io::AsyncSeekExt;
        file.rewind().await?;
        let sha256: [u8; 32] = hash.finalize().into();
        let mut channel = self.open_channel(target, peer_id, transfer_id).await?;
        channel
            .command(&Command::File {
                name,
                size: total,
                sha256,
            })
            .await?;
        // Receiver has authenticated the offer and reserved safe temporary storage.
        channel.ack().await?;
        let start = Instant::now();
        let mut sent = 0;
        progress(0, total, 0.0, 0);
        while sent < total {
            if cancel.load(Ordering::Acquire) {
                return Err(cancelled_error());
            }
            let max = (total - sent).min(CHUNK_SIZE as u64) as usize;
            let count = file.read(&mut buffer[..max]).await?;
            if count == 0 {
                return Err(invalid("The source file changed during transfer"));
            }
            channel.write(&buffer[..count]).await?;
            sent += count as u64;
            let (speed, eta) = transfer_rate(sent, total, start);
            progress(sent, total, speed, eta);
        }
        if cancel.load(Ordering::Acquire) {
            return Err(cancelled_error());
        }
        // Success is only reported after checksum verification and durable publication.
        channel.ack().await
    }

    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        address: SocketAddr,
        events: mpsc::UnboundedSender<TransferEvent>,
    ) -> io::Result<()> {
        let mut magic = [0u8; 8];
        bounded(stream.read_exact(&mut magic)).await?;
        if &magic == PING_MAGIC {
            let bytes = read_bounded_packet(&mut stream, 1024).await?;
            let beacon: BeaconMessage = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if uuid::Uuid::parse_str(&beacon.id).is_ok()
                && beacon.id != self.trust_manager.self_id()
                && beacon.tcp_port != 0
            {
                let _ = events.send(TransferEvent::PeerDiscovered(Peer {
                    id: beacon.id,
                    name: beacon.name.chars().take(40).collect(),
                    device_type: beacon.device_type,
                    ip: address.ip(),
                    tcp_port: beacon.tcp_port,
                    last_seen: Instant::now(),
                }));
            }
            return Ok(());
        }
        if &magic != MAGIC {
            return Err(invalid("Unsupported protocol; update both devices"));
        }
        let hello_bytes = read_bounded_packet(&mut stream, 1024).await?;
        let mut hello: Hello = serde_json::from_slice(&hello_bytes).map_err(io::Error::other)?;
        if hello.recipient_id != self.trust_manager.self_id()
            || uuid::Uuid::parse_str(&hello.sender_id).is_err()
            || uuid::Uuid::parse_str(&hello.transfer_id).is_err()
        {
            return Err(auth_error());
        }
        let key = self
            .trust_manager
            .get_key_for_peer(&hello.sender_id)
            .await?;
        let challenge = random_bytes::<32>();
        bounded(stream.write_all(&challenge)).await?;
        let mut channel = SecureChannel::new(stream, &key, &challenge, &hello_bytes, false);
        // Authenticate before trusting any metadata or producing UI events.
        let command: Command =
            serde_json::from_slice(&channel.read(MAX_TEXT_SIZE * 6 + 1024).await?)
                .map_err(io::Error::other)?;
        if let Command::Probe = command {
            return channel.command(&Command::Ack).await;
        }
        let _activity = TransferLease::acquire(&self.transfer_gate)?;
        // UI/cancellation IDs include direction and peer. A remote wire UUID can
        // never replace an outgoing job, or a job from another paired device.
        hello.transfer_id = format!("in:{}:{}", hello.sender_id, hello.transfer_id);
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut active = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
            if active.contains_key(&hello.transfer_id) {
                return Err(invalid("Duplicate active transfer identifier"));
            }
            active.insert(hello.transfer_id.clone(), cancel.clone());
        }
        let name = match &command {
            Command::File { name, .. } => sanitize_filename(name),
            _ => "Text".into(),
        };
        let result = tokio::select! {
            result = self.receive_command(&mut channel, command, &hello, &events, &cancel) => result,
            _ = wait_cancelled(&cancel) => Err(cancelled_error()),
        };
        self.incoming
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&hello.transfer_id);
        if let Err(ref problem) = result {
            let _ = events.send(TransferEvent::IncomingFailed {
                id: hello.transfer_id,
                peer_id: hello.sender_id,
                name,
                message: problem.to_string(),
            });
        }
        result
    }

    async fn receive_command(
        &self,
        channel: &mut SecureChannel,
        command: Command,
        hello: &Hello,
        events: &mpsc::UnboundedSender<TransferEvent>,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
        match command {
            Command::Text { text } => {
                if text.len() > MAX_TEXT_SIZE || text.trim().is_empty() {
                    return Err(invalid("Invalid text size"));
                }
                let total = text.len() as u64;
                let _ = events.send(TransferEvent::IncomingStarted {
                    id: hello.transfer_id.clone(),
                    peer_id: hello.sender_id.clone(),
                    name: "Text".into(),
                    total_bytes: total,
                    kind: "text".into(),
                });
                let _ = events.send(TransferEvent::IncomingComplete {
                    id: hello.transfer_id.clone(),
                    peer_id: hello.sender_id.clone(),
                    name: "Text".into(),
                    path: None,
                    text: Some(text),
                    total_bytes: total,
                });
                let _ = channel.command(&Command::Ack).await;
                Ok(())
            }
            Command::File { name, size, sha256 } => {
                if size > MAX_FILE_SIZE {
                    return Err(invalid("The offered file exceeds the 50 GB limit"));
                }
                tokio::fs::create_dir_all(&self.download_dir).await?;
                let _reservation = {
                    let mut reserved = self
                        .reserved_bytes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let required = size.saturating_add(*reserved).saturating_add(1024 * 1024);
                    if get_available_disk_space(&self.download_dir)
                        .is_some_and(|space| space < required)
                    {
                        return Err(error(
                            io::ErrorKind::StorageFull,
                            "There is not enough space to receive this file",
                        ));
                    }
                    *reserved = reserved.saturating_add(size);
                    DiskReservation {
                        reserved: &self.reserved_bytes,
                        bytes: size,
                    }
                };
                let base = self.download_dir.canonicalize()?;
                let name = sanitize_filename(&name);
                let temp_path = base.join(format!(".flow-{}.flowpart", uuid::Uuid::new_v4()));
                let cleanup = TemporaryFile(temp_path.clone());
                let mut file = tokio::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&temp_path)
                    .await?;
                let _ = events.send(TransferEvent::IncomingStarted {
                    id: hello.transfer_id.clone(),
                    peer_id: hello.sender_id.clone(),
                    name: name.clone(),
                    total_bytes: size,
                    kind: "file".into(),
                });
                channel.command(&Command::Ack).await?;
                let mut hash = Sha256::new();
                let mut received = 0;
                let start = Instant::now();
                while received < size {
                    if cancel.load(Ordering::Acquire) {
                        return Err(cancelled_error());
                    }
                    let chunk = channel.read(CHUNK_SIZE).await?;
                    if chunk.is_empty() || chunk.len() as u64 > size - received {
                        return Err(invalid("The received file length does not match its offer"));
                    }
                    file.write_all(&chunk).await?;
                    hash.update(&chunk);
                    received += chunk.len() as u64;
                    let (speed, eta) = transfer_rate(received, size, start);
                    let _ = events.send(TransferEvent::IncomingProgress {
                        id: hello.transfer_id.clone(),
                        current_bytes: received,
                        total_bytes: size,
                        speed_mb_s: speed,
                        eta_secs: eta,
                    });
                }
                if cancel.load(Ordering::Acquire) {
                    return Err(cancelled_error());
                }
                let actual: [u8; 32] = hash.finalize().into();
                if actual != sha256 {
                    return Err(invalid(
                        "The file changed or failed its integrity check; it was not saved",
                    ));
                }
                file.sync_all().await?;
                drop(file);
                let final_path = publish_file(&temp_path, &base, &name).await?;
                drop(cleanup);
                let _ = events.send(TransferEvent::IncomingComplete {
                    id: hello.transfer_id.clone(),
                    peer_id: hello.sender_id.clone(),
                    name: final_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    path: Some(final_path),
                    text: None,
                    total_bytes: size,
                });
                let _ = channel.command(&Command::Ack).await;
                Ok(())
            }
            _ => Err(invalid("Unexpected protocol command")),
        }
    }

    /// Discovery metadata only. This method never transfers clipboard/file content.
    pub async fn send_tcp_ping(
        target: SocketAddr,
        id: String,
        name: String,
        device_type: DeviceType,
        tcp_port: u16,
    ) -> io::Result<()> {
        let bytes = serde_json::to_vec(&BeaconMessage {
            id,
            name,
            device_type,
            tcp_port,
        })
        .map_err(io::Error::other)?;
        let mut stream = connect_with_retry(target, 1).await?;
        bounded(async {
            stream.write_all(PING_MAGIC).await?;
            stream.write_u32(bytes.len() as u32).await?;
            stream.write_all(&bytes).await
        })
        .await
    }
}

struct TemporaryFile(PathBuf);
struct DiskReservation<'a> {
    reserved: &'a Mutex<u64>,
    bytes: u64,
}
impl Drop for DiskReservation<'_> {
    fn drop(&mut self) {
        let mut reserved = self.reserved.lock().unwrap_or_else(|e| e.into_inner());
        *reserved = reserved.saturating_sub(self.bytes);
    }
}
impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if std::fs::remove_file(&self.0).is_err() && self.0.exists() {
            // An in-flight Tokio file operation can briefly retain a Windows handle.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let path = self.0.clone();
                runtime.spawn(async move {
                    for _ in 0..10 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if tokio::fs::remove_file(&path).await.is_ok() || !path.exists() {
                            break;
                        }
                    }
                });
            }
        }
    }
}

async fn read_bounded_packet(stream: &mut TcpStream, maximum: usize) -> io::Result<Vec<u8>> {
    bounded(async {
        let size = stream.read_u32().await? as usize;
        if size == 0 || size > maximum {
            return Err(invalid("Invalid protocol header size"));
        }
        let mut bytes = vec![0u8; size];
        stream.read_exact(&mut bytes).await?;
        Ok(bytes)
    })
    .await
}

async fn publish_file(temporary: &Path, base: &Path, name: &str) -> io::Result<PathBuf> {
    let original = Path::new(name);
    let stem = original.file_stem().unwrap_or_default().to_string_lossy();
    let extension = original
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for index in 0..10_000 {
        let filename = if index == 0 {
            name.to_owned()
        } else {
            format!("{stem} ({index}){extension}")
        };
        let target = base.join(filename);
        // The OS primitive atomically fails on collision; there is no check/rename race.
        let source = temporary.to_owned();
        let destination = target.clone();
        match tokio::task::spawn_blocking(move || publish_no_replace(&source, &destination))
            .await
            .map_err(io::Error::other)?
        {
            Ok(()) => return Ok(target),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(error(
        io::ErrorKind::AlreadyExists,
        "Too many files share this name",
    ))
}

#[cfg(windows)]
fn publish_no_replace(source: &Path, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(source: *const u16, target: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    // MOVEFILE_WRITE_THROUGH; deliberately omit MOVEFILE_REPLACE_EXISTING.
    let moved = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 8) };
    if moved != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn publish_no_replace(source: &Path, target: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| invalid("Invalid source path"))?;
    let to = std::ffi::CString::new(target.as_os_str().as_bytes())
        .map_err(|_| invalid("Invalid destination path"))?;
    // Direct syscall also works on Android API levels whose libc lacks renameat2.
    let moved = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            1u32,
        )
    };
    if moved == 0 {
        return Ok(());
    }
    let problem = io::Error::last_os_error();
    if problem.raw_os_error() == Some(libc::ENOSYS) || problem.raw_os_error() == Some(libc::EINVAL)
    {
        // Older kernels: hard-link creation has the same no-replace guarantee.
        std::fs::hard_link(source, target)?;
        let _ = std::fs::remove_file(source);
        Ok(())
    } else {
        Err(problem)
    }
}

#[cfg(target_os = "macos")]
fn publish_no_replace(source: &Path, target: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| invalid("Invalid source path"))?;
    let to = std::ffi::CString::new(target.as_os_str().as_bytes())
        .map_err(|_| invalid("Invalid destination path"))?;
    let moved = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if moved == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos"
)))]
fn publish_no_replace(source: &Path, target: &Path) -> io::Result<()> {
    std::fs::hard_link(source, target)?;
    let _ = std::fs::remove_file(source);
    Ok(())
}

pub fn sanitize_filename(input: &str) -> String {
    let basename = input.rsplit(['/', '\\']).next().unwrap_or_default();
    let filtered: String = basename.chars().filter(|c| !c.is_control() && !matches!(c, '<'|'>'|':'|'"'|'/'|'\\'|'|'|'?'|'*'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')).collect();
    let clean = filtered.trim().trim_matches('.').trim();
    let clean = if clean.is_empty() { "file" } else { clean };
    let path = Path::new(clean);
    let stem: String = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .chars()
        .take(70)
        .collect();
    let stem = stem.trim_end_matches([' ', '.']);
    let mut stem_bytes = 0;
    let stem: String = stem
        .chars()
        .take_while(|character| {
            stem_bytes += character.len_utf8();
            stem_bytes <= 180
        })
        .collect();
    let extension: String = path
        .extension()
        .map(|e| e.to_string_lossy().chars().take(16).collect())
        .unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    let reserved = matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|number| {
            number.chars().count() == 1
                && number
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '¹' | '²' | '³'))
        });
    format!(
        "{}{}{}",
        if reserved { "_" } else { "" },
        stem,
        if extension.is_empty() {
            String::new()
        } else {
            format!(".{extension}")
        }
    )
}

fn transfer_rate(done: u64, total: u64, start: Instant) -> (f64, u64) {
    let bytes_per_second = done as f64 / start.elapsed().as_secs_f64().max(0.001);
    (
        bytes_per_second / (1024.0 * 1024.0),
        if bytes_per_second > 0.0 {
            ((total.saturating_sub(done)) as f64 / bytes_per_second) as u64
        } else {
            0
        },
    )
}

pub async fn connect_with_retry(target: SocketAddr, attempts: usize) -> io::Result<TcpStream> {
    let mut last = error(
        io::ErrorKind::NotConnected,
        "The selected device is unavailable",
    );
    for attempt in 0..attempts {
        match tokio::time::timeout(Duration::from_millis(2500), TcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Ok(Err(e)) => last = e,
            Err(_) => last = error(io::ErrorKind::TimedOut, "Connection timed out"),
        }
        if attempt + 1 < attempts {
            tokio::time::sleep(Duration::from_millis(100 * (1 << attempt.min(4)))).await;
        }
    }
    Err(last)
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
pub fn format_transfer_status(current: u64, total: u64, speed: f64, eta: u64) -> String {
    format!(
        "{} / {} · {:.1} MB/s · {}s",
        format_bytes(current),
        format_bytes(total),
        speed,
        eta
    )
}

#[cfg(windows)]
pub fn get_available_disk_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            path: *const u16,
            available: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut available = 0;
    let success = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (success != 0).then_some(available)
}
#[cfg(unix)]
pub fn get_available_disk_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut statistics = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), statistics.as_mut_ptr()) } != 0 {
        return None;
    }
    let statistics = unsafe { statistics.assume_init() };
    (statistics.f_bavail as u64).checked_mul(statistics.f_frsize as u64)
}
#[cfg(not(any(windows, unix)))]
pub fn get_available_disk_space(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_pause_is_exclusive_with_concurrent_transfer_leases() {
        let gate = Arc::new(Mutex::new(GateState::default()));
        let worker_gate = gate.clone();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let lease = TransferLease::acquire(&worker_gate).unwrap();
            acquired_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(lease);
        });
        acquired_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            UpdatePause::acquire(&gate).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        release_tx.send(()).unwrap();
        worker.join().unwrap();

        let pause = UpdatePause::acquire(&gate).unwrap();
        assert_eq!(
            UpdatePause::acquire(&gate).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let contender_gate = gate.clone();
        let blocked = std::thread::spawn(move || {
            TransferLease::acquire(&contender_gate)
                .err()
                .unwrap()
                .kind()
        });
        assert_eq!(blocked.join().unwrap(), io::ErrorKind::WouldBlock);
        drop(pause);
        drop(TransferLease::acquire(&gate).unwrap());
        assert_eq!(gate.lock().unwrap().active, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn update_pause_blocks_data_in_both_directions_but_allows_probes() {
        let root = std::env::temp_dir().join(format!("flow-update-gate-{}", uuid::Uuid::new_v4()));
        let sender_id = uuid::Uuid::new_v4().to_string();
        let receiver_id = uuid::Uuid::new_v4().to_string();
        let sender_trust = Arc::new(
            TrustManager::try_with_self_id(root.join("sender"), sender_id.clone()).unwrap(),
        );
        let receiver_trust = Arc::new(
            TrustManager::try_with_self_id(root.join("receiver"), receiver_id.clone()).unwrap(),
        );
        sender_trust
            .trust_peer_with_secret(
                receiver_id.clone(),
                "Receiver".into(),
                &receiver_trust.pairing_code().await,
            )
            .await
            .unwrap();
        receiver_trust
            .trust_peer_with_secret(
                sender_id.clone(),
                "Sender".into(),
                &sender_trust.pairing_code().await,
            )
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = Arc::new(TransferManager::with_trust(
            address.port(),
            root.join("files"),
            receiver_trust,
        ));
        let sender = Arc::new(TransferManager::with_trust(
            0,
            root.join("outgoing"),
            sender_trust,
        ));
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        receiver
            .clone()
            .start_with_listener(listener, events_tx)
            .await;

        let pause = sender.pause_for_update().unwrap();
        assert_eq!(
            sender
                .send_secure_text(
                    address,
                    &receiver_id,
                    "blocked".into(),
                    &uuid::Uuid::new_v4().to_string()
                )
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            sender
                .send_secure_file(
                    address,
                    &receiver_id,
                    &root.join("not-opened.txt"),
                    &uuid::Uuid::new_v4().to_string(),
                    Arc::new(AtomicBool::new(false)),
                    |_, _, _, _| {}
                )
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        sender.verify_peer(address, &receiver_id).await.unwrap();
        drop(pause);

        let pause = receiver.pause_for_update().unwrap();
        sender.verify_peer(address, &receiver_id).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_secure_text(
                address,
                &receiver_id,
                "also blocked".into(),
                &uuid::Uuid::new_v4().to_string()
            )
        )
        .await
        .unwrap()
        .is_err());
        assert!(
            events_rx.try_recv().is_err(),
            "paused data must not create a received activity row"
        );
        drop(pause);

        sender
            .send_secure_text(
                address,
                &receiver_id,
                "resumed".into(),
                &uuid::Uuid::new_v4().to_string(),
            )
            .await
            .unwrap();
        let mut delivered = false;
        while let Ok(event) = events_rx.try_recv() {
            if let TransferEvent::IncomingComplete {
                text: Some(text), ..
            } = event
            {
                delivered |= text == "resumed";
            }
        }
        assert!(delivered);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_outgoing_transfer_blocks_update_until_future_is_cancelled() {
        let root =
            std::env::temp_dir().join(format!("flow-update-active-{}", uuid::Uuid::new_v4()));
        let trust = Arc::new(
            TrustManager::try_with_self_id(root.clone(), uuid::Uuid::new_v4().to_string()).unwrap(),
        );
        let peer_id = uuid::Uuid::new_v4().to_string();
        trust
            .trust_peer_with_secret(peer_id.clone(), "Peer".into(), &"a".repeat(64))
            .await
            .unwrap();
        let manager = Arc::new(TransferManager::with_trust(0, root.join("files"), trust));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sending = manager.clone();
        let task = tokio::spawn(async move {
            sending
                .send_secure_text(
                    address,
                    &peer_id,
                    "waiting for peer".into(),
                    &uuid::Uuid::new_v4().to_string(),
                )
                .await
        });
        let (_stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            manager.pause_for_update().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(manager.pause_for_update().unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn safe_names_preserve_unicode_and_extensions() {
        assert_eq!(sanitize_filename("../../صورة (1).png"), "صورة (1).png");
        assert_eq!(sanitize_filename("C:\\folder\\CON.txt"), "_CON.txt");
        assert_eq!(sanitize_filename("evil:stream?.txt"), "evilstream.txt");
        assert_eq!(sanitize_filename(" ... "), "file");
        assert!(sanitize_filename(&format!("{}.pdf", "a".repeat(200))).ends_with(".pdf"));
        assert!(sanitize_filename(&format!("{}.png", "📁".repeat(100))).len() < 255);
        assert_eq!(sanitize_filename("COM¹.txt"), "_COM¹.txt");
    }

    #[tokio::test]
    async fn frame_sequence_rejects_replayed_authenticated_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut channel = SecureChannel::new(stream, &[7; 32], &[9; 32], b"context", false);
            assert_eq!(channel.read(128).await.unwrap(), b"first");
            assert!(channel.read(128).await.is_err());
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let mut channel = SecureChannel::new(stream, &[7; 32], &[9; 32], b"context", true);
        let nonce = random_bytes::<12>();
        let ciphertext = channel
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: b"first",
                    aad: &channel.aad(true, 0),
                },
            )
            .unwrap();
        for _ in 0..2 {
            channel
                .stream
                .write_u32((ciphertext.len() + 12) as u32)
                .await
                .unwrap();
            channel.stream.write_all(&nonce).await.unwrap();
            channel.stream.write_all(&ciphertext).await.unwrap();
        }
        server.await.unwrap();
    }
}
