//! Protocol 3 regression coverage. All listeners use ephemeral loopback ports.
use otium_flow::protocol::transfer::sanitize_filename;
use otium_flow::protocol::{clean_text, TransferEvent, TransferManager, TrustManager};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("flow-v3-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        // Only a UUID test directory directly under the OS temporary directory.
        if self.0.parent() == Some(std::env::temp_dir().as_path())
            && self
                .0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("flow-v3-test-")
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

struct Pair {
    directory: TestDirectory,
    sender: Arc<TransferManager>,
    receiver: Arc<TransferManager>,
    sender_trust: Arc<TrustManager>,
    receiver_trust: Arc<TrustManager>,
    target: SocketAddr,
    events: mpsc::UnboundedReceiver<TransferEvent>,
}
impl Pair {
    async fn new() -> Self {
        let directory = TestDirectory::new();
        let sender_trust = Arc::new(
            TrustManager::try_with_self_id(
                directory.0.join("a-private"),
                uuid::Uuid::new_v4().to_string(),
            )
            .unwrap(),
        );
        let receiver_trust = Arc::new(
            TrustManager::try_with_self_id(
                directory.0.join("b-private"),
                uuid::Uuid::new_v4().to_string(),
            )
            .unwrap(),
        );
        sender_trust
            .trust_peer_with_secret(
                receiver_trust.self_id().into(),
                "Receiver".into(),
                &receiver_trust.pairing_code().await,
            )
            .await
            .unwrap();
        receiver_trust
            .trust_peer_with_secret(
                sender_trust.self_id().into(),
                "Sender".into(),
                &sender_trust.pairing_code().await,
            )
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let receiver = Arc::new(TransferManager::with_trust(
            target.port(),
            directory.0.join("received"),
            receiver_trust.clone(),
        ));
        let sender = Arc::new(TransferManager::with_trust(
            0,
            directory.0.join("sent"),
            sender_trust.clone(),
        ));
        let (tx, events) = mpsc::unbounded_channel();
        receiver.clone().start_with_listener(listener, tx).await;
        Self {
            directory,
            sender,
            receiver,
            sender_trust,
            receiver_trust,
            target,
            events,
        }
    }
    fn file(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.directory.0.join(name);
        std::fs::write(&path, data).unwrap();
        path
    }
    async fn terminal(&mut self, id: &str) -> TransferEvent {
        let expected = format!("in:{}:{}", self.sender_trust.self_id(), id);
        tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let event=self.events.recv().await.expect("receiver event channel");
                if matches!(&event,TransferEvent::IncomingComplete{id:actual,..}|TransferEvent::IncomingFailed{id:actual,..} if actual==&expected) { return event; }
            }
        }).await.expect("transfer should terminate")
    }
    async fn send_file(&self, path: &Path, id: &str) -> std::io::Result<()> {
        self.sender
            .send_secure_file(
                self.target,
                self.receiver_trust.self_id(),
                path,
                id,
                Arc::new(AtomicBool::new(false)),
                |_, _, _, _| {},
            )
            .await
    }
}

#[test]
fn url_cleaning_preserves_meaningful_parameters_and_fragments() {
    assert_eq!(
        clean_text("https://youtu.be/id?si=tracking#t=30s").0,
        "https://youtu.be/id#t=30s"
    );
    assert_eq!(
        clean_text("https://store.example/item?id=9988&fbclid=tracking&gclid=test").0,
        "https://store.example/item?id=9988"
    );
    assert_eq!(
        clean_text("مرحبا من الهاتف"),
        ("مرحبا من الهاتف".into(), false)
    );
    assert_eq!(
        clean_text("https://github.com/org/repo/tree/main#readme").0,
        "https://github.com/org/repo/tree/main#readme"
    );
}

#[test]
fn filenames_cannot_escape_or_name_windows_devices() {
    for name in ["CON", "nul.txt", "AUX.png", "COM1.log", "LPT9.txt"] {
        assert!(sanitize_filename(name).starts_with('_'));
    }
    assert_eq!(
        sanitize_filename("../../ملاحظات (نهائي).txt"),
        "ملاحظات (نهائي).txt"
    );
    assert_eq!(
        sanitize_filename("C:\\Windows\\evil:alternate?.txt"),
        "evilalternate.txt"
    );
    assert!(!sanitize_filename("\u{202e}txt.exe").contains('\u{202e}'));
    let long = sanitize_filename(&format!("{}.png", "ص".repeat(500)));
    assert!(long.chars().count() < 100);
    assert!(long.ends_with(".png"));
}

#[tokio::test]
async fn mutual_pairing_probe_and_unicode_text_are_acknowledged() {
    let mut pair = Pair::new().await;
    pair.sender
        .verify_peer(pair.target, pair.receiver_trust.self_id())
        .await
        .unwrap();
    assert!(pair.events.try_recv().is_err(), "probes are not transfers");
    let id = uuid::Uuid::new_v4().to_string();
    let text = "مرحبا 👋\nhttps://example.org/path?a=1#part";
    pair.sender
        .send_secure_text(pair.target, pair.receiver_trust.self_id(), text.into(), &id)
        .await
        .unwrap();
    match pair.terminal(&id).await {
        TransferEvent::IncomingComplete {
            text: Some(actual),
            peer_id,
            ..
        } => {
            assert_eq!(actual, text);
            assert_eq!(peer_id, pair.sender_trust.self_id());
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn files_are_durable_and_verified_before_sender_success() {
    let mut pair = Pair::new().await;
    let data: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let source = pair.file("صورة (نهائي).bin", &data);
    let id = uuid::Uuid::new_v4().to_string();
    pair.send_file(&source, &id).await.unwrap();
    match pair.terminal(&id).await {
        TransferEvent::IncomingComplete {
            path: Some(path),
            total_bytes,
            ..
        } => {
            assert_eq!(total_bytes, data.len() as u64);
            assert_eq!(std::fs::read(path).unwrap(), data);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn zero_byte_files_are_complete_files() {
    let mut pair = Pair::new().await;
    let source = pair.file("empty.txt", b"");
    let id = uuid::Uuid::new_v4().to_string();
    pair.send_file(&source, &id).await.unwrap();
    match pair.terminal(&id).await {
        TransferEvent::IncomingComplete {
            path: Some(path), ..
        } => assert_eq!(std::fs::metadata(path).unwrap().len(), 0),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn colliding_names_never_overwrite_existing_content() {
    let mut pair = Pair::new().await;
    let source = pair.file("report.txt", b"new report");
    std::fs::create_dir_all(&pair.receiver.download_dir).unwrap();
    let existing = pair.receiver.download_dir.join("report.txt");
    std::fs::write(&existing, b"keep this").unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    pair.send_file(&source, &id).await.unwrap();
    match pair.terminal(&id).await {
        TransferEvent::IncomingComplete {
            path: Some(path), ..
        } => {
            assert_ne!(path, existing);
            assert_eq!(std::fs::read(path).unwrap(), b"new report");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(std::fs::read(existing).unwrap(), b"keep this");
}

#[tokio::test]
async fn wrong_secret_and_revocation_cannot_deliver_data() {
    let mut pair = Pair::new().await;
    pair.sender_trust
        .trust_peer_with_secret(
            pair.receiver_trust.self_id().into(),
            "Receiver".into(),
            &"ab".repeat(32),
        )
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    assert!(pair
        .sender
        .send_secure_text(
            pair.target,
            pair.receiver_trust.self_id(),
            "secret".into(),
            &id
        )
        .await
        .is_err());
    assert!(pair.events.try_recv().is_err());
    pair.sender_trust
        .trust_peer_with_secret(
            pair.receiver_trust.self_id().into(),
            "Receiver".into(),
            &pair.receiver_trust.pairing_code().await,
        )
        .await
        .unwrap();
    pair.receiver_trust
        .revoke_peer(pair.sender_trust.self_id())
        .await
        .unwrap();
    assert!(pair
        .sender
        .verify_peer(pair.target, pair.receiver_trust.self_id())
        .await
        .is_err());
    assert!(pair.events.try_recv().is_err());
}

#[tokio::test]
async fn plaintext_and_oversized_headers_are_rejected_without_activity() {
    let mut pair = Pair::new().await;
    let mut plain = TcpStream::connect(pair.target).await.unwrap();
    plain
        .write_all(b"{\"ClipboardText\":{\"content\":\"no\"}}")
        .await
        .unwrap();
    let mut byte = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), plain.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    let mut huge = TcpStream::connect(pair.target).await.unwrap();
    huge.write_all(b"FLOWSEC3").await.unwrap();
    huge.write_u32(u32::MAX).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), huge.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    assert!(pair.events.try_recv().is_err());
    pair.sender
        .verify_peer(pair.target, pair.receiver_trust.self_id())
        .await
        .unwrap();
}

#[tokio::test]
async fn source_modification_fails_integrity_and_leaves_no_published_file() {
    let mut pair = Pair::new().await;
    let source = pair.file("changing.bin", &vec![1; 256 * 1024]);
    let change = source.clone();
    let id = uuid::Uuid::new_v4().to_string();
    let result = pair
        .sender
        .send_secure_file(
            pair.target,
            pair.receiver_trust.self_id(),
            &source,
            &id,
            Arc::new(AtomicBool::new(false)),
            move |done, _, _, _| {
                if done == 0 {
                    std::fs::write(&change, vec![2; 256 * 1024]).unwrap();
                }
            },
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        pair.terminal(&id).await,
        TransferEvent::IncomingFailed { .. }
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        std::fs::read_dir(&pair.receiver.download_dir)
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn per_transfer_cancel_cleans_partial_file_and_allows_next_transfer() {
    let mut pair = Pair::new().await;
    let source = pair.file("cancel.bin", &vec![3; 2 * 1024 * 1024]);
    let id = uuid::Uuid::new_v4().to_string();
    let token = Arc::new(AtomicBool::new(false));
    let cancel = token.clone();
    let result = pair
        .sender
        .send_secure_file(
            pair.target,
            pair.receiver_trust.self_id(),
            &source,
            &id,
            token,
            move |done, _, _, _| {
                if done > 0 {
                    cancel.store(true, Ordering::Release);
                }
            },
        )
        .await;
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
    assert!(matches!(
        pair.terminal(&id).await,
        TransferEvent::IncomingFailed { .. }
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        std::fs::read_dir(&pair.receiver.download_dir)
            .unwrap()
            .count(),
        0
    );
    let next = uuid::Uuid::new_v4().to_string();
    pair.send_file(&source, &next).await.unwrap();
    assert!(matches!(
        pair.terminal(&next).await,
        TransferEvent::IncomingComplete { .. }
    ));
}

#[tokio::test]
async fn receiver_can_cancel_a_specific_incoming_job() {
    let mut pair = Pair::new().await;
    let source = pair.file("receive-cancel.bin", &vec![4; 4 * 1024 * 1024]);
    let id = uuid::Uuid::new_v4().to_string();
    let sender = pair.sender.clone();
    let target = pair.target;
    let peer = pair.receiver_trust.self_id().to_string();
    let send_id = id.clone();
    let send = tokio::spawn(async move {
        sender
            .send_secure_file(
                target,
                &peer,
                &source,
                &send_id,
                Arc::new(AtomicBool::new(false)),
                |_, _, _, _| {},
            )
            .await
    });
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), pair.events.recv())
            .await
            .unwrap()
            .unwrap();
        if matches!(event, TransferEvent::IncomingStarted { .. }) {
            assert!(pair.receiver.cancel_incoming(&format!(
                "in:{}:{}",
                pair.sender_trust.self_id(),
                id
            )));
            break;
        }
    }
    assert!(send.await.unwrap().is_err());
    assert!(matches!(
        pair.terminal(&id).await,
        TransferEvent::IncomingFailed { .. }
    ));
    assert!(!pair.receiver.cancel_incoming("unknown"));
}

#[tokio::test]
async fn concurrent_transfers_have_independent_identifiers_and_files() {
    let mut pair = Pair::new().await;
    let one = pair.file("one.bin", &vec![5; 128 * 1024]);
    let two = pair.file("two.bin", &vec![6; 128 * 1024]);
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let (first, second) = tokio::join!(pair.send_file(&one, &a), pair.send_file(&two, &b));
    first.unwrap();
    second.unwrap();
    let mut complete = std::collections::HashSet::new();
    while complete.len() < 2 {
        match tokio::time::timeout(Duration::from_secs(5), pair.events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            TransferEvent::IncomingComplete {
                id,
                path: Some(path),
                ..
            } => {
                assert!(path.exists());
                complete.insert(id);
            }
            TransferEvent::IncomingFailed { message, .. } => panic!("{message}"),
            _ => {}
        }
    }
    assert!(
        complete.contains(&format!("in:{}:{}", pair.sender_trust.self_id(), a))
            && complete.contains(&format!("in:{}:{}", pair.sender_trust.self_id(), b))
    );
}

#[tokio::test]
async fn encrypted_wire_hides_text_and_cannot_be_replayed_on_a_new_connection() {
    let mut pair = Pair::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let target = pair.target;
    let capture = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect(target).await.unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let upstream = async move {
            let mut captured = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    server_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(captured);
                }
                captured.extend_from_slice(&buf[..n]);
                server_write.write_all(&buf[..n]).await?;
            }
        };
        let downstream = async move { tokio::io::copy(&mut server_read, &mut client_write).await };
        let (data, _) = tokio::join!(upstream, downstream);
        data.unwrap()
    });
    let secret = "a private clipboard message that must never appear on the wire";
    let id = uuid::Uuid::new_v4().to_string();
    pair.sender
        .send_secure_text(proxy, pair.receiver_trust.self_id(), secret.into(), &id)
        .await
        .unwrap();
    assert!(matches!(
        pair.terminal(&id).await,
        TransferEvent::IncomingComplete { .. }
    ));
    let wire = tokio::time::timeout(Duration::from_secs(5), capture)
        .await
        .unwrap()
        .unwrap();
    assert!(!wire
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()));
    assert!(wire.starts_with(b"FLOWSEC3"));
    // Replaying a complete captured offer/frame gets a fresh server challenge.
    let mut replay = TcpStream::connect(pair.target).await.unwrap();
    replay.write_all(&wire).await.unwrap();
    let mut challenge = [0u8; 32];
    replay.read_exact(&mut challenge).await.unwrap();
    let mut byte = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), replay.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    assert!(
        pair.events.try_recv().is_err(),
        "a replay must not deliver the text twice"
    );
}
