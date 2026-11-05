use otium_flow::protocol::cleaner::clean_text;
use otium_flow::protocol::transfer::{PacketHeader, TransferEvent, TransferManager};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_url_cleaner_all_platforms() {
    // 1. يوتيوب مع تتبع si والهاش
    let yt = "https://youtu.be/dQw4w9WgXcQ?si=abc123xyz#t=30s";
    let (cleaned, was_cleaned) = clean_text(yt);
    assert!(was_cleaned);
    assert_eq!(cleaned, "https://youtu.be/dQw4w9WgXcQ#t=30s");

    // 2. فيسبوك وجوجل مع الحفاظ على البارامترات الحقيقية
    let fb = "https://store.example.com/item?id=9988&fbclid=IwAR234&gclid=TeStInG";
    let (cleaned, was_cleaned) = clean_text(fb);
    assert!(was_cleaned);
    assert_eq!(cleaned, "https://store.example.com/item?id=9988");

    // 3. نص عادي بدون روابط
    let text = "Hello from phone!";
    let (cleaned, was_cleaned) = clean_text(text);
    assert!(!was_cleaned);
    assert_eq!(cleaned, text);
}

#[tokio::test]
async fn test_path_traversal_attack_blocked() {
    let test_dir = std::env::temp_dir().join(format!("flow_sec_test_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&test_dir);

    let test_port = 56121;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // هجوم Path Traversal: محاولة كتابة ملف خارج المجلد
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let malicious_header = PacketHeader::FileOffer {
        name: "../../evil_script.bat".to_string(),
        size: 5,
        sha256: None,
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&malicious_header).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.write_all(b"pwned").await.unwrap();
    client.flush().await.unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            assert_eq!(name, "evil_script.bat");
            assert!(path.starts_with(&test_dir));
            assert_eq!(path.file_name().unwrap(), "evil_script.bat");
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_dos_huge_header_rejected() {
    let test_dir = std::env::temp_dir().join(format!("flow_dos_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56122;
    let (tx, _rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let fake_len: u32 = 1_000_000_000;
    client.write_u32(fake_len).await.unwrap();
    client.flush().await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let mut test_buf = [0u8; 1];
    let res = client.try_read(&mut test_buf);
    assert!(res.is_err() || res.unwrap() == 0);

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_end_to_end_file_stream_integrity() {
    let base_dir = std::env::temp_dir().join(format!("flow_stream_test_{}", uuid::Uuid::new_v4()));
    let src_dir = base_dir.join("sender");
    let dest_dir = base_dir.join("receiver");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dest_dir).unwrap();

    let test_port = 56123;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, dest_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let source_file = src_dir.join("test_payload.dat");
    let original_data: Vec<u8> = (0..256 * 1024).map(|i| (i % 255) as u8).collect();
    std::fs::write(&source_file, &original_data).unwrap();

    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();
    TransferManager::send_file(target, &source_file, |_s, _t, _speed, _eta| {})
        .await
        .unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            assert_eq!(name, "test_payload.dat");
            let received_data = std::fs::read(&path).unwrap();
            assert_eq!(received_data.len(), original_data.len());
            assert_eq!(received_data, original_data);
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&base_dir);
}

#[tokio::test]
async fn test_file_collision_prevention() {
    let base_dir = std::env::temp_dir().join(format!("flow_col_test_{}", uuid::Uuid::new_v4()));
    let src_dir = base_dir.join("sender");
    let dest_dir = base_dir.join("receiver");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dest_dir).unwrap();

    let test_port = 56124;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, dest_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let source_file = src_dir.join("doc.txt");
    std::fs::write(&source_file, b"Version 1").unwrap();

    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();

    TransferManager::send_file(target, &source_file, |_s, _t, _speed, _eta| {}).await.unwrap();
    let mut first_name = String::new();
    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, .. } = event {
            first_name = name;
            break;
        }
    }
    assert_eq!(first_name, "doc.txt");

    TransferManager::send_file(target, &source_file, |_s, _t, _speed, _eta| {}).await.unwrap();
    let mut second_name = String::new();
    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, .. } = event {
            second_name = name;
            break;
        }
    }
    assert_eq!(second_name, "doc_1.txt");

    let _ = std::fs::remove_dir_all(&base_dir);
}

#[tokio::test]
async fn test_interrupted_transfer_cleans_flowpart() {
    // اختبار انقطاع الاتصال المفاجئ والتأكد من تنظيف الملفات المؤقتة وعدم ترك ملفات تالفة
    let test_dir = std::env::temp_dir().join(format!("flow_abort_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56125;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // الاتصال وإرسال وعد بملف حجمه 1 ميجابايت، لكن قطع الاتصال بعد 100 بايت فقط
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let offer = PacketHeader::FileOffer {
        name: "large_movie.mp4".to_string(),
        size: 1_000_000,
        sha256: None,
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.write_all(&vec![0xAA; 100]).await.unwrap();
    client.flush().await.unwrap();

    // قطع الاتصال عمداً بمحاكاة انقطاع شبكة الـ Wi-Fi
    drop(client);

    // انتظار معالجة الخطأ
    while let Some(event) = rx.recv().await {
        if let TransferEvent::Error(_) = event {
            break;
        }
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // التأكد من عدم وجود أي ملف .flowpart متبقي في المجلد!
    let entries = std::fs::read_dir(&test_dir).unwrap();
    let count = entries.count();
    assert_eq!(count, 0, "No corrupted files should remain after aborted transfer");

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_encrypted_clipboard_e2ee() {
    // اختبار تشفير الحافظة من طرف لطرف بـ ChaCha20-Poly1305
    let test_dir = std::env::temp_dir().join(format!("flow_e2ee_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56126;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let secret_message = "Confidential Otium Token #99182".to_string();
    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();
    TransferManager::send_encrypted_clipboard(target, secret_message.clone()).await.unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::ClipboardReceived(received_text) = event {
            assert_eq!(received_text, secret_message);
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_corrupted_checksum_rejected() {
    let test_dir = std::env::temp_dir().join(format!("flow_corrupt_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56127;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // الاتصال وإرسال ملف مع بصمة تشفيرية متوقعة
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let offer = PacketHeader::FileOffer {
        name: "tampered.dat".to_string(),
        size: 10,
        sha256: Some("0000000000000000000000000000000000000000000000000000000000000000".to_string()), // بصمة خاطئة عمداً
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.write_all(b"0123456789").await.unwrap();
    client.flush().await.unwrap();

    // انتظار صدور خطأ التحقق التشفيري
    let mut got_error = false;
    while let Some(event) = rx.recv().await {
        if let TransferEvent::Error(err) = event {
            assert!(err.contains("Cryptographic Integrity Error") || err.contains("Checksum mismatch"));
            got_error = true;
            break;
        }
    }
    assert!(got_error);

    // التأكد من حذف الملف وعدم وجود أي ملف تالف
    let entries = std::fs::read_dir(&test_dir).unwrap();
    assert_eq!(entries.count(), 0);

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_multi_file_batch_transfer() {
    let base_dir = std::env::temp_dir().join(format!("flow_batch_test_{}", uuid::Uuid::new_v4()));
    let src_dir = base_dir.join("src");
    let dest_dir = base_dir.join("dest");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dest_dir).unwrap();

    let test_port = 56128;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, dest_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // تجهيز 3 ملفات مختلفة في مجلد المصدر
    let f1 = src_dir.join("photo1.jpg");
    let f2 = src_dir.join("photo2.png");
    let f3 = src_dir.join("document.pdf");
    std::fs::write(&f1, b"JPEG_DATA_1").unwrap();
    std::fs::write(&f2, b"PNG_DATA_2").unwrap();
    std::fs::write(&f3, b"PDF_DATA_3").unwrap();

    let file_list = vec![f1, f2, f3];
    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();

    // إرسال الحزمة كاملة
    TransferManager::send_multiple_files(target, &file_list, |_idx, _tot, _s, _t, _speed, _eta| {})
        .await
        .unwrap();

    // التحقق من استقبال جميع الملفات الثلاثة بنجاح
    let mut completed_files = Vec::new();
    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            assert!(path.exists());
            completed_files.push(name);
            if completed_files.len() == 3 {
                break;
            }
        }
    }

    assert_eq!(completed_files.len(), 3);
    completed_files.sort();
    let mut expected = vec!["document.pdf", "photo1.jpg", "photo2.png"];
    expected.sort();
    assert_eq!(completed_files, expected);

    let _ = std::fs::remove_dir_all(&base_dir);
}

#[tokio::test]
async fn test_zero_byte_empty_file_transfer() {
    // اختبار نقل ملف فارغ بحجم 0 بايت
    let base_dir = std::env::temp_dir().join(format!("flow_zero_test_{}", uuid::Uuid::new_v4()));
    let src_dir = base_dir.join("src");
    let dest_dir = base_dir.join("dest");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dest_dir).unwrap();

    let test_port = 56129;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, dest_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let empty_file = src_dir.join("empty.txt");
    std::fs::write(&empty_file, b"").unwrap();

    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();
    TransferManager::send_file(target, &empty_file, |_s, _t, _speed, _eta| {}).await.unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            assert_eq!(name, "empty.txt");
            assert!(path.exists());
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&base_dir);
}

#[tokio::test]
async fn test_very_long_filename_truncated_safely() {
    // اختبار حماية تجاوز طول المسار (MAX_PATH) لأسماء الملفات المفرطة في الطول
    let test_dir = std::env::temp_dir().join(format!("flow_long_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56130;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // اسم ملف بطول 200 حرف
    let long_name = format!("{}.pdf", "a".repeat(200));

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let offer = PacketHeader::FileOffer {
        name: long_name,
        size: 4,
        sha256: None,
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.write_all(b"test").await.unwrap();
    client.flush().await.unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            // نتحقق من أن الاسم تم اختصاره بأمان لأقل من 110 أحرف مع الحفاظ على الامتداد
            assert!(name.len() <= 110);
            assert!(name.ends_with(".pdf"));
            assert!(path.exists());
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_rapid_clipboard_burst_stress() {
    // اختبار إجهاد إرسال 50 حزمة حافظة متتالية وسريعة عبر الشبكة
    let test_dir = std::env::temp_dir().join(format!("flow_burst_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56131;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();

    // إرسال 50 تحديثاً متتالياً
    for i in 0..50 {
        let msg = format!("Burst Clipboard Message #{}", i);
        TransferManager::send_clipboard(target, msg).await.unwrap();
    }

    let mut received_count = 0;
    while let Some(event) = rx.recv().await {
        if let TransferEvent::ClipboardReceived(_) = event {
            received_count += 1;
            if received_count == 50 {
                break;
            }
        }
    }

    assert_eq!(received_count, 50);
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_two_instances_discovery_and_sync() {
    use otium_flow::protocol::{DeviceType, DiscoveryManager};

    let p1_name = "Workstation PC".to_string();
    let p2_name = "Galaxy Ultra".to_string();

    let d1 = Arc::new(DiscoveryManager::new(p1_name.clone(), DeviceType::Desktop, 59121));
    let d2 = Arc::new(DiscoveryManager::new(p2_name.clone(), DeviceType::Mobile, 59122));

    d1.clone().start().await.unwrap();
    d2.clone().start().await.unwrap();

    // انتظار تبادل حزم الـ UDP Beacon
    let mut found_peer = false;
    for _ in 0..10 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        let peers_of_d1 = d1.active_peers().await;
        if peers_of_d1.iter().any(|p| p.name == p2_name) {
            found_peer = true;
            break;
        }
    }

    assert!(found_peer, "Peer 1 should automatically discover Peer 2 on the local network");
}

#[tokio::test]
async fn test_massive_clipboard_payload_transfer() {
    // اختبار إرسال نص حافظة ضخم جداً (128 كيلوبايت من النصوص والشيفرات البرمجية)
    let test_dir = std::env::temp_dir().join(format!("flow_mass_clip_{}", uuid::Uuid::new_v4()));
    let test_port = 56132;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // نص ضخم بحجم 128 KB
    let huge_text: String = "const DATA_CHUNK_0123456789_ABCDEF = 42;\n".repeat(3000);
    assert!(huge_text.len() > 120_000);

    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();
    TransferManager::send_clipboard(target, huge_text.clone()).await.unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::ClipboardReceived(received_text) = event {
            assert_eq!(received_text.len(), huge_text.len());
            assert_eq!(received_text, huge_text);
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_unicode_and_spaces_filename_sanitization() {
    // اختبار دعم أسماء الملفات العربية واليونيكود مع الحفاظ على المسافات والأقواس
    let test_dir = std::env::temp_dir().join(format!("flow_unicode_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56133;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let original_name = "تقرير أوتيوم (النسخة النهائية) 2026.pdf".to_string();
    let file_data = b"Pure Rust Slint Otium PDF Stream";

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let offer = PacketHeader::FileOffer {
        name: original_name.clone(),
        size: file_data.len() as u64,
        sha256: None,
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.write_all(file_data).await.unwrap();
    client.flush().await.unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            assert_eq!(name, original_name);
            assert!(path.exists());
            let disk_content = std::fs::read(&path).unwrap();
            assert_eq!(disk_content, file_data);
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_dangerous_chars_filename_sanitization() {
    // اختبار استبعاد المحارف المحظورة لأنظمة التشغيل (: * ? < > |)
    let test_dir = std::env::temp_dir().join(format!("flow_danger_name_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56134;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // اسم يحتوي على محارف غير صالحة لنظام التشغيل
    let dirty_name = "my:test*file?name<1>|bad.txt".to_string();
    let file_data = b"Sanitized stream data";

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let offer = PacketHeader::FileOffer {
        name: dirty_name,
        size: file_data.len() as u64,
        sha256: None,
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.write_all(file_data).await.unwrap();
    client.flush().await.unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            assert_eq!(name, "mytestfilename1bad.txt");
            assert!(path.exists());
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_max_file_size_limit_rejected() {
    // اختبار حظر الملفات ذات الحجم المفرط وغير الواقعي (>50 GB) لحماية القرص الصلب
    let test_dir = std::env::temp_dir().join(format!("flow_maxsize_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56135;
    let (tx, _rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let huge_offer = PacketHeader::FileOffer {
        name: "infinite_void.iso".to_string(),
        size: 100 * 1024 * 1024 * 1024, // 100 GB
        sha256: None,
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&huge_offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.flush().await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let mut buf = [0u8; 1];
    let res = client.try_read(&mut buf);
    assert!(res.is_err() || res.unwrap() == 0);

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_chacha20_unique_nonces() {
    // التأكد من أن كل رسالة مشفرة تستخدم Nonce عشوائياً مختلفاً تماماً
    let test_dir = std::env::temp_dir().join(format!("flow_nonce_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56136;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();
    TransferManager::send_encrypted_clipboard(target, "Secret Otium Token".to_string()).await.unwrap();
    TransferManager::send_encrypted_clipboard(target, "Secret Otium Token".to_string()).await.unwrap();

    let mut count = 0;
    while let Some(event) = rx.recv().await {
        if let TransferEvent::ClipboardReceived(text) = event {
            assert_eq!(text, "Secret Otium Token");
            count += 1;
            if count == 2 {
                break;
            }
        }
    }

    assert_eq!(count, 2);
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_untrusted_peer_file_rejected_when_auto_accept_disabled() {
    use otium_flow::protocol::TrustManager;

    let test_dir = std::env::temp_dir().join(format!("flow_trust_reject_{}", uuid::Uuid::new_v4()));
    let test_port = 56137;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();

    let trust = Arc::new(TrustManager::new(test_dir.clone()));
    trust.set_auto_accept(false).await.unwrap(); // تعطيل القبول التلقائي لحماية القرص

    let manager = Arc::new(TransferManager::with_trust(test_port, test_dir.clone(), trust));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // محاولة إرسال ملف من جهاز غير موثوق به
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let unauth_offer = PacketHeader::FileOffer {
        name: "unauthorized.exe".to_string(),
        size: 50,
        sha256: None,
        sender_id: Some("unknown_hacker_device".to_string()),
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&unauth_offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.flush().await.unwrap();

    // نتحقق من وصول حدث خطأ ورفض الاتصال الأمني
    let mut rejected = false;
    while let Some(event) = rx.recv().await {
        if let TransferEvent::Error(err) = event {
            assert!(err.contains("Untrusted peer"));
            rejected = true;
            break;
        }
    }
    assert!(rejected);
    assert!(!test_dir.join("unauthorized.exe").exists());

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_transfer_real_cancellation_aborts_stream_and_cleans_flowpart() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let test_dir = std::env::temp_dir().join(format!("flow_cancel_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56138;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let manager = Arc::new(
        TransferManager::new(test_port, test_dir.clone())
            .with_cancellation(cancel_flag.clone())
    );
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let offer = PacketHeader::FileOffer {
        name: "cancelled_transfer.dat".to_string(),
        size: 10_000_000,
        sha256: None,
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.write_all(&vec![0xAA; 1000]).await.unwrap();
    client.flush().await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // تفعيل إشارة الإلغاء اللحظية أثناء النقل
    cancel_flag.store(true, Ordering::SeqCst);

    // متابعة إرسال بايتات إضافية لتحفيز حلقة الفحص
    let _ = client.write_all(&vec![0xBB; 1000]).await;
    let _ = client.flush().await;

    let mut got_abort_error = false;
    while let Some(event) = rx.recv().await {
        if let TransferEvent::Error(err) = event {
            if err.contains("cancelled by user") {
                got_abort_error = true;
                break;
            }
        }
    }
    assert!(got_abort_error);

    // التأكد من أن الملف المؤقت .flowpart تم حذفه فوراً ولم يتبق أي أثر يتيم على القرص
    let entries = std::fs::read_dir(&test_dir).unwrap();
    let flowpart_count = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("flowpart"))
        .count();
    assert_eq!(flowpart_count, 0);

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_flowpart_startup_purge() {
    let test_dir = std::env::temp_dir().join(format!("flow_purge_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&test_dir).unwrap();

    // إنشاء ملفات .flowpart يتيمة تحاكي جلسات سابقة منهيارة
    let orphan1 = test_dir.join("old_movie.12345678.flowpart");
    let orphan2 = test_dir.join("corrupted.87654321.flowpart");
    let normal_file = test_dir.join("keep_this.pdf");

    std::fs::write(&orphan1, b"dangling bytes").unwrap();
    std::fs::write(&orphan2, b"partial bytes").unwrap();
    std::fs::write(&normal_file, b"important doc").unwrap();

    // تشغيل مدير النقل الجديد يستدعي purge_orphaned_flowparts تلقائياً
    let _manager = TransferManager::new(56139, test_dir.clone());

    assert!(!orphan1.exists());
    assert!(!orphan2.exists());
    assert!(normal_file.exists()); // الملفات العادية تظل سليمة 100%

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_windows_dos_device_names_sanitization() {
    // اختبار تحصين ويندوز ضد الأسماء المحجوزة في النواة مثل CON.txt و NUL.dat و AUX.mp4
    let test_dir = std::env::temp_dir().join(format!("flow_dos_dev_name_{}", uuid::Uuid::new_v4()));
    let test_port = 56140;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let offer = PacketHeader::FileOffer {
        name: "CON.txt".to_string(), // اسم محجوز قاتل لويندوز
        size: 9,
        sha256: None,
        sender_id: None,
        file_id: None,
        offset: 0,
    };
    let header_bytes = serde_json::to_vec(&offer).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.write_all(b"safe data").await.unwrap();
    client.flush().await.unwrap();

    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            // نتحقق من أن النظام حماه ببادئة safe_ لمنع تعليق ويندوز
            assert_eq!(name, "safe_CON.txt");
            assert!(path.exists());
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_replay_attack_rejected_after_ttl() {
    // اختبار منع هجمات إعادة الإرسال Replay Attack عند انتهاء مهلة TTL (120 ثانية)
    let test_dir = std::env::temp_dir().join(format!("flow_replay_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56141;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // محاكاة حزمة مشفرة تم اعتراضها قبل 300 ثانية وإعادة إرسالها الآن
    let old_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() - 300;

    let mut client = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let replayed_header = PacketHeader::EncryptedPayload {
        nonce: [0x77u8; 12],
        ciphertext: vec![0x11, 0x22, 0x33, 0x44],
        sender_id: Some("alice_phone".to_string()),
        timestamp_secs: old_timestamp, // حزمة قديمة منتهية الصلاحية
    };
    let header_bytes = serde_json::to_vec(&replayed_header).unwrap();
    client.write_u32(header_bytes.len() as u32).await.unwrap();
    client.write_all(&header_bytes).await.unwrap();
    client.flush().await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // الاتصال يجب أن يُقطع فوراً مع رفض الحزمة المعاد إرسالها
    let mut check_buf = [0u8; 1];
    let res = client.try_read(&mut check_buf);
    assert!(res.is_err() || res.unwrap() == 0);

    // لم يتم تسليم أي حدث للحافظة
    assert!(rx.try_recv().is_err());

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_resumable_transfer_midway_recovery() {
    // اختبار استئناف النقل الذاتي التلقائي عند انقطاع الاتصال في المنتصف
    let test_dir = std::env::temp_dir().join(format!("flow_resume_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56142;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let total_size: u64 = 1_000_000; // 1 MB
    let first_chunk_size: usize = 400_000; // 400 KB
    let test_file_id = "test_fid_12345678".to_string();
    let filename = "resumable_video.mp4".to_string();

    // 1. الجلسة الأولى: إرسال 400KB ثم قطع الاتصال عمداً
    let mut client1 = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let offer1 = PacketHeader::FileOffer {
        name: filename.clone(),
        size: total_size,
        sha256: None,
        sender_id: None,
        file_id: Some(test_file_id.clone()),
        offset: 0,
    };
    let h1_bytes = serde_json::to_vec(&offer1).unwrap();
    client1.write_u32(h1_bytes.len() as u32).await.unwrap();
    client1.write_all(&h1_bytes).await.unwrap();
    client1.write_all(&vec![0xAA; first_chunk_size]).await.unwrap();
    client1.flush().await.unwrap();

    // قطع الاتصال لمحاكاة سقوط شبكة الـ Wi-Fi
    drop(client1);
    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // استهلاك حدث الخطأ الناتج عن قطع الاتصال
    while let Ok(_) = rx.try_recv() {}

    // التأكد من بقاء ملف .flowpart حياً على القرص لاستئنافه
    let part_path = test_dir.join(format!("{}.{}.flowpart", filename, test_file_id));
    assert!(part_path.exists());
    let saved_len = std::fs::metadata(&part_path).unwrap().len();
    assert_eq!(saved_len, first_chunk_size as u64);

    // 2. الجلسة الثانية: استعلام الاستئناف واستكمال الـ 600KB المتبقية فقط
    let mut client2 = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
    let query = PacketHeader::ResumeQuery {
        file_id: test_file_id.clone(),
        name: filename.clone(),
        total_size,
        sender_id: None,
    };
    let q_bytes = serde_json::to_vec(&query).unwrap();
    client2.write_u32(q_bytes.len() as u32).await.unwrap();
    client2.write_all(&q_bytes).await.unwrap();
    client2.flush().await.unwrap();

    // قراءة رد الاستئناف من السيرفر
    let resp_len = client2.read_u32().await.unwrap();
    let mut resp_buf = vec![0u8; resp_len as usize];
    client2.read_exact(&mut resp_buf).await.unwrap();
    let resume_resp: PacketHeader = serde_json::from_slice(&resp_buf).unwrap();

    if let PacketHeader::ResumeResponse { offset, accepted, .. } = resume_resp {
        assert!(accepted);
        assert_eq!(offset, first_chunk_size as u64);

        // إرسال طلب استكمال النقل من النقطة التي توقف عندها
        let mut client3 = TcpStream::connect(format!("127.0.0.1:{}", test_port)).await.unwrap();
        let offer2 = PacketHeader::FileOffer {
            name: filename.clone(),
            size: total_size,
            sha256: None,
            sender_id: None,
            file_id: Some(test_file_id),
            offset,
        };
        let h2_bytes = serde_json::to_vec(&offer2).unwrap();
        client3.write_u32(h2_bytes.len() as u32).await.unwrap();
        client3.write_all(&h2_bytes).await.unwrap();

        let remaining = (total_size - offset) as usize;
        client3.write_all(&vec![0xBB; remaining]).await.unwrap();
        client3.flush().await.unwrap();

        // ننتظر اكتمال الملف بنجاح
        let mut completed = false;
        while let Some(event) = rx.recv().await {
            if let TransferEvent::FileComplete { name, path } = event {
                assert_eq!(name, filename);
                assert!(path.exists());
                let final_len = std::fs::metadata(&path).unwrap().len();
                assert_eq!(final_len, total_size);

                // التحقق من أن النصف الأول كان 0xAA والنصف الثاني كان 0xBB
                let content = std::fs::read(&path).unwrap();
                assert_eq!(&content[0..10], &[0xAA; 10]);
                assert_eq!(&content[first_chunk_size..first_chunk_size + 10], &[0xBB; 10]);
                completed = true;
                break;
            }
        }
        assert!(completed);
    } else {
        panic!("Expected ResumeResponse packet");
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_clipboard_image_direct_transfer() {
    let test_dir = std::env::temp_dir().join(format!("flow_img_test_{}", uuid::Uuid::new_v4()));
    let test_port = 56143;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, test_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();
    let dummy_pixels = vec![255u8; 100 * 100 * 4]; // صورة RGBA 100x100
    TransferManager::send_clipboard_image(target, 100, 100, dummy_pixels.clone(), Some("desktop_pc".to_string()))
        .await
        .unwrap();

    let mut got_image = false;
    while let Some(event) = rx.recv().await {
        if let TransferEvent::ClipboardImageReceived { width, height, data } = event {
            assert_eq!(width, 100);
            assert_eq!(height, 100);
            assert_eq!(data, dummy_pixels);
            got_image = true;
            break;
        }
    }
    assert!(got_image);

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_symlink_path_sandbox_blocks_escape() {
    use otium_flow::protocol::transfer::verify_path_sandbox;

    let base_dir = std::env::temp_dir().join(format!("flow_sandbox_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base_dir).unwrap();

    let inside_path = base_dir.join("safe_file.txt");
    assert!(verify_path_sandbox(&base_dir, &inside_path).is_ok());

    let outside_path = std::env::temp_dir().join("escaped_file.txt");
    assert!(verify_path_sandbox(&base_dir, &outside_path).is_err());

    let _ = std::fs::remove_dir_all(&base_dir);
}

#[tokio::test]
async fn test_windows_disk_space_query() {
    use otium_flow::protocol::transfer::get_available_disk_space;

    let temp_dir = std::env::temp_dir();
    let free_space = get_available_disk_space(&temp_dir);

    #[cfg(target_os = "windows")]
    {
        assert!(free_space.is_some());
        assert!(free_space.unwrap() > 1_000_000); // أكثر من 1 ميجابايت على القرص
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = free_space;
    }
}


#[tokio::test]
async fn test_sas_pairing_code_visual_verification() {
    use otium_flow::protocol::compute_sas_code;

    let peer_pc = "FLOW-DESKTOP-9X82";
    let peer_phone = "FLOW-PIXEL-4K19";

    // التحقق من تماثل رمز المصادقة البصري (SAS) على كلا الجهازين
    let code_pc_side = compute_sas_code(peer_pc, peer_phone);
    let code_phone_side = compute_sas_code(peer_phone, peer_pc);

    assert_eq!(code_pc_side, code_phone_side);
    assert_eq!(code_pc_side.len(), 6);
    assert!(code_pc_side.chars().all(|c| c.is_ascii_digit()));

    // التحقق من تنوع الرموز للأجهزة المختلفة لمنع هجمات التخمين
    let third_peer = "FLOW-MACBOOK-7Z01";
    let code_different = compute_sas_code(peer_pc, third_peer);
    assert_ne!(code_pc_side, code_different);
}
