use otium_flow::protocol::transfer::{TransferEvent, TransferManager};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_10mb_high_throughput_file_benchmark() {
    let base_dir = std::env::temp_dir().join(format!("flow_bench_{}", uuid::Uuid::new_v4()));
    let src_dir = base_dir.join("src");
    let dest_dir = base_dir.join("dest");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dest_dir).unwrap();

    let test_port = 57121;
    let (tx, mut rx) = mpsc::unbounded_channel::<TransferEvent>();
    let manager = Arc::new(TransferManager::new(test_port, dest_dir.clone()));
    manager.clone().start_receiver(tx).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // توليد ملف اختباري بحجم 10 ميجابايت (10 * 1024 * 1024 بايت)
    let size_bytes: usize = 10 * 1024 * 1024;
    let test_file = src_dir.join("large_archive.iso");

    let mut mock_data = Vec::with_capacity(size_bytes);
    for i in 0..size_bytes {
        mock_data.push((i % 251) as u8);
    }
    std::fs::write(&test_file, &mock_data).unwrap();

    let target: SocketAddr = format!("127.0.0.1:{}", test_port).parse().unwrap();

    // بدء قياس سرعة النقل الحقيقية
    let start_time = Instant::now();

    TransferManager::send_file(target, &test_file, |_sent, _total, _speed, _eta| {})
        .await
        .unwrap();

    // انتظار اكتمال التدفق والحفظ الذري
    while let Some(event) = rx.recv().await {
        if let TransferEvent::FileComplete { name, path } = event {
            let duration = start_time.elapsed();
            let duration_secs = duration.as_secs_f64();
            let mb_transferred = size_bytes as f64 / (1024.0 * 1024.0);
            let speed_mb_s = mb_transferred / duration_secs;

            println!("\n==========================================");
            println!("⚡ [FLOW BENCHMARK 10MB RESULTS]");
            println!("Transferred: {:.2} MB in {:.3} seconds", mb_transferred, duration_secs);
            println!("Throughput Speed: {:.2} MB/s", speed_mb_s);
            println!("==========================================\n");

            assert_eq!(name, "large_archive.iso");
            assert!(path.exists());
            assert_eq!(std::fs::metadata(&path).unwrap().len(), size_bytes as u64);

            // التحقق من سلامة البايتات كاملة
            let received_data = std::fs::read(&path).unwrap();
            assert_eq!(received_data, mock_data);
            break;
        }
    }

    let _ = std::fs::remove_dir_all(&base_dir);
}
