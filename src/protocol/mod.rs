pub mod cleaner;
pub mod discovery;
pub mod history;
pub mod transfer;
pub mod trust;
pub mod updater;

pub use cleaner::clean_text;
pub use discovery::{get_or_create_device_id, DeviceType, DiscoveryManager, Peer};
pub use history::{HistoryEntry, HistoryKind, HistoryManager};
pub use transfer::{
    format_bytes, format_transfer_status, sanitize_filename, TransferEvent, TransferManager,
};
pub use trust::{normalize_pairing_code, TrustConfig, TrustManager, TrustedDevice};
