use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub const DISCOVERY_PORT: u16 = 54124;
pub const BROADCAST_INTERVAL: Duration = Duration::from_secs(2);
pub const PEER_TIMEOUT: Duration = Duration::from_secs(6);
pub const MAX_DISCOVERED_PEERS: usize = 32; // سقف أمان أقصى لحماية الذاكرة من هجمات الإغراق (Beacon Flooding DoS)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Desktop,
    Mobile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconMessage {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub tcp_port: u16,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub ip: IpAddr,
    pub tcp_port: u16,
    pub last_seen: Instant,
}

pub type PeerRegistry = Arc<RwLock<HashMap<String, Peer>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BeaconChange {
    New,
    EndpointChanged,
    Seen,
    Rejected,
}

impl BeaconChange {
    fn needs_reply(self) -> bool {
        matches!(self, Self::New | Self::EndpointChanged)
    }
}

/// Refresh presence on every beacon, but answer only a newly discovered endpoint.
/// Answering ordinary presence replies creates a UDP echo loop between two peers.
fn register_beacon(
    peers: &mut HashMap<String, Peer>,
    self_id: &str,
    beacon: &BeaconMessage,
    ip: IpAddr,
) -> BeaconChange {
    if beacon.id == self_id || uuid::Uuid::parse_str(&beacon.id).is_err() || beacon.tcp_port == 0 {
        return BeaconChange::Rejected;
    }
    let change = match peers.get(&beacon.id) {
        Some(peer) if peer.ip != ip || peer.tcp_port != beacon.tcp_port => {
            BeaconChange::EndpointChanged
        }
        Some(_) => BeaconChange::Seen,
        None if peers.len() >= MAX_DISCOVERED_PEERS => return BeaconChange::Rejected,
        None => BeaconChange::New,
    };
    peers.insert(
        beacon.id.clone(),
        Peer {
            id: beacon.id.clone(),
            name: beacon
                .name
                .chars()
                .filter(|c| !c.is_control())
                .take(40)
                .collect(),
            device_type: beacon.device_type,
            ip,
            tcp_port: beacon.tcp_port,
            last_seen: Instant::now(),
        },
    );
    change
}

pub struct DiscoveryManager {
    pub self_id: String,
    pub self_name: String,
    pub self_type: DeviceType,
    pub tcp_port: u16,
    pub peers: PeerRegistry,
}

impl DiscoveryManager {
    /// إنشاء مدير اكتشاف جديد بمعرف تلقائي
    pub fn new(self_name: String, self_type: DeviceType, tcp_port: u16) -> Self {
        Self::with_id(
            uuid::Uuid::new_v4().to_string(),
            self_name,
            self_type,
            tcp_port,
        )
    }

    /// إنشاء مدير اكتشاف بمعرف دائم ومثبت على القرص
    pub fn with_id(
        self_id: String,
        self_name: String,
        self_type: DeviceType,
        tcp_port: u16,
    ) -> Self {
        Self {
            self_id,
            self_name,
            self_type,
            tcp_port,
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// يبدأ مهمة البث الذكي متعدد الشبكات مع حماية الذاكرة ودعم SO_REUSEADDR
    pub async fn start(self: Arc<Self>) -> Result<(), std::io::Error> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        let _ = sock.set_reuse_port(true);
        sock.set_broadcast(true)?;
        sock.set_nonblocking(true)?;

        let bind_addr: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DISCOVERY_PORT);
        let _ = sock.bind(&bind_addr.into());
        // الانضمام لمجموعة البث المتعدد المحلية (Local Multicast Group) لتجاوز حظر الـ Broadcast في بعض الموجهات
        let _ = sock.join_multicast_v4(&Ipv4Addr::new(239, 255, 255, 250), &Ipv4Addr::UNSPECIFIED);

        let std_socket: std::net::UdpSocket = sock.into();
        let tokio_socket = UdpSocket::from_std(std_socket)?;
        let socket = Arc::new(tokio_socket);

        // مهمة استقبال الحزم مع حماية صارمة ضد هجمات تضخيم الذاكرة
        let listener_self = self.clone();
        let listener_socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match listener_socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        if let Ok(beacon) = serde_json::from_slice::<BeaconMessage>(&buf[..len]) {
                            let change = {
                                let mut peers = listener_self.peers.write().await;
                                register_beacon(
                                    &mut peers,
                                    &listener_self.self_id,
                                    &beacon,
                                    src.ip(),
                                )
                            };
                            // Release the registry before network I/O. Known peers are
                            // refreshed above without replying to their own replies.
                            if change.needs_reply() {
                                // 1. إرسال رد Unicast فوري ومباشر على IP الهاتف لتخطي حظر الـ Broadcast
                                let reply = BeaconMessage {
                                    id: listener_self.self_id.clone(),
                                    name: listener_self.self_name.clone(),
                                    device_type: listener_self.self_type,
                                    tcp_port: listener_self.tcp_port,
                                };
                                if let Ok(bytes) = serde_json::to_vec(&reply) {
                                    let target = SocketAddr::new(src.ip(), DISCOVERY_PORT);
                                    let _ = listener_socket.send_to(&bytes, target).await;
                                }

                                // 2. إرسال TCP Discovery Ping مضمون لتخطي حظر موجهات الـ Wi-Fi
                                let target_tcp = SocketAddr::new(src.ip(), beacon.tcp_port);
                                let s_id = listener_self.self_id.clone();
                                let s_name = listener_self.self_name.clone();
                                let s_type = listener_self.self_type;
                                let s_port = listener_self.tcp_port;
                                tokio::spawn(async move {
                                    let _ = super::transfer::TransferManager::send_tcp_ping(
                                        target_tcp, s_id, s_name, s_type, s_port,
                                    )
                                    .await;
                                });
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Discovery] Receive error: {:?}", e);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        });

        // مهمة الإرسال متعدد الشبكات (Global + Subnet + Hotspot Support)
        let sender_self = self.clone();
        let sender_socket = socket.clone();
        tokio::spawn(async move {
            let broadcast_addrs = [
                SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT),
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
                    DISCOVERY_PORT,
                ),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 43, 255)), DISCOVERY_PORT),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 20, 10, 255)), DISCOVERY_PORT),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)), DISCOVERY_PORT),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)), DISCOVERY_PORT),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 255)), DISCOVERY_PORT),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)), DISCOVERY_PORT),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)), DISCOVERY_PORT),
            ];

            let beacon = BeaconMessage {
                id: sender_self.self_id.clone(),
                name: sender_self.self_name.clone(),
                device_type: sender_self.self_type,
                tcp_port: sender_self.tcp_port,
            };
            let payload = serde_json::to_vec(&beacon).unwrap_or_default();

            loop {
                for addr in &broadcast_addrs {
                    let _ = sender_socket.send_to(&payload, *addr).await;
                }

                // إرسال Unicast دوري لجميع الأجهزة النشطة لضمان ثبات الاتصال على أندرويد
                let known_ips: Vec<SocketAddr> = {
                    let p = sender_self.peers.read().await;
                    p.values()
                        .map(|peer| SocketAddr::new(peer.ip, DISCOVERY_PORT))
                        .collect()
                };
                for target_ip in known_ips {
                    let _ = sender_socket.send_to(&payload, target_ip).await;
                }

                // إضافة تأخير عشوائي خفيف (Jitter 0-400ms) لمنع عواصف البث وتصادم الحزم وتوفير بطارية الهواتف
                let jitter_ms = (uuid::Uuid::new_v4().as_bytes()[0] as u64) % 400;
                tokio::time::sleep(BROADCAST_INTERVAL + Duration::from_millis(jitter_ms)).await;

                // تنظيف الأجهزة غير النشطة دورياً
                let mut peers = sender_self.peers.write().await;
                let now = Instant::now();
                peers.retain(|_, peer| now.duration_since(peer.last_seen) < PEER_TIMEOUT);
            }
        });

        Ok(())
    }

    /// إرجاع قائمة الأجهزة المتصلة حالياً
    pub async fn active_peers(&self) -> Vec<Peer> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }
}

/// استرجاع أو توليد معرف دائم للجهاز مثبت على القرص لضمان ثبات الثقة
pub fn get_or_create_device_id(storage_dir: &Path) -> String {
    let id_file = storage_dir.join("device_id.txt");
    if let Ok(content) = std::fs::read_to_string(&id_file) {
        let trimmed = content.trim();
        if uuid::Uuid::parse_str(trimmed).is_ok() {
            return trimmed.to_string();
        }
    }
    let new_id = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::create_dir_all(storage_dir);
    let _ = std::fs::write(&id_file, &new_id);
    new_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_presence_does_not_trigger_a_reply_loop() {
        let self_id = uuid::Uuid::new_v4().to_string();
        let mut beacon = BeaconMessage {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Phone".into(),
            device_type: DeviceType::Mobile,
            tcp_port: 54125,
        };
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let mut peers = HashMap::new();
        assert!(register_beacon(&mut peers, &self_id, &beacon, ip).needs_reply());
        peers.get_mut(&beacon.id).unwrap().last_seen = Instant::now() - PEER_TIMEOUT;
        for _ in 0..100 {
            assert_eq!(
                register_beacon(&mut peers, &self_id, &beacon, ip),
                BeaconChange::Seen
            );
        }
        assert!(peers[&beacon.id].last_seen.elapsed() < Duration::from_secs(1));
        beacon.tcp_port += 1;
        assert_eq!(
            register_beacon(&mut peers, &self_id, &beacon, ip),
            BeaconChange::EndpointChanged
        );
        assert!(!register_beacon(&mut peers, &self_id, &beacon, ip).needs_reply());
    }

    #[test]
    fn discovery_rejects_invalid_beacons_and_bounds_new_peers() {
        let self_id = uuid::Uuid::new_v4().to_string();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut peers = HashMap::new();
        let mut beacon = BeaconMessage {
            id: "not-a-device-id".into(),
            name: "Phone".into(),
            device_type: DeviceType::Mobile,
            tcp_port: 54125,
        };
        assert_eq!(
            register_beacon(&mut peers, &self_id, &beacon, ip),
            BeaconChange::Rejected
        );
        beacon.id = self_id.clone();
        assert_eq!(
            register_beacon(&mut peers, &self_id, &beacon, ip),
            BeaconChange::Rejected
        );
        beacon.id = uuid::Uuid::new_v4().to_string();
        beacon.tcp_port = 0;
        assert_eq!(
            register_beacon(&mut peers, &self_id, &beacon, ip),
            BeaconChange::Rejected
        );
        beacon.tcp_port = 54125;
        for _ in 0..MAX_DISCOVERED_PEERS {
            beacon.id = uuid::Uuid::new_v4().to_string();
            assert_eq!(
                register_beacon(&mut peers, &self_id, &beacon, ip),
                BeaconChange::New
            );
        }
        let known_id = beacon.id.clone();
        beacon.id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            register_beacon(&mut peers, &self_id, &beacon, ip),
            BeaconChange::Rejected
        );
        beacon.id = known_id;
        assert_eq!(
            register_beacon(&mut peers, &self_id, &beacon, ip),
            BeaconChange::Seen
        );
        assert_eq!(peers.len(), MAX_DISCOVERED_PEERS);
    }

    #[test]
    fn test_persistent_device_id() {
        let temp_dir = std::env::temp_dir().join(format!("flow_dev_id_{}", uuid::Uuid::new_v4()));
        let id1 = get_or_create_device_id(&temp_dir);
        assert_eq!(id1.len(), 36);

        // الاستدعاء الثاني يجب أن يُرجع نفس المعرف تماماً من القرص
        let id2 = get_or_create_device_id(&temp_dir);
        assert_eq!(id1, id2);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
