#[cfg(not(target_os = "android"))]
use arboard::Clipboard;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct ClipboardManager {
    running: Arc<AtomicBool>,
}

impl ClipboardManager {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// قراءة محتوى الحافظة الحالي
    pub fn read_current() -> Option<String> {
        #[cfg(not(target_os = "android"))]
        {
            let mut clipboard = Clipboard::new().ok()?;
            clipboard.get_text().ok()
        }
        #[cfg(target_os = "android")]
        {
            None
        }
    }

    /// التحقق مما إذا كانت الحافظة تحتوي على صورة ممسوحة (لقطة شاشة)
    pub fn read_current_image_bytes() -> Option<(usize, usize, Vec<u8>)> {
        #[cfg(not(target_os = "android"))]
        {
            let mut clipboard = Clipboard::new().ok()?;
            let img = clipboard.get_image().ok()?;
            Some((img.width, img.height, img.bytes.into_owned()))
        }
        #[cfg(target_os = "android")]
        {
            None
        }
    }

    /// تعيين نص جديد في الحافظة
    pub fn set_text(text: &str) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(target_os = "android"))]
        {
            let mut clipboard = Clipboard::new()?;
            clipboard.set_text(text)?;
            Ok(())
        }
        #[cfg(target_os = "android")]
        {
            let _ = text;
            Ok(())
        }
    }

    /// تعيين صورة في الحافظة
    pub fn set_image(width: usize, height: usize, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(not(target_os = "android"))]
        {
            let mut clipboard = Clipboard::new()?;
            clipboard.set_image(arboard::ImageData {
                width,
                height,
                bytes: std::borrow::Cow::Borrowed(data),
            })?;
            Ok(())
        }
        #[cfg(target_os = "android")]
        {
            let _ = (width, height, data);
            Ok(())
        }
    }

    /// بدء مراقبة الحافظة في الخلفية مع التعافي التلقائي من أقفال نظام التشغيل (Anti-Zombie Thread)
    pub fn start_monitoring(&self, tx: mpsc::UnboundedSender<String>) {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        #[cfg(not(target_os = "android"))]
        std::thread::spawn(move || {
            let mut last_content = String::new();

            while running.load(Ordering::SeqCst) {
                // حماية ضد فشل فتح الحافظة المؤقت أو حجزها من تطبيقات أخرى (مثل Excel أو إدارة كلمات المرور)
                let mut clipboard = match Clipboard::new() {
                    Ok(cb) => cb,
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        continue;
                    }
                };

                while running.load(Ordering::SeqCst) {
                    match clipboard.get_text() {
                        Ok(current) => {
                            if !current.is_empty() && current != last_content {
                                last_content = current.clone();
                                let _ = tx.send(current);
                            }
                        }
                        Err(_) => {
                            // قفل مؤقت للحافظة من قبل تطبيق آخر في نظام التشغيل - نعيد المحاولة بسلاسة
                            std::thread::sleep(std::time::Duration::from_millis(400));
                            break;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(600));
                }
            }
        });

        #[cfg(target_os = "android")]
        {
            let _ = tx;
        }
    }

    #[allow(dead_code)]
    pub fn stop_monitoring(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Default for ClipboardManager {
    fn default() -> Self {
        Self::new()
    }
}
