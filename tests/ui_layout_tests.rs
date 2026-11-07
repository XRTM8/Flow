//! Exercise actual layout and CPU rendering, not just Slint compilation.
//! Intrinsic-size binding cycles can compile successfully and panic only here.
use otium_flow::{AppState, AppWindow, FilePickerItem, HistoryItem, PeerItem, TransferItem};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, PhysicalSize, Rgb8Pixel, VecModel};
use std::rc::Rc;

thread_local! {
    static WINDOW: Rc<MinimalSoftwareWindow> =
        MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
}

struct HeadlessPlatform;

impl Platform for HeadlessPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(WINDOW.with(Rc::clone))
    }
}

fn model<T: Clone + 'static>(rows: Vec<T>) -> ModelRc<T> {
    Rc::new(VecModel::from(rows)).into()
}

#[derive(Clone, Copy, Debug)]
enum Page {
    Home,
    Devices,
    Settings,
    History,
    Pairing,
    FileBrowser,
    ReceivedFiles,
}

fn select_page(state: &AppState<'_>, page: Page) {
    state.set_show_devices(matches!(page, Page::Devices));
    state.set_show_settings(matches!(page, Page::Settings));
    state.set_show_history(matches!(page, Page::History));
    state.set_show_pairing(matches!(page, Page::Pairing));
    state.set_show_file_picker(matches!(page, Page::FileBrowser | Page::ReceivedFiles));
    state.set_browser_read_only(matches!(page, Page::ReceivedFiles));
}

fn draw_frame(window: &MinimalSoftwareWindow, width: u32, height: u32, context: &str) {
    window.set_size(PhysicalSize::new(width, height));
    slint::platform::update_timers_and_animations();
    window.request_redraw();
    let mut pixels = vec![Rgb8Pixel::default(); width as usize * height as usize];
    // Print the scenario before evaluating layout, so any recursion panic has context.
    eprintln!("Rendering {context}");
    let drew = window.draw_if_needed(|renderer| {
        renderer.render(pixels.as_mut_slice(), width as usize);
    });
    assert!(drew, "No frame was rendered for {context}");
    assert!(
        pixels.iter().any(|p| p.r != 0 || p.g != 0 || p.b != 0),
        "The rendered frame was empty for {context}"
    );
}

fn populate_content(state: &AppState<'_>) {
    let filename =
        "تقرير المشروع ومرفقات المراجعة النهائية — a-long-file-name-without-a-shortcut.pdf";
    state.set_selected_peer_id("11111111-1111-4111-8111-111111111111".into());
    state.set_peer_name("هاتف العمل — A device with a deliberately long descriptive name".into());
    state.set_connection_status("تم التحقق من الجهاز على الشبكة المحلية — Ready to send".into());
    state.set_is_connected(true);
    state.set_connection_busy(false);
    state.set_connection_failed(false);
    state.set_peers(model(vec![
        PeerItem {
            id: "11111111-1111-4111-8111-111111111111".into(),
            name: "هاتف العمل — A device with a deliberately long descriptive name".into(),
            kind: "mobile".into(),
            selected: true,
            trusted: true,
        },
        PeerItem {
            id: "22222222-2222-4222-8222-222222222222".into(),
            name: "حاسوب آخر على الشبكة المحلية".into(),
            kind: "desktop".into(),
            selected: false,
            trusted: false,
        },
    ]));
    state.set_trusted_devices(model(vec![PeerItem {
        id: "33333333-3333-4333-8333-333333333333".into(),
        name: "جهاز مقترن غير متصل حاليًا — Offline paired device".into(),
        kind: "desktop".into(),
        selected: false,
        trusted: true,
    }]));
    state.set_draft_text(
        "رسالة متعددة الأسطر مع رابط واسم ملف طويل.\nhttps://example.invalid/a/very/long/path?view=preview\nA note that exercises mixed Arabic and Latin text wrapping."
            .into(),
    );
    state.set_clipboard_text(
        "نص مستلم يمكن تحديده ونسخه.\nA received message with enough content to wrap onto several lines on a small screen."
            .into(),
    );
    state.set_notice("تعذر إرسال أحد الملفات. تحقق من الجهاز المستلم ثم أعد المحاولة — A deliberately long actionable error message.".into());
    state.set_notice_error(true);
    state.set_transfers(model(vec![
        TransferItem {
            id: "active-layout-test".into(),
            title: filename.into(),
            detail: "12 MB / 40 MB · 5.2 MB/s · 6 ث متبقية".into(),
            progress: 0.3,
            status: "sending".into(),
            direction: "sent".into(),
            can_cancel: true,
        },
        TransferItem {
            id: "failed-layout-test".into(),
            title: "مستند لم يكتمل إرساله — Failed document.txt".into(),
            detail: "انقطع الاتصال بالجهاز المستلم. أعد المحاولة عندما يصبح متاحًا.".into(),
            progress: 0.55,
            status: "failed".into(),
            direction: "sent".into(),
            can_cancel: false,
        },
    ]));
    state.set_history_items(model(vec![
        HistoryItem {
            id: "history-file".into(),
            kind: "file".into(),
            title: filename.into(),
            subtitle: "مستلم · هاتف العمل · تم الاستلام والتحقق".into(),
            timestamp: "قبل دقيقتين".into(),
            success: true,
            action_label: "فتح الملف".into(),
        },
        HistoryItem {
            id: "history-failure".into(),
            kind: "text".into(),
            title: "رسالة لم يكتمل إرسالها".into(),
            subtitle: "تعذر الاتصال بالجهاز المختار — Connection unavailable".into(),
            timestamp: "قبل ساعة".into(),
            success: false,
            action_label: "نسخ النص".into(),
        },
    ]));
    state.set_download_path(
        "/storage/emulated/0/Android/data/org.otium.flow/files/Download/Flow".into(),
    );
    // Fixed synthetic values, never user pairing credentials.
    state.set_pairing_code(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
    );
    state
        .set_pair_secret("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".into());
    state.set_pairing_busy(false);
    state.set_browser_path("/storage/emulated/0/Download/a-folder-with-a-long-name".into());
    state.set_browser_can_up(true);
    state.set_browser_selection_count(1);
    state.set_browser_items(model(vec![
        FilePickerItem {
            path: "/storage/emulated/0/Download/مجلد المستندات".into(),
            name: "مجلد المستندات والمرفقات — Documents".into(),
            detail: "".into(),
            is_dir: true,
            selected: false,
        },
        FilePickerItem {
            path: "/storage/emulated/0/Download/report.pdf".into(),
            name: filename.into(),
            detail: "24.8 MB".into(),
            is_dir: false,
            selected: true,
        },
    ]));
}

#[test]
fn every_page_renders_without_recursive_layout_at_desktop_and_phone_sizes() {
    slint::platform::set_platform(Box::new(HeadlessPlatform))
        .expect("The headless rendering test owns its platform");
    let window = WINDOW.with(Rc::clone);
    let ui = AppWindow::new().expect("Create the real Flow component");
    ui.show().expect("Show the software-only window");
    for (width, height, mobile, language) in [
        (920, 690, false, "EN"),
        (920, 690, false, "AR"),
        (390, 820, true, "AR"),
    ] {
        let state = ui.global::<AppState>();
        state.set_mobile_mode(mobile);
        state.set_compact_mode(mobile);
        state.set_lang(language.into());
        state.set_native_glass(false);
        for dark in [false, true] {
            state.set_dark_mode(dark);
            state.set_peers(model(Vec::<PeerItem>::new()));
            state.set_trusted_devices(model(Vec::<PeerItem>::new()));
            state.set_history_items(model(Vec::<HistoryItem>::new()));
            state.set_transfers(model(Vec::<TransferItem>::new()));
            state.set_browser_items(model(Vec::<FilePickerItem>::new()));
            state.set_browser_selection_count(0);
            state.set_selected_peer_id("".into());
            state.set_peer_name("".into());
            state.set_is_connected(false);
            state.set_notice("".into());
            state.set_notice_error(false);
            state.set_draft_text("".into());
            state.set_clipboard_text("".into());
            for page in [
                Page::Home,
                Page::Devices,
                Page::Settings,
                Page::History,
                Page::Pairing,
                Page::FileBrowser,
                Page::ReceivedFiles,
            ] {
                select_page(&state, page);
                draw_frame(
                    &window,
                    width,
                    height,
                    &format!("{width}x{height} {language} dark={dark} empty {page:?}"),
                );
            }
            populate_content(&state);
            for page in [
                Page::Home,
                Page::Devices,
                Page::Settings,
                Page::History,
                Page::Pairing,
                Page::FileBrowser,
                Page::ReceivedFiles,
            ] {
                select_page(&state, page);
                draw_frame(
                    &window,
                    width,
                    height,
                    &format!("{width}x{height} {language} dark={dark} {page:?}"),
                );
            }
        }
    }
    ui.hide().expect("Hide the headless window");
}
