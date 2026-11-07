//! Native Windows Acrylic with a readable opaque fallback on other platforms.
//!
//! Slint must be configured before creating its first component. The UI then
//! uses the boolean returned by `apply` to decide whether to paint translucent
//! glass or the normal opaque silver surface. No OS preferences are modified.

/// Select Winit and request an alpha-capable window before it is created.
/// Android has already initialized its platform, so this is a no-op there.
pub fn select_backend() -> Result<(), slint::PlatformError> {
    #[cfg(target_os = "windows")]
    {
        use slint::winit_030::winit::platform::windows::{
            BackdropType, CornerPreference, WindowAttributesExtWindows,
        };
        let glass = supported();
        let alpha_capable = windows::backdrop_available();
        slint::BackendSelector::new()
            .backend_name("winit".into())
            .with_winit_window_attributes_hook(move |attributes| {
                attributes
                    .with_transparent(alpha_capable)
                    .with_system_backdrop(if glass {
                        BackdropType::TransientWindow
                    } else {
                        BackdropType::None
                    })
                    .with_corner_preference(CornerPreference::Round)
            })
            .select()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(())
    }
}

/// Whether documented Desktop Acrylic is available and allowed by the user's
/// current accessibility/transparency preferences. This does not create a window.
pub fn supported() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows::supported()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Apply native frame colors and Desktop Acrylic on the UI thread.
///
/// Call after `show()` or from a Winit resize/event callback, when the native
/// window is available. `false` means the UI must use its opaque fallback.
pub fn apply(window: &slint::Window, dark: bool) -> bool {
    #[cfg(target_os = "windows")]
    {
        use slint::winit_030::WinitWindowAccessor;
        window
            .with_winit_window(|native| windows::apply(native, dark))
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (window, dark);
        false
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use slint::winit_030::winit::{
        platform::windows::{Color, CornerPreference, WindowExtWindows},
        raw_window_handle::{HasWindowHandle, RawWindowHandle},
        window::{Theme, Window},
    };
    use std::{ffi::c_void, mem::size_of, ptr, sync::OnceLock};

    const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
    const DWMWA_SYSTEMBACKDROP_TYPE: u32 = 38;
    const DWMWA_REDIRECTIONBITMAP_ALPHA: u32 = 39;
    const DWMSBT_NONE: i32 = 1;
    const DWMSBT_TRANSIENTWINDOW: i32 = 3;

    #[repr(C)]
    struct OsVersionInfo {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        service_pack: [u16; 128],
    }

    #[repr(C)]
    struct HighContrast {
        size: u32,
        flags: u32,
        default_scheme: *mut u16,
    }

    #[repr(C)]
    struct Margins {
        left: i32,
        right: i32,
        top: i32,
        bottom: i32,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn RtlGetVersion(version: *mut OsVersionInfo) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn SystemParametersInfoW(action: u32, param: u32, value: *mut c_void, flags: u32) -> i32;
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            key: *mut c_void,
            subkey: *const u16,
            value: *const u16,
            flags: u32,
            value_type: *mut u32,
            data: *mut c_void,
            size: *mut u32,
        ) -> i32;
    }
    #[link(name = "dwmapi")]
    extern "system" {
        fn DwmSetWindowAttribute(
            window: *mut c_void,
            attribute: u32,
            value: *const c_void,
            size: u32,
        ) -> i32;
        fn DwmExtendFrameIntoClientArea(window: *mut c_void, margins: *const Margins) -> i32;
        fn DwmIsCompositionEnabled(enabled: *mut i32) -> i32;
    }

    fn build_number() -> u32 {
        static BUILD: OnceLock<u32> = OnceLock::new();
        *BUILD.get_or_init(|| {
            let mut version = OsVersionInfo {
                size: size_of::<OsVersionInfo>() as u32,
                major: 0,
                minor: 0,
                build: 0,
                platform: 0,
                service_pack: [0; 128],
            };
            // RtlGetVersion reports the real version independently of app manifests.
            if unsafe { RtlGetVersion(&mut version) } >= 0 && version.major >= 10 {
                version.build
            } else {
                0
            }
        })
    }

    fn transparency_allowed() -> bool {
        let mut contrast = HighContrast {
            size: size_of::<HighContrast>() as u32,
            flags: 0,
            default_scheme: ptr::null_mut(),
        };
        // SPI_GETHIGHCONTRAST / HCF_HIGHCONTRASTON. Fall back if this query fails.
        if unsafe {
            SystemParametersInfoW(
                0x0042,
                contrast.size,
                (&mut contrast as *mut HighContrast).cast(),
                0,
            )
        } == 0
            || contrast.flags & 1 != 0
        {
            return false;
        }
        let path: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\0"
            .encode_utf16()
            .collect();
        let name: Vec<u16> = "EnableTransparency\0".encode_utf16().collect();
        let mut enabled: u32 = 1;
        let mut length = size_of::<u32>() as u32;
        // HKEY_CURRENT_USER; RRF_RT_REG_DWORD. A missing preference uses Windows' default.
        let status = unsafe {
            RegGetValueW(
                (-2_147_483_647isize) as *mut c_void,
                path.as_ptr(),
                name.as_ptr(),
                0x0000_0018,
                ptr::null_mut(),
                (&mut enabled as *mut u32).cast(),
                &mut length,
            )
        };
        status != 0 || enabled != 0
    }

    pub(super) fn supported() -> bool {
        let mut composition = 0;
        // DWMWA_SYSTEMBACKDROP_TYPE is documented from Windows 11 22H2 / 22621.
        backdrop_available()
            && transparency_allowed()
            && unsafe { DwmIsCompositionEnabled(&mut composition) } >= 0
            && composition != 0
    }

    pub(super) fn backdrop_available() -> bool {
        build_number() >= 22621
    }

    fn set_attribute<T>(window: *mut c_void, attribute: u32, value: &T) -> bool {
        // The attribute/value pairs below use the exact documented BOOL/DWORD types.
        unsafe {
            DwmSetWindowAttribute(
                window,
                attribute,
                (value as *const T).cast(),
                size_of::<T>() as u32,
            ) >= 0
        }
    }

    pub(super) fn apply(native: &Window, dark: bool) -> bool {
        native.set_theme(Some(if dark { Theme::Dark } else { Theme::Light }));
        native.set_corner_preference(CornerPreference::Round);
        native.set_border_color(Some(if dark {
            Color::from_rgb(87, 95, 104)
        } else {
            Color::from_rgb(171, 178, 187)
        }));
        // Let DWM blend its own caption into the backdrop rather than painting a solid strip.
        native.set_title_background_color(None);
        native.set_title_text_color(if dark {
            Color::from_rgb(231, 234, 238)
        } else {
            Color::from_rgb(34, 39, 46)
        });
        let Ok(handle) = native.window_handle() else {
            return false;
        };
        let RawWindowHandle::Win32(handle) = handle.as_raw() else {
            return false;
        };
        let hwnd = handle.hwnd.get() as *mut c_void;
        let allowed = supported();
        let enabled: i32 = i32::from(dark);
        set_attribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &enabled);
        let material = if allowed {
            DWMSBT_TRANSIENTWINDOW
        } else {
            DWMSBT_NONE
        };
        let backdrop_ok = set_attribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &material);
        let margin = if allowed && backdrop_ok { -1 } else { 0 };
        let margins = Margins {
            left: margin,
            right: margin,
            top: margin,
            bottom: margin,
        };
        let frame_ok = unsafe { DwmExtendFrameIntoClientArea(hwnd, &margins) } >= 0;
        if allowed && build_number() >= 26100 {
            // Windows 11 24H2 adds an explicit premultiplied-alpha redirection switch.
            let alpha: i32 = 1;
            set_attribute(hwnd, DWMWA_REDIRECTIONBITMAP_ALPHA, &alpha);
        }
        allowed && backdrop_ok && frame_ok
    }
}
