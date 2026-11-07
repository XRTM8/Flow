//! Small, native OS integrations shared by both application layouts.
//!
//! Android uses JNI from Rust. Its file picker is the Slint browser: a plain
//! NativeActivity does not receive Android Activity result callbacks.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// List one directory, rather than scanning the whole device in the background.
pub fn list_files(path: &Path) -> Result<Vec<FileEntry>, String> {
    let entries =
        std::fs::read_dir(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("Cannot read this folder: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        // Do not navigate symlinks into private or unexpected locations.
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_symlink() || (!kind.is_dir() && !kind.is_file()) {
            continue;
        }
        files.push(FileEntry {
            path: entry.path(),
            name,
            is_dir: kind.is_dir(),
            size: if kind.is_file() {
                entry.metadata().map_err(|e| e.to_string())?.len()
            } else {
                0
            },
        });
    }
    files.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(files)
}

pub fn storage_root() -> Result<PathBuf, String> {
    #[cfg(target_os = "android")]
    {
        android::storage_root()
    }
    #[cfg(not(target_os = "android"))]
    {
        home_dir()
    }
}

/// Private application state. Never keep keys or trust records in Downloads.
pub fn app_data_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "android")]
    let directory = android::app_data_dir()?;
    #[cfg(target_os = "windows")]
    let directory = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or("Windows did not provide an application data folder")?
        .join("Otium")
        .join("Flow");
    #[cfg(target_os = "macos")]
    let directory = home_dir()?.join("Library/Application Support/OtiumFlow");
    #[cfg(all(
        not(target_os = "android"),
        not(target_os = "windows"),
        not(target_os = "macos")
    ))]
    let directory = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or(home_dir()?.join(".local/share"))
        .join("otium-flow");
    ensure_directory(directory)
}

/// Receive files into an actually writable folder. On Android this is Flow's
/// app-specific external Download folder; it is not public system Downloads.
pub fn downloads_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "android")]
    let directory = android::downloads_dir()?;
    #[cfg(target_os = "windows")]
    let directory = windows_downloads_dir()?.join("OtiumFlow");
    #[cfg(all(not(target_os = "android"), not(target_os = "windows")))]
    let directory = home_dir()?.join("Downloads").join("OtiumFlow");
    let directory = ensure_directory(directory)?;
    let probe = directory.join(format!(".flow-write-{}", uuid::Uuid::new_v4()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|e| format!("Cannot save received files in {}: {e}", directory.display()))?;
    drop(file);
    std::fs::remove_file(probe).map_err(|e| e.to_string())?;
    Ok(directory)
}

fn ensure_directory(directory: PathBuf) -> Result<PathBuf, String> {
    std::fs::create_dir_all(&directory)
        .map_err(|e| format!("Cannot create {}: {e}", directory.display()))?;
    Ok(directory)
}

#[cfg(not(target_os = "android"))]
fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os(if cfg!(target_os = "windows") {
        "USERPROFILE"
    } else {
        "HOME"
    })
    .map(PathBuf::from)
    .ok_or_else(|| "The system did not provide a home folder".to_string())
}

#[cfg(target_os = "windows")]
fn windows_downloads_dir() -> Result<PathBuf, String> {
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::OsStringExt;

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetKnownFolderPath(
            folder: *const Guid,
            flags: u32,
            token: *mut c_void,
            path: *mut *mut u16,
        ) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(memory: *mut c_void);
    }
    let downloads = Guid {
        data1: 0x374DE290,
        data2: 0x123F,
        data3: 0x4565,
        data4: [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B],
    };
    let mut raw = std::ptr::null_mut();
    // The Shell allocates a null-terminated UTF-16 path. Respect redirected
    // Downloads locations instead of creating a second USERPROFILE/Downloads.
    let status = unsafe { SHGetKnownFolderPath(&downloads, 0, std::ptr::null_mut(), &mut raw) };
    if status < 0 || raw.is_null() {
        return Err(format!(
            "Windows could not locate Downloads (0x{:08X})",
            status as u32
        ));
    }
    let mut length = 0;
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
        let path = OsString::from_wide(std::slice::from_raw_parts(raw, length));
        CoTaskMemFree(raw.cast());
        Ok(PathBuf::from(path))
    }
}

pub async fn pick_files() -> Result<Vec<PathBuf>, String> {
    #[cfg(not(target_os = "android"))]
    {
        Ok(rfd::AsyncFileDialog::new()
            .set_title("Select files to send")
            .pick_files()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|file| file.path().to_path_buf())
            .collect())
    }
    #[cfg(target_os = "android")]
    {
        Err("Use Flow's file browser to select files on Android".into())
    }
}

/// This is only called by the user's explicit storage-access action.
pub fn request_storage_access() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        android::request_storage_access()
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(())
    }
}

pub fn has_storage_access() -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        android::has_storage_access()
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(true)
    }
}

pub fn open_path(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err("This file or folder no longer exists".into());
    }
    #[cfg(target_os = "android")]
    {
        android::open_path(path)
    }
    #[cfg(not(target_os = "android"))]
    {
        let program = if cfg!(target_os = "windows") {
            "explorer.exe"
        } else if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        std::process::Command::new(program)
            .arg(path)
            .spawn()
            .map_err(|e| format!("Cannot open this item: {e}"))?;
        Ok(())
    }
}

/// Android's explicit "Save copy" action publishes a copy in public Downloads
/// before asking another app to view it. Other platforms open the existing file.
pub fn export_and_open_file(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        android::export_and_open_file(path)
    }
    #[cfg(not(target_os = "android"))]
    {
        open_path(path)
    }
}

/// Physical Android inset pixels converted to Slint logical pixels. Insets can
/// be unavailable before the first window frame, so callers refresh after show.
pub fn safe_insets() -> (f32, f32) {
    #[cfg(target_os = "android")]
    {
        android::safe_insets().unwrap_or_default()
    }
    #[cfg(not(target_os = "android"))]
    {
        (0.0, 0.0)
    }
}

pub fn open_url(url: &str) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Only HTTP and HTTPS links can be opened".into());
    }
    #[cfg(target_os = "android")]
    {
        android::open_url(url)
    }
    #[cfg(not(target_os = "android"))]
    {
        #[cfg(target_os = "windows")]
        let mut command = {
            let mut command = std::process::Command::new("rundll32.exe");
            command.arg("url.dll,FileProtocolHandler");
            command
        };
        #[cfg(not(target_os = "windows"))]
        let mut command = std::process::Command::new(if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        });
        command
            .arg(url)
            .spawn()
            .map_err(|e| format!("Cannot open this link: {e}"))?;
        Ok(())
    }
}

#[cfg(target_os = "android")]
pub(crate) mod android {
    use super::*;
    use jni::objects::{JObject, JString, JValue};
    use jni::JNIEnv;

    fn jni_error(error: jni::errors::Error) -> String {
        format!("Android could not complete this action: {error}")
    }

    /// Borrow the activity global reference only for this attached thread and
    /// release every local JNI reference at the end of the operation.
    fn with_activity<T>(
        action: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let context = ndk_context::android_context();
        if context.vm().is_null() || context.context().is_null() {
            return Err("Android activity is unavailable".into());
        }
        let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }.map_err(jni_error)?;
        let mut env = vm.attach_current_thread().map_err(jni_error)?;
        env.push_local_frame(64).map_err(jni_error)?;
        // ndk-context owns this global reference. JObject does not delete it.
        let activity = unsafe { JObject::from_raw(context.context().cast()) };
        let result = action(&mut env, &activity);
        let exception = env.exception_check().map_err(jni_error)?;
        if exception {
            env.exception_clear().map_err(jni_error)?;
        }
        unsafe { env.pop_local_frame(&JObject::null()) }.map_err(jni_error)?;
        if exception {
            Err(result
                .err()
                .unwrap_or_else(|| "Android rejected this action".into()))
        } else {
            result
        }
    }

    fn sdk_version(env: &mut JNIEnv<'_>) -> Result<i32, String> {
        env.get_static_field("android/os/Build$VERSION", "SDK_INT", "I")
            .and_then(|v| v.i())
            .map_err(jni_error)
    }

    fn file_path(env: &mut JNIEnv<'_>, file: JObject<'_>) -> Result<PathBuf, String> {
        if file.is_null() {
            return Err("Android did not provide a storage folder".into());
        }
        let path = env
            .call_method(file, "getAbsolutePath", "()Ljava/lang/String;", &[])
            .and_then(|v| v.l())
            .map_err(jni_error)?;
        let path: String = env
            .get_string(&JString::from(path))
            .map_err(jni_error)?
            .into();
        Ok(PathBuf::from(path))
    }

    pub fn app_data_dir() -> Result<PathBuf, String> {
        with_activity(|env, activity| {
            let file = env
                .call_method(activity, "getFilesDir", "()Ljava/io/File;", &[])
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            file_path(env, file)
        })
    }

    pub fn downloads_dir() -> Result<PathBuf, String> {
        with_activity(|env, activity| {
            let kind = env.new_string("Download").map_err(jni_error)?;
            let file = env
                .call_method(
                    activity,
                    "getExternalFilesDir",
                    "(Ljava/lang/String;)Ljava/io/File;",
                    &[JValue::Object(&kind)],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            if file.is_null() {
                let internal = env
                    .call_method(activity, "getFilesDir", "()Ljava/io/File;", &[])
                    .and_then(|v| v.l())
                    .map_err(jni_error)?;
                return Ok(file_path(env, internal)?.join("received"));
            }
            file_path(env, file)
        })
    }

    pub fn storage_root() -> Result<PathBuf, String> {
        with_activity(|env, _| {
            let file = env
                .call_static_method(
                    "android/os/Environment",
                    "getExternalStorageDirectory",
                    "()Ljava/io/File;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            file_path(env, file)
        })
    }

    pub fn has_storage_access() -> Result<bool, String> {
        with_activity(|env, activity| {
            if sdk_version(env)? >= 30 {
                env.call_static_method(
                    "android/os/Environment",
                    "isExternalStorageManager",
                    "()Z",
                    &[],
                )
                .and_then(|v| v.z())
                .map_err(jni_error)
            } else {
                let permission = env
                    .new_string("android.permission.READ_EXTERNAL_STORAGE")
                    .map_err(jni_error)?;
                env.call_method(
                    activity,
                    "checkSelfPermission",
                    "(Ljava/lang/String;)I",
                    &[JValue::Object(&permission)],
                )
                .and_then(|v| v.i())
                .map(|value| value == 0)
                .map_err(jni_error)
            }
        })
    }

    pub fn request_storage_access() -> Result<(), String> {
        with_activity(|env, activity| {
            if sdk_version(env)? >= 30 {
                let package = env
                    .call_method(activity, "getPackageName", "()Ljava/lang/String;", &[])
                    .and_then(|v| v.l())
                    .map_err(jni_error)?;
                let package: String = env
                    .get_string(&JString::from(package))
                    .map_err(jni_error)?
                    .into();
                let uri_text = env
                    .new_string(format!("package:{package}"))
                    .map_err(jni_error)?;
                let uri = env
                    .call_static_method(
                        "android/net/Uri",
                        "parse",
                        "(Ljava/lang/String;)Landroid/net/Uri;",
                        &[JValue::Object(&uri_text)],
                    )
                    .and_then(|v| v.l())
                    .map_err(jni_error)?;
                let action = env
                    .new_string("android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION")
                    .map_err(jni_error)?;
                let intent = env
                    .new_object(
                        "android/content/Intent",
                        "(Ljava/lang/String;Landroid/net/Uri;)V",
                        &[JValue::Object(&action), JValue::Object(&uri)],
                    )
                    .map_err(jni_error)?;
                env.call_method(
                    activity,
                    "startActivity",
                    "(Landroid/content/Intent;)V",
                    &[JValue::Object(&intent)],
                )
                .map_err(jni_error)?;
            } else {
                let permissions = env
                    .new_object_array(2, "java/lang/String", JObject::null())
                    .map_err(jni_error)?;
                for (index, name) in [
                    "android.permission.READ_EXTERNAL_STORAGE",
                    "android.permission.WRITE_EXTERNAL_STORAGE",
                ]
                .iter()
                .enumerate()
                {
                    let value = env.new_string(name).map_err(jni_error)?;
                    env.set_object_array_element(&permissions, index as i32, value)
                        .map_err(jni_error)?;
                }
                env.call_method(
                    activity,
                    "requestPermissions",
                    "([Ljava/lang/String;I)V",
                    &[JValue::Object(&permissions), JValue::Int(4101)],
                )
                .map_err(jni_error)?;
            }
            Ok(())
        })
    }

    pub fn read_clipboard() -> Result<Option<String>, String> {
        with_activity(|env, activity| {
            let focused = env
                .call_method(activity, "hasWindowFocus", "()Z", &[])
                .and_then(|v| v.z())
                .map_err(jni_error)?;
            if !focused {
                return Err("Open Flow and tap Paste to read the clipboard".into());
            }
            let name = env.new_string("clipboard").map_err(jni_error)?;
            let manager = env
                .call_method(
                    activity,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[JValue::Object(&name)],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let clip = env
                .call_method(
                    manager,
                    "getPrimaryClip",
                    "()Landroid/content/ClipData;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            if clip.is_null() {
                return Ok(None);
            }
            let count = env
                .call_method(&clip, "getItemCount", "()I", &[])
                .and_then(|v| v.i())
                .map_err(jni_error)?;
            if count == 0 {
                return Ok(None);
            }
            let item = env
                .call_method(
                    clip,
                    "getItemAt",
                    "(I)Landroid/content/ClipData$Item;",
                    &[JValue::Int(0)],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            // getText avoids unexpectedly resolving a URI or copying a binary
            // payload when the user asked to paste text.
            let text = env
                .call_method(item, "getText", "()Ljava/lang/CharSequence;", &[])
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            if text.is_null() {
                return Ok(None);
            }
            let string = env
                .call_method(text, "toString", "()Ljava/lang/String;", &[])
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let string: String = env
                .get_string(&JString::from(string))
                .map_err(jni_error)?
                .into();
            Ok(Some(string))
        })
    }

    pub fn copy_text(text: &str) -> Result<(), String> {
        with_activity(|env, activity| {
            let name = env.new_string("clipboard").map_err(jni_error)?;
            let manager = env
                .call_method(
                    activity,
                    "getSystemService",
                    "(Ljava/lang/String;)Ljava/lang/Object;",
                    &[JValue::Object(&name)],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let label = env.new_string("Flow").map_err(jni_error)?;
            let text = env.new_string(text).map_err(jni_error)?;
            let clip = env
                .call_static_method(
                    "android/content/ClipData",
                    "newPlainText",
                    "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;",
                    &[JValue::Object(&label), JValue::Object(&text)],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            env.call_method(
                manager,
                "setPrimaryClip",
                "(Landroid/content/ClipData;)V",
                &[JValue::Object(&clip)],
            )
            .map_err(jni_error)?;
            Ok(())
        })
    }

    pub fn open_url(url: &str) -> Result<(), String> {
        with_activity(|env, activity| {
            let value = env.new_string(url).map_err(jni_error)?;
            let uri = env
                .call_static_method(
                    "android/net/Uri",
                    "parse",
                    "(Ljava/lang/String;)Landroid/net/Uri;",
                    &[JValue::Object(&value)],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let action = env
                .new_string("android.intent.action.VIEW")
                .map_err(jni_error)?;
            let intent = env
                .new_object(
                    "android/content/Intent",
                    "(Ljava/lang/String;Landroid/net/Uri;)V",
                    &[JValue::Object(&action), JValue::Object(&uri)],
                )
                .map_err(jni_error)?;
            env.call_method(
                activity,
                "startActivity",
                "(Landroid/content/Intent;)V",
                &[JValue::Object(&intent)],
            )
            .map_err(jni_error)?;
            Ok(())
        })
    }

    pub fn open_path(_path: &Path) -> Result<(), String> {
        // Android requires a grantable content URI. Never pretend a file://
        // intent works: other apps cannot read Flow's app-specific files.
        Err("Use Flow's files list to select and send this item. Opening it in another Android app requires a content provider.".into())
    }

    fn put_string(
        env: &mut JNIEnv<'_>,
        values: &JObject<'_>,
        name: &str,
        value: &str,
    ) -> Result<(), String> {
        let name = env.new_string(name).map_err(jni_error)?;
        let value = env.new_string(value).map_err(jni_error)?;
        env.call_method(
            values,
            "put",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            &[JValue::Object(&name), JValue::Object(&value)],
        )
        .map_err(jni_error)?;
        Ok(())
    }

    fn put_int(
        env: &mut JNIEnv<'_>,
        values: &JObject<'_>,
        name: &str,
        value: i32,
    ) -> Result<(), String> {
        let name = env.new_string(name).map_err(jni_error)?;
        let value = env
            .call_static_method(
                "java/lang/Integer",
                "valueOf",
                "(I)Ljava/lang/Integer;",
                &[JValue::Int(value)],
            )
            .and_then(|v| v.l())
            .map_err(jni_error)?;
        env.call_method(
            values,
            "put",
            "(Ljava/lang/String;Ljava/lang/Integer;)V",
            &[JValue::Object(&name), JValue::Object(&value)],
        )
        .map_err(jni_error)?;
        Ok(())
    }

    pub fn export_and_open_file(path: &Path) -> Result<(), String> {
        use std::os::fd::FromRawFd;

        if !path.is_file() {
            return Err("Select an existing file to save a copy".into());
        }
        let mut source =
            std::fs::File::open(path).map_err(|e| format!("Cannot read this file: {e}"))?;
        let name = path
            .file_name()
            .ok_or("This file has no name")?
            .to_string_lossy()
            .into_owned();
        let extension = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        with_activity(|env, activity| {
            if sdk_version(env)? < 29 {
                return Err("Saving a public copy from Flow requires Android 10 or later. The received file remains in Flow's files.".into());
            }
            let map = env
                .call_static_method(
                    "android/webkit/MimeTypeMap",
                    "getSingleton",
                    "()Landroid/webkit/MimeTypeMap;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let extension = env.new_string(extension).map_err(jni_error)?;
            let mime = env
                .call_method(
                    map,
                    "getMimeTypeFromExtension",
                    "(Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(&extension)],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let mime: String = if mime.is_null() {
                "application/octet-stream".into()
            } else {
                env.get_string(&JString::from(mime))
                    .map_err(jni_error)?
                    .into()
            };
            let resolver = env
                .call_method(
                    activity,
                    "getContentResolver",
                    "()Landroid/content/ContentResolver;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let collection = env
                .get_static_field(
                    "android/provider/MediaStore$Downloads",
                    "EXTERNAL_CONTENT_URI",
                    "Landroid/net/Uri;",
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let values = env
                .new_object("android/content/ContentValues", "()V", &[])
                .map_err(jni_error)?;
            put_string(env, &values, "_display_name", &name)?;
            put_string(env, &values, "mime_type", &mime)?;
            put_string(env, &values, "relative_path", "Download/Flow")?;
            put_int(env, &values, "is_pending", 1)?;
            let uri = env
                .call_method(
                    &resolver,
                    "insert",
                    "(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;",
                    &[JValue::Object(&collection), JValue::Object(&values)],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            if uri.is_null() {
                return Err("Android could not create a copy in Downloads/Flow".into());
            }
            let mut published = false;
            let result = (|| {
                let mode = env.new_string("w").map_err(jni_error)?;
                let parcel = env
                    .call_method(
                        &resolver,
                        "openFileDescriptor",
                        "(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;",
                        &[JValue::Object(&uri), JValue::Object(&mode)],
                    )
                    .and_then(|v| v.l())
                    .map_err(jni_error)?;
                if parcel.is_null() {
                    return Err("Android could not open the new copy for writing".into());
                }
                let fd = env
                    .call_method(parcel, "detachFd", "()I", &[])
                    .and_then(|v| v.i())
                    .map_err(jni_error)?;
                if fd < 0 {
                    return Err("Android returned an invalid file descriptor".into());
                }
                // detachFd transfers ownership to Rust; File closes it on all
                // success/error paths. Copy in chunks without loading the file.
                let mut output = unsafe { std::fs::File::from_raw_fd(fd) };
                std::io::copy(&mut source, &mut output)
                    .map_err(|e| format!("Cannot save the complete copy: {e}"))?;
                output
                    .sync_all()
                    .map_err(|e| format!("Cannot finish saving the copy: {e}"))?;
                drop(output);
                let complete = env
                    .new_object("android/content/ContentValues", "()V", &[])
                    .map_err(jni_error)?;
                put_int(env, &complete, "is_pending", 0)?;
                let changed = env.call_method(&resolver, "update", "(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I", &[JValue::Object(&uri), JValue::Object(&complete), JValue::Object(&JObject::null()), JValue::Object(&JObject::null())])
                    .and_then(|v| v.i()).map_err(jni_error)?;
                if changed != 1 {
                    return Err("Android could not publish the completed copy".into());
                }
                published = true;
                let action = env
                    .new_string("android.intent.action.VIEW")
                    .map_err(jni_error)?;
                let intent = env
                    .new_object(
                        "android/content/Intent",
                        "(Ljava/lang/String;)V",
                        &[JValue::Object(&action)],
                    )
                    .map_err(jni_error)?;
                let mime = env.new_string(mime).map_err(jni_error)?;
                env.call_method(
                    &intent,
                    "setDataAndType",
                    "(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;",
                    &[JValue::Object(&uri), JValue::Object(&mime)],
                )
                .map_err(jni_error)?;
                env.call_method(
                    &intent,
                    "addFlags",
                    "(I)Landroid/content/Intent;",
                    &[JValue::Int(1)],
                )
                .map_err(jni_error)?; // FLAG_GRANT_READ_URI_PERMISSION
                env.call_method(
                    activity,
                    "startActivity",
                    "(Landroid/content/Intent;)V",
                    &[JValue::Object(&intent)],
                )
                .map_err(|_| {
                    "Copy saved in Downloads/Flow. Android could not find an app to open this file."
                        .to_string()
                })?;
                Ok(())
            })();
            if result.is_err() && !published {
                // JNI calls cannot run while an exception is pending. Clear it
                // before removing a partial row and return the original error.
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                let _ = env.call_method(
                    &resolver,
                    "delete",
                    "(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I",
                    &[
                        JValue::Object(&uri),
                        JValue::Object(&JObject::null()),
                        JValue::Object(&JObject::null()),
                    ],
                );
            }
            // Keep a successfully saved copy if no viewer is installed. The
            // error then explicitly reports the saved location to the user.
            result
        })
    }

    pub fn safe_insets() -> Result<(f32, f32), String> {
        with_activity(|env, activity| {
            let window = env
                .call_method(activity, "getWindow", "()Landroid/view/Window;", &[])
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let decor = env
                .call_method(window, "getDecorView", "()Landroid/view/View;", &[])
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let insets = env
                .call_method(
                    decor,
                    "getRootWindowInsets",
                    "()Landroid/view/WindowInsets;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            if insets.is_null() {
                return Ok((0.0, 0.0));
            }
            let (top, bottom) = if sdk_version(env)? >= 30 {
                let types = env
                    .call_static_method("android/view/WindowInsets$Type", "systemBars", "()I", &[])
                    .and_then(|v| v.i())
                    .map_err(jni_error)?;
                let edges = env
                    .call_method(
                        insets,
                        "getInsets",
                        "(I)Landroid/graphics/Insets;",
                        &[JValue::Int(types)],
                    )
                    .and_then(|v| v.l())
                    .map_err(jni_error)?;
                let top = env
                    .get_field(&edges, "top", "I")
                    .and_then(|v| v.i())
                    .map_err(jni_error)?;
                let bottom = env
                    .get_field(edges, "bottom", "I")
                    .and_then(|v| v.i())
                    .map_err(jni_error)?;
                (top, bottom)
            } else {
                let top = env
                    .call_method(&insets, "getSystemWindowInsetTop", "()I", &[])
                    .and_then(|v| v.i())
                    .map_err(jni_error)?;
                let bottom = env
                    .call_method(insets, "getSystemWindowInsetBottom", "()I", &[])
                    .and_then(|v| v.i())
                    .map_err(jni_error)?;
                (top, bottom)
            };
            let resources = env
                .call_method(
                    activity,
                    "getResources",
                    "()Landroid/content/res/Resources;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let metrics = env
                .call_method(
                    resources,
                    "getDisplayMetrics",
                    "()Landroid/util/DisplayMetrics;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jni_error)?;
            let density = env
                .get_field(metrics, "density", "F")
                .and_then(|v| v.f())
                .map_err(jni_error)?
                .max(0.1);
            Ok((top as f32 / density, bottom as f32 / density))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_browser_lists_real_metadata_with_directories_first() {
        let directory = std::env::temp_dir().join(format!("flow-browser-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(directory.join("z-folder")).unwrap();
        std::fs::write(directory.join("B.txt"), b"four").unwrap();
        std::fs::write(directory.join("a.txt"), b"a").unwrap();
        std::fs::write(directory.join(".private"), b"hidden").unwrap();
        let entries = list_files(&directory).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["z-folder", "a.txt", "B.txt"]
        );
        assert!(entries[0].is_dir);
        assert_eq!(entries[2].size, 4);
        assert_eq!(entries[1].path, directory.join("a.txt"));
        for name in ["B.txt", "a.txt", ".private"] {
            std::fs::remove_file(directory.join(name)).unwrap();
        }
        std::fs::remove_dir(directory.join("z-folder")).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn file_browser_does_not_masquerade_missing_directory_as_empty() {
        let missing = std::env::temp_dir().join(format!("flow-missing-{}", uuid::Uuid::new_v4()));
        assert!(list_files(&missing).is_err());
    }
}
