//! Native Android update delivery. Call only from a blocking worker after the
//! user chooses Update; Android always owns the final installation confirmation.
#![cfg(target_os = "android")]

use crate::protocol::updater::AvailableUpdate;
use jni::objects::{JByteArray, JObject, JObjectArray, JString, JValue};
use jni::JNIEnv;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const PACKAGE: &str = "org.otium.flow";
const APK_MIME: &str = "application/vnd.android.package-archive";
const MAX_APK_BYTES: u64 = 256 * 1024 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
static UPDATING: AtomicBool = AtomicBool::new(false);

struct UpdateGuard;
impl Drop for UpdateGuard {
    fn drop(&mut self) {
        UPDATING.store(false, Ordering::Release);
    }
}

fn jni_error(error: jni::errors::Error) -> String {
    format!("Android could not complete the update action: {error}")
}

fn clear_exception(env: &mut JNIEnv<'_>) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
}

fn local_frame<T>(
    env: &mut JNIEnv<'_>,
    action: impl FnOnce(&mut JNIEnv<'_>) -> Result<T, String>,
) -> Result<T, String> {
    env.push_local_frame(48).map_err(jni_error)?;
    let result = action(env);
    clear_exception(env);
    let popped = unsafe { env.pop_local_frame(&JObject::null()) }.map_err(jni_error);
    result.and_then(|value| popped.map(|_| value))
}

fn with_activity<T>(
    action: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let context = ndk_context::android_context();
    if context.vm().is_null() || context.context().is_null() {
        return Err("Android activity is unavailable".into());
    }
    let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }.map_err(jni_error)?;
    let mut env = vm.attach_current_thread().map_err(jni_error)?;
    env.push_local_frame(96).map_err(jni_error)?;
    // Own a reference for this worker even if the native activity is closing.
    let activity = unsafe { JObject::from_raw(context.context().cast()) };
    let retained = env.new_global_ref(&activity).map_err(jni_error);
    let result = retained.and_then(|activity| action(&mut env, activity.as_obj()));
    clear_exception(&mut env);
    let popped = unsafe { env.pop_local_frame(&JObject::null()) }.map_err(jni_error);
    result.and_then(|value| popped.map(|_| value))
}

fn ensure_activity_open(env: &mut JNIEnv<'_>, activity: &JObject<'_>) -> Result<(), String> {
    for method in ["isFinishing", "isDestroyed"] {
        if env
            .call_method(activity, method, "()Z", &[])
            .and_then(|value| value.z())
            .map_err(jni_error)?
        {
            return Err("The update was cancelled because Flow is closing".into());
        }
    }
    Ok(())
}

fn string_value(env: &mut JNIEnv<'_>, value: JObject<'_>) -> Result<String, String> {
    if value.is_null() {
        return Err("Android did not return the expected package information".into());
    }
    let value = JString::from(value);
    let text: String = env.get_string(&value).map_err(jni_error)?.into();
    Ok(text)
}

fn package_manager<'a>(
    env: &mut JNIEnv<'a>,
    activity: &JObject<'_>,
) -> Result<JObject<'a>, String> {
    env.call_method(
        activity,
        "getPackageManager",
        "()Landroid/content/pm/PackageManager;",
        &[],
    )
    .and_then(|value| value.l())
    .map_err(jni_error)
}

fn installation_allowed(env: &mut JNIEnv<'_>, manager: &JObject<'_>) -> Result<bool, String> {
    env.call_method(manager, "canRequestPackageInstalls", "()Z", &[])
        .and_then(|value| value.z())
        .map_err(jni_error)
}

fn request_install_permission(env: &mut JNIEnv<'_>, activity: &JObject<'_>) -> Result<(), String> {
    let address = env
        .new_string(format!("package:{PACKAGE}"))
        .map_err(jni_error)?;
    let uri = env
        .call_static_method(
            "android/net/Uri",
            "parse",
            "(Ljava/lang/String;)Landroid/net/Uri;",
            &[JValue::Object(&address)],
        )
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    let action = env
        .new_string("android.settings.MANAGE_UNKNOWN_APP_SOURCES")
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
}

fn download_directory(env: &mut JNIEnv<'_>, activity: &JObject<'_>) -> Result<PathBuf, String> {
    let directory = env.new_string("Download").map_err(jni_error)?;
    let file = env
        .call_method(
            activity,
            "getExternalFilesDir",
            "(Ljava/lang/String;)Ljava/io/File;",
            &[JValue::Object(&directory)],
        )
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    if file.is_null() {
        return Err("Android update storage is unavailable".into());
    }
    let absolute = env
        .call_method(&file, "getAbsolutePath", "()Ljava/lang/String;", &[])
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    let path = PathBuf::from(string_value(env, absolute)?).join("updates");
    std::fs::create_dir_all(&path)
        .map_err(|error| format!("Cannot prepare update storage: {error}"))?;
    Ok(path)
}

fn enqueue(
    env: &mut JNIEnv<'_>,
    activity: &JObject<'_>,
    manager: &JObject<'_>,
    update: &AvailableUpdate,
    filename: &str,
) -> Result<i64, String> {
    let address = env.new_string(&update.download_url).map_err(jni_error)?;
    let uri = env
        .call_static_method(
            "android/net/Uri",
            "parse",
            "(Ljava/lang/String;)Landroid/net/Uri;",
            &[JValue::Object(&address)],
        )
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    let request = env
        .new_object(
            "android/app/DownloadManager$Request",
            "(Landroid/net/Uri;)V",
            &[JValue::Object(&uri)],
        )
        .map_err(jni_error)?;
    let directory = env.new_string("Download").map_err(jni_error)?;
    let subpath = env
        .new_string(format!("updates/{filename}"))
        .map_err(jni_error)?;
    env.call_method(
        &request, "setDestinationInExternalFilesDir",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Landroid/app/DownloadManager$Request;",
        &[JValue::Object(activity), JValue::Object(&directory), JValue::Object(&subpath)],
    ).map_err(jni_error)?;
    let mime = env.new_string(APK_MIME).map_err(jni_error)?;
    env.call_method(
        &request,
        "setMimeType",
        "(Ljava/lang/String;)Landroid/app/DownloadManager$Request;",
        &[JValue::Object(&mime)],
    )
    .map_err(jni_error)?;
    let title = env
        .new_string(format!("Flow {}", update.version))
        .map_err(jni_error)?;
    env.call_method(
        &request,
        "setTitle",
        "(Ljava/lang/CharSequence;)Landroid/app/DownloadManager$Request;",
        &[JValue::Object(&title)],
    )
    .map_err(jni_error)?;
    // Progress is visible, but no completed-download notification is offered
    // before our checksum and package verification have finished.
    env.call_method(
        &request,
        "setNotificationVisibility",
        "(I)Landroid/app/DownloadManager$Request;",
        &[JValue::Int(0)],
    )
    .map_err(jni_error)?;
    env.call_method(
        &request,
        "setVisibleInDownloadsUi",
        "(Z)Landroid/app/DownloadManager$Request;",
        &[JValue::Bool(0)],
    )
    .map_err(jni_error)?;
    let id = env
        .call_method(
            manager,
            "enqueue",
            "(Landroid/app/DownloadManager$Request;)J",
            &[JValue::Object(&request)],
        )
        .and_then(|value| value.j())
        .map_err(jni_error)?;
    if id <= 0 {
        return Err("Android could not start the update download".into());
    }
    Ok(id)
}

struct DownloadStatus {
    status: i32,
    received: u64,
    total: Option<u64>,
    reason: i32,
}

fn cursor_index(env: &mut JNIEnv<'_>, cursor: &JObject<'_>, column: &str) -> Result<i32, String> {
    let name = env.new_string(column).map_err(jni_error)?;
    env.call_method(
        cursor,
        "getColumnIndexOrThrow",
        "(Ljava/lang/String;)I",
        &[JValue::Object(&name)],
    )
    .and_then(|value| value.i())
    .map_err(jni_error)
}

fn query(env: &mut JNIEnv<'_>, manager: &JObject<'_>, id: i64) -> Result<DownloadStatus, String> {
    local_frame(env, |env| {
        let query = env
            .new_object("android/app/DownloadManager$Query", "()V", &[])
            .map_err(jni_error)?;
        let ids = env.new_long_array(1).map_err(jni_error)?;
        env.set_long_array_region(&ids, 0, &[id])
            .map_err(jni_error)?;
        env.call_method(
            &query,
            "setFilterById",
            "([J)Landroid/app/DownloadManager$Query;",
            &[JValue::Object(&ids)],
        )
        .map_err(jni_error)?;
        let cursor = env
            .call_method(
                manager,
                "query",
                "(Landroid/app/DownloadManager$Query;)Landroid/database/Cursor;",
                &[JValue::Object(&query)],
            )
            .and_then(|value| value.l())
            .map_err(jni_error)?;
        if cursor.is_null() {
            return Err("Android could not read update download progress".into());
        }
        let result = (|| {
            let exists = env
                .call_method(&cursor, "moveToFirst", "()Z", &[])
                .and_then(|value| value.z())
                .map_err(jni_error)?;
            if !exists {
                return Err("The update download was cancelled or removed".into());
            }
            let status_index = cursor_index(env, &cursor, "status")?;
            let received_index = cursor_index(env, &cursor, "bytes_so_far")?;
            let total_index = cursor_index(env, &cursor, "total_size")?;
            let reason_index = cursor_index(env, &cursor, "reason")?;
            let status = env
                .call_method(&cursor, "getInt", "(I)I", &[JValue::Int(status_index)])
                .and_then(|value| value.i())
                .map_err(jni_error)?;
            let received = env
                .call_method(&cursor, "getLong", "(I)J", &[JValue::Int(received_index)])
                .and_then(|value| value.j())
                .map_err(jni_error)?;
            let total = env
                .call_method(&cursor, "getLong", "(I)J", &[JValue::Int(total_index)])
                .and_then(|value| value.j())
                .map_err(jni_error)?;
            let reason = env
                .call_method(&cursor, "getInt", "(I)I", &[JValue::Int(reason_index)])
                .and_then(|value| value.i())
                .map_err(jni_error)?;
            Ok(DownloadStatus {
                status,
                received: received.max(0) as u64,
                total: (total >= 0).then_some(total as u64),
                reason,
            })
        })();
        clear_exception(env);
        let closed = env
            .call_method(&cursor, "close", "()V", &[])
            .map_err(jni_error);
        result.and_then(|value| closed.map(|_| value))
    })
}

fn remove_download(env: &mut JNIEnv<'_>, manager: &JObject<'_>, id: i64) {
    clear_exception(env);
    let _ = local_frame(env, |env| {
        let ids = env.new_long_array(1).map_err(jni_error)?;
        env.set_long_array_region(&ids, 0, &[id])
            .map_err(jni_error)?;
        env.call_method(manager, "remove", "([J)I", &[JValue::Object(&ids)])
            .map_err(jni_error)?;
        Ok(())
    });
}

fn verify_bytes(
    env: &mut JNIEnv<'_>,
    activity: &JObject<'_>,
    uri: &JObject<'_>,
    update: &AvailableUpdate,
) -> Result<(), String> {
    let resolver = env
        .call_method(
            activity,
            "getContentResolver",
            "()Landroid/content/ContentResolver;",
            &[],
        )
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    let mode = env.new_string("r").map_err(jni_error)?;
    let parcel = env
        .call_method(
            &resolver,
            "openFileDescriptor",
            "(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;",
            &[JValue::Object(uri), JValue::Object(&mode)],
        )
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    if parcel.is_null() {
        return Err("Android could not open the downloaded update".into());
    }
    let fd = env
        .call_method(parcel, "detachFd", "()I", &[])
        .and_then(|value| value.i())
        .map_err(jni_error)?;
    if fd < 0 {
        return Err("Android returned an invalid update file descriptor".into());
    }
    // detachFd transfers ownership to Rust, so every exit closes the descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    crate::protocol::updater::verify_package(&mut file, update.asset_size, &update.sha256)
}

fn version_code(env: &mut JNIEnv<'_>, package: &JObject<'_>, sdk: i32) -> Result<u64, String> {
    if sdk >= 28 {
        let version = env
            .call_method(package, "getLongVersionCode", "()J", &[])
            .and_then(|value| value.j())
            .map_err(jni_error)?;
        u64::try_from(version).map_err(|_| "Android returned an invalid version code".into())
    } else {
        env.get_field(package, "versionCode", "I")
            .and_then(|value| value.i())
            .map(|value| value as u32 as u64)
            .map_err(jni_error)
    }
}

fn signers(env: &mut JNIEnv<'_>, package: &JObject<'_>, sdk: i32) -> Result<Vec<Vec<u8>>, String> {
    let array = if sdk >= 28 {
        let info = env
            .get_field(package, "signingInfo", "Landroid/content/pm/SigningInfo;")
            .and_then(|value| value.l())
            .map_err(jni_error)?;
        if info.is_null() {
            return Err("Android could not verify the update signing identity".into());
        }
        env.call_method(
            info,
            "getApkContentsSigners",
            "()[Landroid/content/pm/Signature;",
            &[],
        )
        .and_then(|value| value.l())
        .map_err(jni_error)?
    } else {
        env.get_field(package, "signatures", "[Landroid/content/pm/Signature;")
            .and_then(|value| value.l())
            .map_err(jni_error)?
    };
    if array.is_null() {
        return Err("The update has no verifiable signing certificate".into());
    }
    let array = JObjectArray::from(array);
    let length = env.get_array_length(&array).map_err(jni_error)?;
    if !(1..=16).contains(&length) {
        return Err("The update has an invalid signing identity".into());
    }
    let mut certificates = Vec::new();
    for index in 0..length {
        let signature = env
            .get_object_array_element(&array, index)
            .map_err(jni_error)?;
        let bytes = env
            .call_method(signature, "toByteArray", "()[B", &[])
            .and_then(|value| value.l())
            .map_err(jni_error)?;
        certificates.push(
            env.convert_byte_array(JByteArray::from(bytes))
                .map_err(jni_error)?,
        );
    }
    certificates.sort();
    Ok(certificates)
}

fn verify_native_abi(env: &mut JNIEnv<'_>, path: &Path) -> Result<(), String> {
    local_frame(env, |env| {
        let path = env
            .new_string(path.to_string_lossy().as_ref())
            .map_err(jni_error)?;
        let archive = env
            .new_object(
                "java/util/zip/ZipFile",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&path)],
            )
            .map_err(jni_error)?;
        let result = (|| {
            let supported = env
                .get_static_field("android/os/Build", "SUPPORTED_ABIS", "[Ljava/lang/String;")
                .and_then(|value| value.l())
                .map_err(jni_error)?;
            let supported = JObjectArray::from(supported);
            let count = env.get_array_length(&supported).map_err(jni_error)?;
            if !(1..=16).contains(&count) {
                return Err("Android could not report the device architecture".into());
            }
            for index in 0..count {
                let abi = env
                    .get_object_array_element(&supported, index)
                    .map_err(jni_error)?;
                let abi = string_value(env, abi)?;
                let name = env
                    .new_string(format!("lib/{abi}/libotium_flow.so"))
                    .map_err(jni_error)?;
                let entry = env
                    .call_method(
                        &archive,
                        "getEntry",
                        "(Ljava/lang/String;)Ljava/util/zip/ZipEntry;",
                        &[JValue::Object(&name)],
                    )
                    .and_then(|value| value.l())
                    .map_err(jni_error)?;
                if !entry.is_null() {
                    return Ok(());
                }
            }
            Err("The downloaded APK does not support this device's architecture".into())
        })();
        clear_exception(env);
        let closed = env
            .call_method(&archive, "close", "()V", &[])
            .map_err(jni_error);
        result.and(closed.map(|_| ()))
    })
}

fn verify_package(
    env: &mut JNIEnv<'_>,
    manager: &JObject<'_>,
    path: &Path,
    update: &AvailableUpdate,
) -> Result<(), String> {
    let sdk = env
        .get_static_field("android/os/Build$VERSION", "SDK_INT", "I")
        .and_then(|value| value.i())
        .map_err(jni_error)?;
    let flags = if sdk >= 28 { 0x0800_0000 } else { 0x0000_0040 };
    let package_name = env.new_string(PACKAGE).map_err(jni_error)?;
    let installed = env
        .call_method(
            manager,
            "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
            &[JValue::Object(&package_name), JValue::Int(flags)],
        )
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    let archive_path = env
        .new_string(path.to_string_lossy().as_ref())
        .map_err(jni_error)?;
    let archive = env
        .call_method(
            manager,
            "getPackageArchiveInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
            &[JValue::Object(&archive_path), JValue::Int(flags)],
        )
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    if installed.is_null() || archive.is_null() {
        return Err("Android could not parse the installed app or downloaded APK".into());
    }
    let name = env
        .get_field(&archive, "packageName", "Ljava/lang/String;")
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    if string_value(env, name)? != PACKAGE {
        return Err("The downloaded APK belongs to a different application".into());
    }
    let name = env
        .get_field(&archive, "versionName", "Ljava/lang/String;")
        .and_then(|value| value.l())
        .map_err(jni_error)?;
    if string_value(env, name)? != update.version.trim_start_matches(['v', 'V']) {
        return Err("The downloaded APK version does not match the selected release".into());
    }
    if version_code(env, &archive, sdk)? <= version_code(env, &installed, sdk)? {
        return Err(
            "This update is not newer than the installed app; Android installation was not started"
                .into(),
        );
    }
    if signers(env, &archive, sdk)? != signers(env, &installed, sdk)? {
        return Err("The APK signing certificate does not match installed Flow. The update was blocked to protect your app data".into());
    }
    verify_native_abi(env, path)
}

fn launch_installer(
    env: &mut JNIEnv<'_>,
    activity: &JObject<'_>,
    uri: &JObject<'_>,
) -> Result<(), String> {
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
    let mime = env.new_string(APK_MIME).map_err(jni_error)?;
    env.call_method(
        &intent,
        "setDataAndType",
        "(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;",
        &[JValue::Object(uri), JValue::Object(&mime)],
    )
    .map_err(jni_error)?;
    env.call_method(
        &intent,
        "addFlags",
        "(I)Landroid/content/Intent;",
        &[JValue::Int(1)],
    )
    .map_err(jni_error)?; // FLAG_GRANT_READ_URI_PERMISSION, never file://.
    env.call_method(
        activity,
        "startActivity",
        "(Landroid/content/Intent;)V",
        &[JValue::Object(&intent)],
    )
    .map_err(jni_error)?;
    Ok(())
}

/// Blocking worker API. Success means the verified APK was handed to Android's
/// installer, whose user confirmation is required; it does not claim installation.
pub fn apply_update(update: &AvailableUpdate) -> Result<(), String> {
    if UPDATING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("An Android update is already in progress".into());
    }
    let _guard = UpdateGuard;
    if !update.asset_name.to_ascii_lowercase().ends_with(".apk")
        || !update
            .download_url
            .starts_with("https://github.com/XRTM8/Flow/releases/download/")
        || !(1..=MAX_APK_BYTES).contains(&update.asset_size)
        || update.sha256.trim().len() != 64
        || !update
            .sha256
            .trim()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("The release does not contain a trusted, verifiable Android update".into());
    }
    with_activity(|env, activity| {
        let packages = package_manager(env, activity)?;
        if !installation_allowed(env, &packages)? {
            request_install_permission(env, activity)?;
            return Err("Allow updates from Flow in Android settings, then return and press Update again. No installation has started".into());
        }
        let service_name = env.new_string("download").map_err(jni_error)?;
        let manager = env
            .call_method(
                activity,
                "getSystemService",
                "(Ljava/lang/String;)Ljava/lang/Object;",
                &[JValue::Object(&service_name)],
            )
            .and_then(|value| value.l())
            .map_err(jni_error)?;
        if manager.is_null() {
            return Err("Android Download Manager is unavailable or disabled".into());
        }
        let directory = download_directory(env, activity)?;
        let filename = format!("flow-{}.apk", uuid::Uuid::new_v4());
        let path = directory.join(&filename);
        let id = enqueue(env, activity, &manager, update, &filename)?;
        let result = (|| {
            let began = Instant::now();
            loop {
                ensure_activity_open(env, activity)?;
                if began.elapsed() >= DOWNLOAD_TIMEOUT {
                    return Err(
                        "Update download timed out. Try again with a stable connection".into(),
                    );
                }
                let state = query(env, &manager, id)?;
                if state.received > update.asset_size
                    || state.total.is_some_and(|size| size > update.asset_size)
                {
                    return Err("Android downloaded an unexpected update size".into());
                }
                match state.status {
                    8 => break, // STATUS_SUCCESSFUL
                    16 => {
                        return Err(format!(
                            "Android update download failed (reason {})",
                            state.reason
                        ))
                    }
                    1 | 2 | 4 => std::thread::sleep(Duration::from_secs(1)),
                    _ => return Err("Android returned an unknown update download status".into()),
                }
            }
            let uri = env
                .call_method(
                    &manager,
                    "getUriForDownloadedFile",
                    "(J)Landroid/net/Uri;",
                    &[JValue::Long(id)],
                )
                .and_then(|value| value.l())
                .map_err(jni_error)?;
            if uri.is_null() {
                return Err("Android could not provide a readable update URI".into());
            }
            let scheme = env
                .call_method(&uri, "getScheme", "()Ljava/lang/String;", &[])
                .and_then(|value| value.l())
                .map_err(jni_error)?;
            if string_value(env, scheme)? != "content" {
                return Err("Android did not provide a secure content URI for the update".into());
            }
            verify_bytes(env, activity, &uri, update)?;
            verify_package(env, &packages, &path, update)?;
            ensure_activity_open(env, activity)?;
            if !installation_allowed(env, &packages)? {
                request_install_permission(env, activity)?;
                return Err("Allow updates from Flow, then return and retry the update".into());
            }
            launch_installer(env, activity, &uri)
        })();
        if result.is_err() {
            remove_download(env, &manager, id);
            let _ = std::fs::remove_file(&path);
        }
        // Keep the completed row/file alive after launching the installer: it
        // reads the granted content URI asynchronously after startActivity.
        result
    })
}
