//! Windows update handoff. The application verifies the download before calling
//! this module; a Rust helper waits for the old process before replacing files.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

// Preserve the effective historical Inno AppId, including its second closing
// brace. Changing that value would create a separate installation registration.
const INSTALL_ID: &str = "{8B5C061E-74A2-4BC2-9B7E-772A1461A9F4}}";
const INSTALL_MARKER: &str = "OtiumFlow.Installed|{8B5C061E-74A2-4BC2-9B7E-772A1461A9F4}}";
const HELPER_SWITCH: &str = "--flow-update-helper";
const COMPLETE_SWITCH: &str = "--flow-update-complete";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Mode {
    Portable,
    Installer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    id: String,
    mode: Mode,
    target: PathBuf,
    staged: PathBuf,
    backup: PathBuf,
    helper: PathBuf,
    ready: PathBuf,
    target_sha256: String,
    staged_sha256: String,
    parent_pid: u32,
    arguments: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
enum Handoff {
    Ready { helper_pid: u32 },
    Failed(String),
}

pub fn is_installed() -> bool {
    #[cfg(windows)]
    {
        let Ok(executable) = std::env::current_exe().and_then(fs::canonicalize) else {
            return false;
        };
        installed_at(&executable, &windows::registered_directories())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn installed_at(executable: &Path, registered_directories: &[PathBuf]) -> bool {
    if !executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("OtiumFlow.exe"))
    {
        return false;
    }
    let Some(directory) = executable.parent() else {
        return false;
    };
    fs::read_to_string(directory.join(".flow-installed"))
        .is_ok_and(|value| value.trim() == INSTALL_MARKER)
        || registered_directories
            .iter()
            .any(|path| same_path(path, directory))
}

/// Return only after a validated helper has accepted the handoff. The caller
/// then quits Slint normally. A cancelled UAC prompt is returned as an error.
pub fn apply_verified(package: &Path, is_setup: bool) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = (package, is_setup);
        Err("This update handoff is only available on Windows".into())
    }
    #[cfg(windows)]
    {
        let target = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(display_error)?;
        let parent = target
            .parent()
            .ok_or("The application folder is unavailable")?;
        let id = uuid::Uuid::new_v4().to_string();
        let mode = if is_setup {
            Mode::Installer
        } else {
            Mode::Portable
        };
        if is_setup != is_installed() {
            return Err(
                "The downloaded update does not match this installed/portable application".into(),
            );
        }
        let work = if is_setup {
            let directory = std::env::temp_dir().join(format!("OtiumFlow-update-{id}"));
            fs::create_dir(&directory).map_err(display_error)?;
            directory
        } else {
            parent.to_path_buf()
        };
        let stem = format!(".flow-update-{id}");
        let staged = work.join(format!("{stem}.staged.exe"));
        let helper = work.join(format!("{stem}.helper.exe"));
        let plan_path = work.join(format!("{stem}.json"));
        let plan = Plan {
            id,
            mode,
            target: target.clone(),
            staged: staged.clone(),
            backup: parent.join(format!("{stem}.backup.exe")),
            helper: helper.clone(),
            ready: work.join(format!("{stem}.ready")),
            target_sha256: hash_file(&target)?,
            staged_sha256: hash_file(package)?,
            parent_pid: std::process::id(),
            arguments: original_arguments()?,
        };
        let prepare = (|| {
            copy_exclusive(package, &staged)?;
            if hash_file(&staged)? != plan.staged_sha256 {
                return Err("The staged update did not match the verified download".into());
            }
            copy_exclusive(&target, &helper)?;
            write_exclusive(
                &plan_path,
                &serde_json::to_vec(&plan).map_err(display_error)?,
            )?;
            let mut process = Command::new(&helper)
                .arg(HELPER_SWITCH)
                .arg(&plan_path)
                .spawn()
                .map_err(display_error)?;
            // An elevation prompt may remain open until the user responds.
            let deadline = Instant::now() + Duration::from_secs(300);
            loop {
                if let Ok(bytes) = fs::read(&plan.ready) {
                    match serde_json::from_slice::<Handoff>(&bytes).map_err(display_error)? {
                        Handoff::Ready { .. } => return Ok(()),
                        Handoff::Failed(error) => return Err(error),
                    }
                }
                if let Some(status) = process.try_wait().map_err(display_error)? {
                    return Err(format!(
                        "The update helper stopped before accepting the update ({status})"
                    ));
                }
                if Instant::now() >= deadline {
                    // Only terminate the helper created by this invocation. The
                    // running application is retained when no handoff completed.
                    let _ = process.kill();
                    let _ = process.wait();
                    return Err("The update handoff timed out; Flow has not been replaced".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })();
        if prepare.is_err() {
            remove_owned(&plan.ready);
            remove_owned(&plan_path);
            remove_owned(&staged);
            remove_owned(&helper);
        }
        prepare
    }
}

/// Call at the very start of main, before initializing Slint. Helpers are copies
/// of the currently installed executable and need no shell scripts or runtime.
pub fn run_helper_if_requested() -> Result<bool, String> {
    let Some(path) = argument_path(HELPER_SWITCH) else {
        return Ok(false);
    };
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("Windows update helper mode is unavailable on this platform".into())
    }
    #[cfg(windows)]
    {
        let plan = read_plan(&path)?;
        let result = run_helper(&plan, &path);
        if let Err(ref error) = result {
            if !plan.ready.exists() {
                let _ = write_handoff(&plan.ready, &Handoff::Failed(error.clone()));
            } else {
                windows::show_error(error);
            }
        }
        // The helper itself remains until the successfully restarted app's next
        // cleanup. Windows cannot delete a running helper executable reliably.
        result.map(|_| true)
    }
}

#[cfg(windows)]
fn run_helper(plan: &Plan, plan_path: &Path) -> Result<(), String> {
    let _guard = windows::UpdateMutex::acquire(&plan.target)?;
    let current = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(display_error)?;
    if !same_path(&current, &plan.helper) {
        return Err("The update helper location is invalid".into());
    }
    if hash_file(&plan.staged)? != plan.staged_sha256
        || hash_file(&plan.target)? != plan.target_sha256
    {
        return Err(
            "The update or application changed before the handoff; please check for updates again"
                .into(),
        );
    }
    match plan.mode {
        Mode::Installer => {
            let installer = windows::launch_setup(&plan.staged)?;
            write_handoff(
                &plan.ready,
                &Handoff::Ready {
                    helper_pid: std::process::id(),
                },
            )?;
            let exit = installer.wait()?;
            if exit != 0 {
                let message = if exit == 2 {
                    "The update installation was cancelled"
                } else {
                    "The update installation did not complete"
                };
                restart(&plan.target, &plan.arguments, None, Some(message))?;
            }
            remove_owned(&plan.staged);
            remove_owned(&plan.ready);
            remove_owned(plan_path);
            // The new installer handles a successful restart through its
            // dedicated /FLOWUPDATE=1 [Run] entry, using the original user.
            Ok(())
        }
        Mode::Portable => {
            let parent = windows::Process::open(plan.parent_pid)?;
            write_handoff(
                &plan.ready,
                &Handoff::Ready {
                    helper_pid: std::process::id(),
                },
            )?;
            parent.wait_for_exit(Duration::from_secs(120))?;
            let result = replace_transaction(
                &plan.target,
                &plan.staged,
                &plan.backup,
                &plan.target_sha256,
                &plan.staged_sha256,
                |target| restart(target, &plan.arguments, Some(plan_path), None).map(|_| ()),
            );
            if let Err(problem) = result {
                // The transaction restores the original executable before this
                // launch. Keep the backup if Windows prevented a full rollback.
                if hash_file(&plan.target).ok().as_deref() == Some(&plan.target_sha256) {
                    restart(&plan.target, &plan.arguments, None, Some(&problem))?;
                }
                return Err(problem);
            }
            Ok(())
        }
    }
}

/// Call after the restarted app has shown its window. Only the specifically
/// recorded backup is removed, and only if this executable matches the update.
pub fn cleanup_old_executables() {
    #[cfg(windows)]
    if let Some(path) = argument_path(COMPLETE_SWITCH) {
        // Avoid blocking the UI on antivirus/mapped executable handle cleanup.
        std::thread::spawn(move || cleanup_completed_plan(&path));
    }
}

#[cfg(windows)]
fn cleanup_completed_plan(path: &Path) {
    let Ok(plan) = read_plan(&path) else { return };
    let Ok(current) = std::env::current_exe().and_then(fs::canonicalize) else {
        return;
    };
    if plan.mode != Mode::Portable
        || !same_path(&current, &plan.target)
        || hash_file(&current).ok().as_deref() != Some(&plan.staged_sha256)
    {
        return;
    }
    if let Ok(bytes) = fs::read(&plan.ready) {
        if let Ok(Handoff::Ready { helper_pid }) = serde_json::from_slice(&bytes) {
            if let Ok(helper) = windows::Process::open(helper_pid) {
                if helper.wait_for_exit(Duration::from_secs(10)).is_err() {
                    return;
                }
            }
        }
    }
    // A mapped old instance can keep the backup locked; leave it untouched
    // if removal fails rather than deleting any other version/user file.
    if fs::remove_file(&plan.backup).is_ok() || !plan.backup.exists() {
        remove_owned(&plan.staged);
        remove_owned(&plan.ready);
        remove_owned(&plan.helper);
        remove_owned(&path);
    }
}

fn read_plan(path: &Path) -> Result<Plan, String> {
    let bytes = fs::read(path).map_err(display_error)?;
    if bytes.len() > 64 * 1024 {
        return Err("The update plan is too large".into());
    }
    let plan: Plan = serde_json::from_slice(&bytes).map_err(display_error)?;
    let id = uuid::Uuid::parse_str(&plan.id).map_err(display_error)?;
    let stem = format!(".flow-update-{id}");
    let directory = path.parent().ok_or("Invalid update plan folder")?;
    let target_parent = plan.target.parent().ok_or("Invalid update destination")?;
    let named = |actual: &Path, suffix: &str| actual == directory.join(format!("{stem}.{suffix}"));
    if !plan.target.is_absolute()
        || plan.parent_pid == 0
        || !named(path, "json")
        || !named(&plan.staged, "staged.exe")
        || !named(&plan.helper, "helper.exe")
        || !named(&plan.ready, "ready")
        || plan.backup != target_parent.join(format!("{stem}.backup.exe"))
        || (plan.mode == Mode::Portable && !same_path(directory, target_parent))
        || plan.target_sha256.len() != 64
        || plan.staged_sha256.len() != 64
        || !plan
            .target_sha256
            .bytes()
            .chain(plan.staged_sha256.bytes())
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("The update plan contains an invalid file location".into());
    }
    Ok(plan)
}

fn replace_transaction(
    target: &Path,
    staged: &Path,
    backup: &Path,
    old_hash: &str,
    new_hash: &str,
    mut launch: impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    if !same_path(
        target.parent().ok_or("Invalid application folder")?,
        staged.parent().ok_or("Invalid update folder")?,
    ) || !same_path(
        target.parent().unwrap(),
        backup.parent().ok_or("Invalid backup folder")?,
    ) || backup.exists()
        || hash_file(target)? != old_hash
        || hash_file(staged)? != new_hash
    {
        return Err(
            "The application or update changed; the original application was retained".into(),
        );
    }
    if let Err(error) = replace_with_backup(target, staged, backup) {
        if backup.exists() && hash_file(target).ok().as_deref() != Some(old_hash) {
            restore_backup(target, backup, staged)?;
        }
        return Err(error);
    }
    if let Err(error) = launch(target) {
        restore_backup(target, backup, staged)
            .map_err(|restore| format!("{error}; rollback: {restore}"))?;
        return Err(format!(
            "The new version could not start. Your original version was restored: {error}"
        ));
    }
    Ok(())
}

fn restore_backup(target: &Path, backup: &Path, staged: &Path) -> Result<(), String> {
    if target.exists() {
        replace_with_backup(target, backup, staged)
    } else {
        fs::rename(backup, target).map_err(display_error)
    }
}

fn replace_with_backup(target: &Path, staged: &Path, backup: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::replace(target, staged, backup)
    }
    #[cfg(not(windows))]
    {
        fs::rename(target, backup).map_err(display_error)?;
        if let Err(error) = fs::rename(staged, target) {
            fs::rename(backup, target).map_err(display_error)?;
            return Err(display_error(error));
        }
        Ok(())
    }
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(display_error)?;
    if !file.metadata().map_err(display_error)?.is_file() {
        return Err("Select a regular update file".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(display_error)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn copy_exclusive(source: &Path, target: &Path) -> Result<(), String> {
    let mut input = File::open(source).map_err(display_error)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(display_error)?;
    std::io::copy(&mut input, &mut output).map_err(display_error)?;
    output.sync_all().map_err(display_error)
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(display_error)?;
    file.write_all(bytes).map_err(display_error)?;
    file.sync_all().map_err(display_error)
}

fn write_handoff(path: &Path, handoff: &Handoff) -> Result<(), String> {
    // The parent must never observe a created-but-not-written JSON status file.
    let temporary = path.with_extension(format!("{}.pending", uuid::Uuid::new_v4()));
    let result = (|| {
        write_exclusive(
            &temporary,
            &serde_json::to_vec(handoff).map_err(display_error)?,
        )?;
        fs::rename(&temporary, path).map_err(display_error)
    })();
    if result.is_err() {
        remove_owned(&temporary);
    }
    result
}

fn remove_owned(path: &Path) {
    let _ = fs::remove_file(path);
}
fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn same_path(a: &Path, b: &Path) -> bool {
    let a = fs::canonicalize(a).unwrap_or_else(|_| a.to_path_buf());
    let b = fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());
    #[cfg(windows)]
    {
        a.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

fn argument_path(name: &str) -> Option<PathBuf> {
    let arguments: Vec<_> = std::env::args_os().collect();
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| PathBuf::from(&pair[1]))
}

fn original_arguments() -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let mut arguments = std::env::args_os().skip(1);
    while let Some(value) = arguments.next() {
        if value == COMPLETE_SWITCH || value == "--flow-update-error" {
            let _ = arguments.next();
            continue;
        }
        result.push(
            value
                .into_string()
                .map_err(|_| "The application arguments contain unsupported Unicode".to_string())?,
        );
    }
    Ok(result)
}

fn restart(
    target: &Path,
    arguments: &[String],
    complete: Option<&Path>,
    error: Option<&str>,
) -> Result<Child, String> {
    let mut command = Command::new(target);
    command.args(arguments);
    if let Some(plan) = complete {
        command.arg(COMPLETE_SWITCH).arg(plan);
    }
    if let Some(error) = error {
        command.arg("--flow-update-error").arg(error);
    }
    command.spawn().map_err(display_error)
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{ffi::c_void, mem::size_of, os::windows::ffi::OsStrExt, ptr};
    type Handle = *mut c_void;
    #[repr(C)]
    struct ShellExecuteInfo {
        size: u32,
        mask: u32,
        window: Handle,
        verb: *const u16,
        file: *const u16,
        parameters: *const u16,
        directory: *const u16,
        show: i32,
        instance: Handle,
        id_list: Handle,
        class: *const u16,
        class_key: Handle,
        hotkey: u32,
        icon: Handle,
        process: Handle,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn GetExitCodeProcess(handle: Handle, code: *mut u32) -> i32;
        fn CreateMutexW(attributes: *const c_void, owner: i32, name: *const u16) -> Handle;
        fn ReleaseMutex(handle: Handle) -> i32;
        fn ReplaceFileW(
            target: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *mut c_void,
            reserved: *mut c_void,
        ) -> i32;
    }
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteExW(info: *mut ShellExecuteInfo) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(window: Handle, text: *const u16, title: *const u16, kind: u32) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(reserved: *mut c_void, apartment: u32) -> i32;
        fn CoUninitialize();
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            key: Handle,
            subkey: *const u16,
            value: *const u16,
            flags: u32,
            kind: *mut u32,
            data: *mut c_void,
            size: *mut u32,
        ) -> i32;
    }
    fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
        value.as_ref().encode_wide().chain(Some(0)).collect()
    }

    pub(super) struct Process(Handle);
    impl Drop for Process {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    impl Process {
        pub(super) fn open(pid: u32) -> Result<Self, String> {
            let handle = unsafe { OpenProcess(0x0010_0000 | 0x1000, 0, pid) };
            if handle.is_null() {
                Err(display_error(std::io::Error::last_os_error()))
            } else {
                Ok(Self(handle))
            }
        }
        pub(super) fn wait_for_exit(&self, timeout: Duration) -> Result<(), String> {
            match unsafe {
                WaitForSingleObject(self.0, timeout.as_millis().min(u32::MAX as u128) as u32)
            } {
                0 => Ok(()),
                258 => Err("Flow is still running. Close it and retry the update.".into()),
                _ => Err(display_error(std::io::Error::last_os_error())),
            }
        }
        pub(super) fn wait(&self) -> Result<u32, String> {
            if unsafe { WaitForSingleObject(self.0, u32::MAX) } != 0 {
                return Err(display_error(std::io::Error::last_os_error()));
            }
            let mut code = 0;
            if unsafe { GetExitCodeProcess(self.0, &mut code) } == 0 {
                return Err(display_error(std::io::Error::last_os_error()));
            }
            Ok(code)
        }
    }

    pub(super) struct UpdateMutex(Handle);
    impl UpdateMutex {
        pub(super) fn acquire(target: &Path) -> Result<Self, String> {
            let digest: String = Sha256::digest(target.to_string_lossy().to_lowercase().as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let name = wide(format!("Local\\OtiumFlow.Update.{digest}"));
            let handle = unsafe { CreateMutexW(ptr::null(), 1, name.as_ptr()) };
            if handle.is_null() {
                return Err(display_error(std::io::Error::last_os_error()));
            }
            let status = std::io::Error::last_os_error();
            if status.raw_os_error() == Some(183) {
                unsafe {
                    CloseHandle(handle);
                }
                return Err("Another update is already running for this copy of Flow".into());
            }
            Ok(Self(handle))
        }
    }
    impl Drop for UpdateMutex {
        fn drop(&mut self) {
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }

    pub(super) fn launch_setup(path: &Path) -> Result<Process, String> {
        // ShellExecuteEx can use COM shell extensions; initialize the helper
        // thread explicitly instead of depending on a GUI toolkit side effect.
        let apartment = unsafe { CoInitializeEx(ptr::null_mut(), 2 | 4) };
        if apartment < 0 {
            return Err(format!(
                "Windows could not initialize the installer launcher (0x{:08X})",
                apartment as u32
            ));
        }
        struct Apartment;
        impl Drop for Apartment {
            fn drop(&mut self) {
                unsafe {
                    CoUninitialize();
                }
            }
        }
        let _apartment = Apartment;
        let verb = wide("runas");
        let file = wide(path);
        let parameters = wide("/FLOWUPDATE=1 /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /NORESTART");
        let mut info = ShellExecuteInfo {
            size: size_of::<ShellExecuteInfo>() as u32,
            mask: 0x40 | 0x100 | 0x400,
            window: ptr::null_mut(),
            verb: verb.as_ptr(),
            file: file.as_ptr(),
            parameters: parameters.as_ptr(),
            directory: ptr::null(),
            show: 1,
            instance: ptr::null_mut(),
            id_list: ptr::null_mut(),
            class: ptr::null(),
            class_key: ptr::null_mut(),
            hotkey: 0,
            icon: ptr::null_mut(),
            process: ptr::null_mut(),
        };
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            return Err(display_error(std::io::Error::last_os_error()));
        }
        if info.process.is_null() {
            return Err("Windows did not return an installer process handle".into());
        }
        Ok(Process(info.process))
    }

    pub(super) fn replace(target: &Path, staged: &Path, backup: &Path) -> Result<(), String> {
        let target = wide(target);
        let staged = wide(staged);
        let backup = wide(backup);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if unsafe {
                ReplaceFileW(
                    target.as_ptr(),
                    staged.as_ptr(),
                    backup.as_ptr(),
                    2,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } != 0
            {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(5 | 32 | 33)) || Instant::now() >= deadline {
                return Err(display_error(error));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub(super) fn registered_directories() -> Vec<PathBuf> {
        let mut result = Vec::new();
        for hive in [-2_147_483_647isize, -2_147_483_646isize] {
            for prefix in [
                "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            ] {
                let key = wide(format!("{prefix}\\{INSTALL_ID}_is1"));
                let value = wide("InstallLocation");
                let mut length = 0;
                let status = unsafe {
                    RegGetValueW(
                        hive as Handle,
                        key.as_ptr(),
                        value.as_ptr(),
                        2,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut length,
                    )
                };
                if status != 0 || length == 0 || length > 32 * 1024 {
                    continue;
                }
                let mut buffer = vec![0u16; (length as usize + 1) / 2];
                if unsafe {
                    RegGetValueW(
                        hive as Handle,
                        key.as_ptr(),
                        value.as_ptr(),
                        2,
                        ptr::null_mut(),
                        buffer.as_mut_ptr().cast(),
                        &mut length,
                    )
                } == 0
                {
                    let count = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
                    use std::os::windows::ffi::OsStringExt;
                    result.push(PathBuf::from(std::ffi::OsString::from_wide(
                        &buffer[..count],
                    )));
                }
            }
        }
        result
    }
    pub(super) fn show_error(error: &str) {
        let message = wide(error);
        let title = wide("Flow update");
        unsafe {
            MessageBoxW(ptr::null_mut(), message.as_ptr(), title.as_ptr(), 0x10);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("flow-update-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn failed_launch_restores_the_original_executable() {
        let dir = directory();
        let target = dir.join("Flow.exe");
        let staged = dir.join("stage.exe");
        let backup = dir.join("backup.exe");
        fs::write(&target, b"original executable").unwrap();
        fs::write(&staged, b"new executable").unwrap();
        let result = replace_transaction(
            &target,
            &staged,
            &backup,
            &hash_file(&target).unwrap(),
            &hash_file(&staged).unwrap(),
            |_| Err("simulated launch failure".into()),
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original executable");
        assert_eq!(fs::read(&staged).unwrap(), b"new executable");
        assert!(!backup.exists());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn successful_handoff_keeps_backup_until_the_new_app_starts() {
        let dir = directory();
        let target = dir.join("Flow.exe");
        let staged = dir.join("stage.exe");
        let backup = dir.join("backup.exe");
        fs::write(&target, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();
        let mut launched = false;
        replace_transaction(
            &target,
            &staged,
            &backup,
            &hash_file(&target).unwrap(),
            &hash_file(&staged).unwrap(),
            |path| {
                assert_eq!(fs::read(path).unwrap(), b"new");
                launched = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(launched);
        assert_eq!(fs::read(&backup).unwrap(), b"old");
        assert_eq!(fs::read(&target).unwrap(), b"new");
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn changed_staging_file_cannot_replace_the_application() {
        let dir = directory();
        let target = dir.join("Flow.exe");
        let staged = dir.join("stage.exe");
        let backup = dir.join("backup.exe");
        fs::write(&target, b"old").unwrap();
        fs::write(&staged, b"verified").unwrap();
        let old = hash_file(&target).unwrap();
        let verified = hash_file(&staged).unwrap();
        fs::write(&staged, b"modified").unwrap();
        assert!(
            replace_transaction(&target, &staged, &backup, &old, &verified, |_| panic!(
                "must not launch"
            ))
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(!backup.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn install_channel_uses_identity_instead_of_program_files_spelling() {
        let dir = directory();
        let custom = dir.join("Custom Flow location");
        let portable = dir.join("Program Files");
        fs::create_dir_all(&custom).unwrap();
        fs::create_dir_all(&portable).unwrap();
        let executable = custom.join("OtiumFlow.exe");
        fs::write(&executable, b"installed").unwrap();
        fs::write(portable.join("OtiumFlow.exe"), b"portable").unwrap();
        assert!(!installed_at(&portable.join("OtiumFlow.exe"), &[]));
        assert!(installed_at(&executable, std::slice::from_ref(&custom)));
        fs::write(custom.join(".flow-installed"), INSTALL_MARKER).unwrap();
        assert!(installed_at(&executable, &[]));
        assert!(!installed_at(&custom.join("Renamed-Portable.exe"), &[]));
        fs::remove_dir_all(dir).unwrap();
    }
}
