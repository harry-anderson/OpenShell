// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory copy of the sandbox user environment.
//!
//! Drivers may hand the map to this process as `OPENSHELL_USER_ENVIRONMENT`.
//! That JSON is a second copy of every literal secret. Install the map, wipe
//! any exec-time copy, and remove the variable before any workload process
//! exists. Children receive the individual keys. They do not receive the
//! serialized blob.
//!
//! `/proc/<pid>/environ` is the block passed to `execve`, not the live libc
//! environment. `remove_var` alone leaves that block readable by a workload
//! that can open this process's environ file. The wipe overwrites those
//! original bytes.

use std::collections::HashMap;
use std::sync::Mutex;

use openshell_core::sandbox_env::USER_ENVIRONMENT;

static SNAPSHOT: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn lock_snapshot() -> std::sync::MutexGuard<'static, Option<HashMap<String, String>>> {
    SNAPSHOT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Store `map` for later child injection and drop the process-level JSON copy.
///
/// A key named `OPENSHELL_USER_ENVIRONMENT` is discarded so a poisoned map
/// cannot be copied back into a child by `cmd.envs`.
pub(crate) fn install(map: HashMap<String, String>) {
    let map = map
        .into_iter()
        .filter(|(key, _)| key != USER_ENVIRONMENT)
        .collect();
    *lock_snapshot() = Some(map);
    drop_process_copy();
}

/// The user environment workload children should receive.
///
/// Prefers the installed snapshot. Falls back to the process variable so a
/// caller that has not installed yet still sees a map. Production installs
/// and clears the variable before the first child spawn.
pub(crate) fn current() -> HashMap<String, String> {
    if let Some(map) = lock_snapshot().as_ref() {
        return map.clone();
    }
    std::env::var(USER_ENVIRONMENT)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

/// Remove the serialized copy from the live environment and from the exec-time
/// block `/proc/self/environ` still exposes.
#[allow(unsafe_code)]
fn drop_process_copy() {
    // SAFETY: called on the boundary thread before the workload launcher
    // starts. No other thread may read or mutate this variable across the
    // wipe. `remove_var` is unsafe because a racy environ mutation from
    // another thread is undefined. The pointer capture happens first so the
    // exec-time bytes can be overwritten after the libc pointer is dropped.
    let originals = capture_initial_entries(USER_ENVIRONMENT);
    unsafe {
        std::env::remove_var(USER_ENVIRONMENT);
    }
    wipe_entries(&originals);
}

#[cfg(unix)]
#[allow(unsafe_code)]
unsafe extern "C" {
    static mut environ: *mut *mut libc::c_char;
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn capture_initial_entries(key: &str) -> Vec<(*mut u8, usize)> {
    let prefix = format!("{key}=");
    let prefix_bytes = prefix.as_bytes();
    let mut matches = Vec::new();
    unsafe {
        let mut cursor = environ;
        if cursor.is_null() {
            return matches;
        }
        while !(*cursor).is_null() {
            let entry = std::ffi::CStr::from_ptr(*cursor);
            let bytes = entry.to_bytes();
            if bytes.starts_with(prefix_bytes) {
                matches.push((*cursor as *mut u8, bytes.len()));
            }
            cursor = cursor.add(1);
        }
    }
    matches
}

#[cfg(not(unix))]
fn capture_initial_entries(_key: &str) -> Vec<(*mut u8, usize)> {
    Vec::new()
}

#[allow(unsafe_code)]
fn wipe_entries(entries: &[(*mut u8, usize)]) {
    // SAFETY: the pointers were taken from this process's environ block
    // before `remove_var`. `unsetenv` does not free those strings. Volatile
    // stores stay in the binary because the kernel reads this memory through
    // `/proc/<pid>/environ`, which the compiler cannot see.
    for &(ptr, len) in entries {
        unsafe {
            for offset in 0..len {
                std::ptr::write_volatile(ptr.add(offset), 0);
            }
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn probe_install() {
        let marker = "rt68-marker-not-in-environ";
        let initial = std::fs::read("/proc/self/environ").expect("read initial environ");
        assert!(
            initial
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "probe must be exec'd with the secret marker in the initial environ"
        );

        let mut incoming = HashMap::new();
        incoming.insert("QDRANT_API_KEY".to_string(), marker.to_string());
        incoming.insert(
            USER_ENVIRONMENT.to_string(),
            format!(r#"{{"QDRANT_API_KEY":"{marker}"}}"#),
        );
        install(incoming);

        assert!(
            std::env::var(USER_ENVIRONMENT).is_err(),
            "process environ must not keep the serialized user environment"
        );
        let after = std::fs::read("/proc/self/environ").expect("read process environ");
        assert!(
            !after
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "secret marker must not remain in /proc/self/environ after install"
        );
        let key_needle = format!("{USER_ENVIRONMENT}=");
        assert!(
            !after
                .windows(key_needle.len())
                .any(|window| window == key_needle.as_bytes()),
            "serialized user environment name must not remain in /proc/self/environ"
        );
        assert_eq!(
            current().get("QDRANT_API_KEY").map(String::as_str),
            Some(marker)
        );
        assert!(
            !current().contains_key(USER_ENVIRONMENT),
            "snapshot must not carry the blob key back into child injection"
        );

        let inherited = std::process::Command::new("/usr/bin/env")
            .output()
            .expect("spawn inherited environ probe");
        assert!(inherited.status.success());
        let stdout = String::from_utf8(inherited.stdout).expect("child environ is utf8");
        assert!(
            !stdout.contains("OPENSHELL_USER_ENVIRONMENT="),
            "inherited child must not see the serialized user environment"
        );
        assert!(
            !stdout.contains(marker),
            "inherited child must not see the secret marker"
        );

        let parent_environ = format!("/proc/{}/environ", std::process::id());
        let reader = std::process::Command::new("/bin/cat")
            .arg(&parent_environ)
            .output()
            .expect("workload read of parent environ");
        assert!(
            reader.status.success(),
            "workload must be able to attempt the parent environ read"
        );
        assert!(
            !reader
                .stdout
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "workload read of /proc/<boundary>/environ must not recover the secret marker"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn install_drops_serialized_copy_and_keeps_keys_for_children() {
        if std::env::var_os("OPENSHELL_TEST_USER_ENV_PROBE").is_some() {
            probe_install();
            return;
        }

        let marker = "rt68-marker-not-in-environ";
        let blob = serde_json::to_string(&HashMap::from([(
            "QDRANT_API_KEY".to_string(),
            marker.to_string(),
        )]))
        .expect("serialize probe map");
        // The marker has to be in the exec-time environ. Setting it after
        // start never lands in `/proc/self/environ`, so that shape cannot
        // catch a wipe that only calls `remove_var`.
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("user_environment::tests::install_drops_serialized_copy_and_keeps_keys_for_children")
            .arg("--exact")
            .env("OPENSHELL_TEST_USER_ENV_PROBE", "1")
            .env(USER_ENVIRONMENT, blob)
            .status()
            .expect("re-exec user-environment probe");
        assert!(status.success(), "user-environment probe failed: {status}");
    }
}
