// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared constants and checks for opt-in SSH agent forwarding.
//!
//! The host `SSH_AUTH_SOCK` never leaves the client. The CLI opens an SSH
//! session with `ForwardAgent=yes` over the existing authenticated
//! gateway relay; the supervisor binds a pinned Unix socket in the sandbox
//! and bridges each accept back to the client with `auth-agent@openssh.com`.
//! That path works for Docker, VM, and Kubernetes: there is no
//! `host.docker.internal` hop and no cluster Service for the agent.

use std::collections::HashMap;
use std::path::Path;

/// Settings registry key. Default false. Gateway-global true is a fleet-wide
/// allow; the client must still pass `--forward-agent` (CLI forces
/// `ForwardAgent=no` otherwise).
pub const SSH_FORWARD_AGENT_KEY: &str = "ssh_forward_agent";

/// Directory for the pinned in-sandbox agent socket. `/tmp` must be
/// Landlock `read_write` (true of the default policy and Harry's SWE
/// policies). Home is often read-only, so `~/.ssh` cannot hold the socket.
pub const SANDBOX_AGENT_DIR: &str = "/tmp/openshell-ssh-agent";

/// Pinned socket path exported as `SSH_AUTH_SOCK` inside the sandbox.
/// Supervisor-started entrypoints and later SSH sessions all use this path
/// so git/ssh look up the agent at use time, not at process start.
pub const SANDBOX_AGENT_SOCK: &str = "/tmp/openshell-ssh-agent/agent.sock";

/// Env var name. The CLI injects the pinned path on `--forward-agent` create.
pub const SSH_AUTH_SOCK_ENV: &str = "SSH_AUTH_SOCK";

/// True when the sandbox was created with the pinned agent socket env.
/// The supervisor uses this as the fail-closed gate for `agent_request`.
#[must_use]
pub fn agent_forward_env_enabled(user_environment: &HashMap<String, String>) -> bool {
    user_environment
        .get(SSH_AUTH_SOCK_ENV)
        .is_some_and(|value| value == SANDBOX_AGENT_SOCK)
}

/// Inject the pinned sandbox socket path. Existing `SSH_AUTH_SOCK` is
/// overwritten so a host socket path never leaks into the sandbox env.
pub fn inject_forward_agent_env(user_environment: &mut HashMap<String, String>) {
    user_environment.insert(
        SSH_AUTH_SOCK_ENV.to_string(),
        SANDBOX_AGENT_SOCK.to_string(),
    );
}

/// Host-side gate: `SSH_AUTH_SOCK` must exist and be a socket (or a path
/// that looks like an agent socket file). Missing/empty fails closed.
pub fn host_agent_socket_ok() -> Result<String, String> {
    let raw = std::env::var(SSH_AUTH_SOCK_ENV).map_err(|_| {
        format!("{SSH_AUTH_SOCK_ENV} is unset on this host. Start ssh-agent / 1Password / PassportControl.")
    })?;
    if raw.is_empty() {
        return Err(format!("{SSH_AUTH_SOCK_ENV} is empty"));
    }
    let path = Path::new(&raw);
    if !path.exists() {
        return Err(format!(
            "{SSH_AUTH_SOCK_ENV}={raw} does not exist. Is the agent running?"
        ));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_gate_requires_exact_pinned_path() {
        let mut env = HashMap::new();
        assert!(!agent_forward_env_enabled(&env));
        env.insert(SSH_AUTH_SOCK_ENV.into(), "/tmp/other.sock".into());
        assert!(!agent_forward_env_enabled(&env));
        inject_forward_agent_env(&mut env);
        assert!(agent_forward_env_enabled(&env));
        assert_eq!(env.get(SSH_AUTH_SOCK_ENV).map(String::as_str), Some(SANDBOX_AGENT_SOCK));
    }

    #[test]
    fn pinned_paths_live_under_tmp() {
        assert!(SANDBOX_AGENT_DIR.starts_with("/tmp/"));
        assert!(SANDBOX_AGENT_SOCK.starts_with(SANDBOX_AGENT_DIR));
        assert!(!SANDBOX_AGENT_SOCK.starts_with("/home/"));
    }
}
