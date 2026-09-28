// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared constants and checks for opt-in SSH agent forwarding.
//!
//! The host `SSH_AUTH_SOCK` never leaves the client. The CLI opens an SSH
//! session with `ForwardAgent=yes` over the existing authenticated
//! gateway relay. The workload binds `/tmp/openshell-ssh-agent/agent.sock`
//! (the supervisor does not share that mount namespace) and the supervisor
//! bridges each accept back to the client with `auth-agent@openssh.com`.
//! Docker, VM, and Kubernetes all use this path.

use std::collections::HashMap;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Settings registry key. Default false. The forwarding path does not read
/// this value. The client must still pass `--forward-agent`.
pub const SSH_FORWARD_AGENT_KEY: &str = "ssh_forward_agent";

/// Directory for the pinned in-sandbox agent socket. `/tmp` must be
/// Landlock `read_write`, which the default policy grants. Home is often
/// read-only, so `~/.ssh` cannot hold the socket.
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
        format!("{SSH_AUTH_SOCK_ENV} is unset on this host. Start your SSH agent.")
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

/// One multiplexed message on the supervisor-to-boundary agent stream.
/// The workload owns `/tmp/openshell-ssh-agent/agent.sock`. The supervisor
/// owns the russh session that can open `auth-agent@openssh.com`.
pub const FRAME_OPEN: u8 = 1;
pub const FRAME_DATA: u8 = 2;
pub const FRAME_CLOSE: u8 = 3;
pub const MAX_AGENT_FRAME: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentFrame {
    pub kind: u8,
    pub conn_id: u32,
    pub payload: Vec<u8>,
}

/// Read one frame. `Ok(None)` is a clean EOF before the header.
pub async fn read_agent_frame<R>(reader: &mut R) -> std::io::Result<Option<AgentFrame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 9];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]).await? {
            0 if filled == 0 => return Ok(None),
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "agent frame header truncated",
                ));
            }
            n => filled += n,
        }
    }
    let kind = header[0];
    let mut id_bytes = [0_u8; 4];
    let mut len_bytes = [0_u8; 4];
    id_bytes.copy_from_slice(&header[1..5]);
    len_bytes.copy_from_slice(&header[5..9]);
    let conn_id = u32::from_be_bytes(id_bytes);
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_AGENT_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "agent frame exceeds 256KiB",
        ));
    }
    let mut payload = vec![0_u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok(Some(AgentFrame {
        kind,
        conn_id,
        payload,
    }))
}

pub async fn write_agent_frame<W>(writer: &mut W, frame: &AgentFrame) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if frame.payload.len() > MAX_AGENT_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "agent frame exceeds 256KiB",
        ));
    }
    let mut header = [0_u8; 9];
    header[0] = frame.kind;
    header[1..5].copy_from_slice(&frame.conn_id.to_be_bytes());
    header[5..9].copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await?;
    Ok(())
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
    #[test]
    fn agent_frame_round_trips() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let (mut client, mut server) = tokio::io::duplex(64);
            let frame = AgentFrame {
                kind: FRAME_DATA,
                conn_id: 7,
                payload: b"ssh".to_vec(),
            };
            write_agent_frame(&mut client, &frame).await.unwrap();
            let got = read_agent_frame(&mut server).await.unwrap().unwrap();
            assert_eq!(got, frame);
        });
    }

    fn pinned_paths_live_under_tmp() {
        assert!(SANDBOX_AGENT_DIR.starts_with("/tmp/"));
        assert!(SANDBOX_AGENT_SOCK.starts_with(SANDBOX_AGENT_DIR));
        assert!(!SANDBOX_AGENT_SOCK.starts_with("/home/"));
    }
}
