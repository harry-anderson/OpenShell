// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload-side SSH agent socket.
//!
//! The supervisor SSH server does not share this mount namespace. It opens
//! `AgentListen`; this process binds `/tmp/openshell-ssh-agent/agent.sock`
//! and multiplexes each accept back on that stream.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use openshell_core::ssh_agent::{
    self, AgentFrame, FRAME_CLOSE, FRAME_DATA, FRAME_OPEN, agent_forward_env_enabled,
    read_agent_frame, write_agent_frame,
};

static AGENT_LISTEN_BUSY: AtomicBool = AtomicBool::new(false);

struct ListenGuard;

impl Drop for ListenGuard {
    fn drop(&mut self) {
        AGENT_LISTEN_BUSY.store(false, Ordering::Release);
    }
}

fn workload_user_environment() -> HashMap<String, String> {
    std::env::var(openshell_core::sandbox_env::USER_ENVIRONMENT)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn bind_agent_socket() -> Result<UnixListener, String> {
    let dir = ssh_agent::SANDBOX_AGENT_DIR;
    let sock = ssh_agent::SANDBOX_AGENT_SOCK;
    std::fs::create_dir_all(dir).map_err(|error| format!("create {dir}: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("chmod {dir}: {error}"))?;
    }
    if std::path::Path::new(sock).exists() {
        std::fs::remove_file(sock).map_err(|error| format!("remove stale {sock}: {error}"))?;
    }
    let listener = std::os::unix::net::UnixListener::bind(sock)
        .map_err(|error| format!("bind {sock}: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("chmod {sock}: {error}"))?;
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set {sock} nonblocking: {error}"))?;
    UnixListener::from_std(listener).map_err(|error| format!("register {sock}: {error}"))
}

/// Fail closed and bind the socket before the supervisor is told the
/// listener is up. A client `ForwardAgent yes` is not enough: create must
/// have injected the pinned `SSH_AUTH_SOCK`.
pub fn prepare_listener() -> Result<UnixListener, String> {
    if !agent_forward_env_enabled(&workload_user_environment()) {
        return Err(
            "agent-forward rejected: sandbox was not created with --forward-agent".to_string(),
        );
    }
    if AGENT_LISTEN_BUSY.swap(true, Ordering::AcqRel) {
        return Err("agent listener is already running".to_string());
    }
    match bind_agent_socket() {
        Ok(listener) => Ok(listener),
        Err(error) => {
            AGENT_LISTEN_BUSY.store(false, Ordering::Release);
            Err(error)
        }
    }
}

/// Multiplex accepted connections onto `stream`. `prepare_listener` must
/// have succeeded on this process first.
pub async fn serve<S>(listener: UnixListener, stream: S) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _guard = ListenGuard;
    let (mut read_half, write_half) = tokio::io::split(stream);
    let write_half = Arc::new(Mutex::new(write_half));
    let mut next_id: u32 = 1;
    let mut inbound: HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>> = HashMap::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (unix, _) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => return Err(format!("agent socket accept: {error}")),
                };
                let conn_id = next_id;
                next_id = next_id.wrapping_add(1);
                if next_id == 0 {
                    next_id = 1;
                }
                let (to_unix_tx, to_unix_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
                inbound.insert(conn_id, to_unix_tx);
                if let Err(error) = write_agent_frame(&mut *write_half.lock().await, &AgentFrame {
                    kind: FRAME_OPEN,
                    conn_id,
                    payload: Vec::new(),
                }).await {
                    return Err(format!("send agent open: {error}"));
                }
                let writer = Arc::clone(&write_half);
                tokio::spawn(async move {
                    pump_unix(conn_id, unix, to_unix_rx, writer).await;
                });
            }
            incoming = read_agent_frame(&mut read_half) => {
                let frame = match incoming {
                    Ok(Some(frame)) => frame,
                    Ok(None) => return Ok(()),
                    Err(error) => return Err(format!("read agent frame: {error}")),
                };
                match frame.kind {
                    FRAME_DATA => {
                        if let Some(tx) = inbound.get(&frame.conn_id) {
                            let _ = tx.send(frame.payload).await;
                        }
                    }
                    FRAME_CLOSE => {
                        inbound.remove(&frame.conn_id);
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn pump_unix<W>(
    conn_id: u32,
    mut unix: tokio::net::UnixStream,
    mut inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    writer: Arc<Mutex<W>>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (mut unix_read, mut unix_write) = unix.into_split();
    let write_out = Arc::clone(&writer);
    let outbound = tokio::spawn(async move {
        let mut buf = [0_u8; 16 * 1024];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut unix_read, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let frame = AgentFrame {
                kind: FRAME_DATA,
                conn_id,
                payload: buf[..n].to_vec(),
            };
            if write_agent_frame(&mut *write_out.lock().await, &frame)
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = write_agent_frame(
            &mut *write_out.lock().await,
            &AgentFrame {
                kind: FRAME_CLOSE,
                conn_id,
                payload: Vec::new(),
            },
        )
        .await;
    });
    while let Some(bytes) = inbound.recv().await {
        if unix_write.write_all(&bytes).await.is_err() {
            break;
        }
    }
    outbound.abort();
}
