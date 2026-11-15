// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bridge a workload agent-socket mux to russh `auth-agent@openssh.com` channels.
//!
//! The workload holds one agent listener per sandbox and refuses a second
//! `AgentListen` while it runs. It stops only when this bridge drops the
//! boundary stream. The SSH session owns the bridge task and aborts it on
//! disconnect (see `SshHandler`'s `Drop`). Per-connection tasks live in a
//! `JoinSet` so that abort drops every clone of the stream's write half.

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::ssh_agent::{
    AgentFrame, FRAME_CLOSE, FRAME_DATA, FRAME_OPEN, read_agent_frame, write_agent_frame,
};
use openshell_isolation_interface::contract::BoundaryDuplexStream;
use russh::server::Handle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

pub async fn bridge_agent_listener(
    stream: BoundaryDuplexStream,
    handle: Handle,
) -> Result<(), String> {
    let (mut read_half, write_half) = tokio::io::split(stream);
    let write_half = Arc::new(Mutex::new(write_half));
    let mut writers: HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut connections = JoinSet::new();

    loop {
        while connections.try_join_next().is_some() {}
        let frame = match read_agent_frame(&mut read_half).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) => return Err(format!("read agent frame: {error}")),
        };
        match frame.kind {
            FRAME_OPEN => {
                let conn_id = frame.conn_id;
                let channel = match handle.channel_open_agent().await {
                    Ok(channel) => channel,
                    Err(error) => {
                        let _ = write_agent_frame(
                            &mut *write_half.lock().await,
                            &AgentFrame {
                                kind: FRAME_CLOSE,
                                conn_id,
                                payload: Vec::new(),
                            },
                        )
                        .await;
                        tracing::warn!(%error, "agent-forward channel_open_agent failed");
                        continue;
                    }
                };
                let agent = channel.into_stream();
                let (mut agent_read, mut agent_write) = tokio::io::split(agent);
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
                writers.insert(conn_id, tx);
                let writer = Arc::clone(&write_half);
                connections.spawn(async move {
                    let mut buf = [0_u8; 16 * 1024];
                    loop {
                        let n = match agent_read.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if write_agent_frame(
                            &mut *writer.lock().await,
                            &AgentFrame {
                                kind: FRAME_DATA,
                                conn_id,
                                payload: buf[..n].to_vec(),
                            },
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    let _ = write_agent_frame(
                        &mut *writer.lock().await,
                        &AgentFrame {
                            kind: FRAME_CLOSE,
                            conn_id,
                            payload: Vec::new(),
                        },
                    )
                    .await;
                });
                connections.spawn(async move {
                    while let Some(bytes) = rx.recv().await {
                        if agent_write.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    // The workload client closed (FRAME_CLOSE dropped `tx`).
                    // Send SSH EOF so the client closes the agent channel.
                    // Without it the channel stays open, the reader above
                    // never sends FRAME_CLOSE, and the workload keeps the
                    // accepted socket for the life of the listener.
                    let _ = agent_write.shutdown().await;
                });
            }
            FRAME_DATA => {
                if let Some(tx) = writers.get(&frame.conn_id) {
                    let _ = tx.send(frame.payload).await;
                }
            }
            FRAME_CLOSE => {
                writers.remove(&frame.conn_id);
            }
            _ => {}
        }
    }
}
