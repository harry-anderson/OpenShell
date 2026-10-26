// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Collect host git identity + SSH-cert signing settings and install them
//! into a sandbox. Private keys and certs stay in the host agent.

use crate::ssh::sandbox_sync_up;
use crate::tls::TlsOptions;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::git_sign::{
    HostGitSignConfig, SANDBOX_GIT_ALLOWED_SIGNERS, SANDBOX_GIT_CONFIG, inject_git_sign_env,
    render_sandbox_gitconfig,
};
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Staged host-side files that must stay on disk until upload finishes.
pub struct StagedGitSign {
    /// Keep the tempdir alive.
    _dir: TempDir,
    pub config_path: PathBuf,
    pub allowed_signers_path: Option<PathBuf>,
    pub summary: String,
}

fn git_config_get(key: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["config", "--get", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn git_config_bool(key: &str) -> bool {
    git_config_get(key).is_some_and(|raw| {
        openshell_core::settings::parse_bool_like(&raw).unwrap_or(false)
    })
}

/// Read identity and SSH-signing flags from the host git config walk
/// (local → global → system). Does **not** read `user.signingKey`.
pub fn collect_host_git_sign_config() -> HostGitSignConfig {
    HostGitSignConfig {
        name: git_config_get("user.name"),
        email: git_config_get("user.email"),
        gpg_format: git_config_get("gpg.format"),
        commit_gpgsign: git_config_bool("commit.gpgsign"),
        tag_gpgsign: git_config_bool("tag.gpgsign"),
        allowed_signers_host_path: git_config_get("gpg.ssh.allowedSignersFile"),
    }
}

/// Materialize a sandbox gitconfig + optional allowed_signers copy.
pub fn stage_host_git_sign(cfg: &HostGitSignConfig) -> Result<Option<StagedGitSign>> {
    if !cfg.is_ssh_signing() && cfg.name.is_none() && cfg.email.is_none() {
        return Ok(None);
    }

    let dir = TempDir::new().into_diagnostic().wrap_err("temp dir for git sign config")?;
    let mut allowed_signers_path = None;
    let mut include_signers = false;
    if let Some(host_path) = cfg.allowed_signers_host_path.as_deref() {
        let expanded = expand_tilde(host_path);
        match std::fs::read(&expanded) {
            Ok(bytes) => {
                let dest = dir.path().join("allowed_signers");
                std::fs::write(&dest, bytes).into_diagnostic()?;
                allowed_signers_path = Some(dest);
                include_signers = true;
            }
            Err(err) => {
                eprintln!(
                    "  {} host gpg.ssh.allowedSignersFile ({}) is unreadable ({err}); signing still works, verify will not",
                    "!".yellow(),
                    expanded.display(),
                );
            }
        }
    }

    let rendered = render_sandbox_gitconfig(cfg, include_signers);
    let config_path = dir.path().join("config");
    std::fs::write(&config_path, rendered).into_diagnostic()?;

    let mut bits = Vec::new();
    if cfg.is_ssh_signing() {
        bits.push("gpg.format=ssh".to_string());
        bits.push("defaultKeyCommand=ssh-add -L".to_string());
        if cfg.commit_gpgsign {
            bits.push("commit.gpgsign".to_string());
        }
    }
    if include_signers {
        bits.push("allowedSignersFile".to_string());
    }
    if cfg.name.is_some() || cfg.email.is_some() {
        bits.push("user.name/email".to_string());
    }

    Ok(Some(StagedGitSign {
        _dir: dir,
        config_path,
        allowed_signers_path,
        summary: bits.join(", "),
    }))
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

pub fn inject_git_env(env: &mut HashMap<String, String>) {
    inject_git_sign_env(env);
}

/// Upload staged config into the sandbox. Parent dirs are created by sync_up.
pub async fn install_staged_git_sign(
    server: &str,
    sandbox_name: &str,
    staged: &StagedGitSign,
    tls: &TlsOptions,
    workspace: &str,
) -> Result<()> {
    sandbox_sync_up(
        server,
        sandbox_name,
        &staged.config_path,
        Some(SANDBOX_GIT_CONFIG),
        tls,
        workspace,
    )
    .await
    .wrap_err("upload sandbox git config")?;
    if let Some(signers) = staged.allowed_signers_path.as_ref() {
        sandbox_sync_up(
            server,
            sandbox_name,
            signers,
            Some(SANDBOX_GIT_ALLOWED_SIGNERS),
            tls,
            workspace,
        )
        .await
        .wrap_err("upload allowed_signers")?;
    }
    Ok(())
}

pub fn warn_if_missing_identity(cfg: &HostGitSignConfig) {
    if cfg.name.is_none() || cfg.email.is_none() {
        eprintln!(
            "  {} host git user.name/email incomplete; commits inside the sandbox may be rejected",
            "!".yellow(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_tilde_joins_home() {
        let path = expand_tilde("~/Library/foo");
        if let Ok(home) = std::env::var("HOME") {
            assert!(path.starts_with(home));
            assert!(path.ends_with("Library/foo"));
        }
    }

    #[test]
    fn stage_writes_config_without_signing_key() {
        let cfg = HostGitSignConfig {
            name: Some("Ada".into()),
            email: Some("ada@example.com".into()),
            gpg_format: Some("ssh".into()),
            commit_gpgsign: true,
            ..HostGitSignConfig::default()
        };
        let staged = stage_host_git_sign(&cfg).unwrap().unwrap();
        let body = std::fs::read_to_string(&staged.config_path).unwrap();
        assert!(!body.to_ascii_lowercase().contains("signingkey"));
        assert!(body.contains("defaultKeyCommand = \"ssh-add -L\""));
        assert!(staged.allowed_signers_path.is_none());
    }

    #[test]
    fn stage_copies_allowed_signers() {
        let host_signers = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(host_signers.path(), "harry namespaces=\"git\" ssh-ed25519-cert-v01@openssh.com AAAA\n").unwrap();
        let cfg = HostGitSignConfig {
            gpg_format: Some("ssh".into()),
            commit_gpgsign: true,
            allowed_signers_host_path: Some(host_signers.path().display().to_string()),
            ..HostGitSignConfig::default()
        };
        let staged = stage_host_git_sign(&cfg).unwrap().unwrap();
        let copied = std::fs::read_to_string(staged.allowed_signers_path.as_ref().unwrap()).unwrap();
        assert!(copied.contains("ssh-ed25519-cert-v01@openssh.com"));
        let body = std::fs::read_to_string(&staged.config_path).unwrap();
        assert!(body.contains(SANDBOX_GIT_ALLOWED_SIGNERS));
        assert!(!body.contains(host_signers.path().to_str().unwrap()));
    }
}
