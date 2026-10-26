# harry-anderson/OpenShell

Branch: `feat/ssh-agent-forward-upstream`

This is current NVIDIA `main` plus opt-in SSH agent forwarding. The workload
and the supervisor do not share a mount namespace, so the agent socket is
bound inside the workload and bridged back to the supervisor SSH session.

You need this CLI and this supervisor together. A stock supervisor ignores
`auth-agent-req@openssh.com`.

```bash
cargo build --release -p openshell-cli
openshell sandbox create --forward-agent --name agent-smoke -- echo ready
openshell sandbox connect agent-smoke --forward-agent
```

Inside the sandbox, `ssh-add -l` should show the host agent. `SSH_AUTH_SOCK`
is `/tmp/openshell-ssh-agent/agent.sock`. Git signing uses
`gpg.ssh.defaultKeyCommand=ssh-add -L` and does not copy a private key.

The architecture, the fail-closed gates, and how `smartcontractkit/openshell`
`swe/` consumes this (including the legacy `:9922` relay) are in
[docs/how-it-works/sandboxes/ssh-agent-forwarding.mdx](docs/how-it-works/sandboxes/ssh-agent-forwarding.mdx).
