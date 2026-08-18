# Install this fork (harry-anderson/OpenShell)

Branch: `feat/ssh-agent-forward`

You need **both** a forked CLI **and** a forked supervisor. CLI-only `ssh -A` is silently ignored by stock NVIDIA russh (no `agent_request`).

## 1. CLI (this machine)

```bash
git clone -b feat/ssh-agent-forward https://github.com/harry-anderson/OpenShell.git
cd OpenShell
cargo build --release -p openshell-cli
# pick one:
sudo install -m 0755 target/release/openshell /usr/local/bin/openshell
# or: cargo install --path crates/openshell-cli --force
openshell --help | grep forward-agent
```

## 2. Supervisor image (k8s / EKS)

```bash
# from the same tree
docker build -f deploy/docker/Dockerfile.supervisor -t ghcr.io/harry-anderson/openshell/supervisor:forward-agent .
docker push ghcr.io/harry-anderson/openshell/supervisor:forward-agent
```

Helm values overlay:

```yaml
supervisor:
  image:
    repository: ghcr.io/harry-anderson/openshell/supervisor
    tag: forward-agent
```

```bash
helm upgrade --install openshell oci://ghcr.io/nvidia/openshell/helm-chart \
  -n openshell \
  -f values-forward-agent.yaml
```

Local Docker gateway: point the gateway config at the same supervisor image, or run a locally built `openshell-sandbox` / supervisor binary if that is how you develop.

## 3. Smoke

```bash
export SSH_AUTH_SOCK=...   # already set if ssh-add -l works
openshell sandbox create --forward-agent --name agent-smoke -- ssh-add -l
openshell sandbox connect agent-smoke --forward-agent
# in sandbox: echo $SSH_AUTH_SOCK  →  /tmp/openshell-ssh-agent/agent.sock
```
