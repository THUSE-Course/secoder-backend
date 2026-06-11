# SECoder backend

## Quick start

Build and run:

```bash
cargo build --release
export SECODER_JWT_SECRET=change-me
export SECODER_WEBHOOK_TOKEN=change-me
./target/release/secoder -c config.json
```

Check metrics:

```bash
curl -s http://localhost:9090/metrics
```

## Rbac

This backend talks to the Kubernetes API and requires a service account with
permissions to:

- Create/get/patch namespaces (to ensure per-user namespaces and labels).
- Create/get secrets in user namespaces (to fetch service account tokens).
- Create clusterrolebindings (to bind users to a configured ClusterRole).

Notes:

- It assumes the user's service account named by `rbac.account` already exists
  in the user namespace; it only creates the token secret and reads it.
- It creates a `ClusterRoleBinding` named `secoder-<user prefix><user id>` that
  binds the `rbac.account` service account in the user’s namespace to
  `rbac.clusterrole`.
- For the backend user id `root`, it binds to `rbac.root_clusterrole` instead.
  This defaults to the Kubernetes built-in `cluster-admin` role.
