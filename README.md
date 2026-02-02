# secoder backend

## Quick start

Build and run:

```bash
export SECODER_SKIP_K8S=1
cargo build --release
./target/release/secoder -c config.json
```

Check the service:

```bash
curl -s http://localhost:8080/health
```

## Creating users

Users must be predefined in a JSON file and the registration request must
match the predefined `id` + `passwd` entry. Set the path in `config.json`
as `user`.
The frontend must send a `password` field in the registration payload.
The backend salts and hashes this password before storing it.

Example `users.json`:

```json
[
  { "id": "s001", "passwd": "s001" },
  { "id": "s002", "passwd": "s002" }
]
```
