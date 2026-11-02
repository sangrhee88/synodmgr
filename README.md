# synodmgr

Synod Manager: the enterprise management tool for Synod RAC clusters, in the role Oracle Enterprise
Manager, srvctl and DBCA play for Oracle RAC. One service the customer runs in their own network shows
every cluster's health and performance, runs admin actions through the Synod control plane, and raises
alerts. A web console and the `synodmgr` CLI share one API.

Design: [docs/design.md](docs/design.md) (the live, commentable version is the Claude Doc "Synod
Manager: design proposal").

## Status (Nov 2, 2026)

Milestone 1, step 3 of the order of work: the manager service, without the console pages yet.

- `synod-manager`: the HTTPS API (`manager/src/api.rs`); its repository is a one-writer Synod database
  ("synodmgr") in the installation, reached over TLS checked against the cluster CA (a writer failover
  costs about 2 s of 503 "try again", then it reconnects by itself); sign-in
  with a user ID and password (Argon2id; 15 to 128 characters, checked against common passwords and
  patterns; 10 failures in a row pause an account for 15 minutes; console sessions end after 30
  minutes idle, every session after 12 hours), Admin and Viewer roles, an append-only audit log whose
  rows are hash-chained, installations (control plane tokens encrypted at rest), the fleet view, the
  control planes' events copied every 5 s, the scrape configuration for VictoriaMetrics, and a
  nightly backup (`manager/src/backup.rs`: the repository, the metrics, the key file and audit anchor,
  in one AES-256-GCM-encrypted file; 7 days kept).
- `synodmgr-admin` on the manager machine: `init-admin`, `reset-password`, `verify-audit`,
  `add-installation`, `backup`, `backups`, `restore FILE`.
- `synod-install` (sangrhee88/stage3-neon-m1, branch `manager`) installs it as role `manager`.

Next: the console pages and the `synodmgr` CLI (step 4).

## Build and test

    cargo build --release                       # target/release/synod-manager, synodmgr-admin
    cargo test --release                        # unit tests
    SYNODMGR_TEST_DATABASE_URL="host=/var/tmp/synodmgr-pg port=55432 user=postgres" \
        cargo test --release --test api         # the API against a scratch PostgreSQL

Packed into the Synod build with `synod-install package --neon-dir <synod-storage> --manager-dir <this
checkout>`; a machine with role `manager` in the inventory gets it (`installer/test/local3-manager.toml`,
checked by `installer/test/manager_check.py`, `manager_failover.py` (the repository's writer killed)
and `manager_backup_check.py` (everything lost, reinstalled, restored)).

## Layout

- `manager/src/config.rs` the configuration file (`/etc/synodmgr/manager.toml`, written by the installer)
- `manager/src/db.rs` the repository schema
- `manager/src/backup.rs` backups and restore
- `manager/src/auth.rs`, `passwords.rs`, `users.rs` sign-in, sessions, accounts
- `manager/src/audit.rs` the audit log
- `manager/src/cplane.rs` the control plane client; `tasks.rs` events and scrape configuration
- `manager/src/api.rs` the API

Related private repos: `sangrhee88/synod-storage` (Synod itself: the control plane, the `synod`
extension, the storage) and `sangrhee88/stage3-neon-m1` (installer and tests).
