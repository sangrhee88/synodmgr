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
- One or two manager machines: both serve the API on the shared repository and each scrapes
  everything into its own metrics store; copying events and removing old sessions is done by the
  machine holding a lease in the repository (`manager/src/lease.rs`: 15 s, renewed every 5 s, given up
  on a clean stop), so losing either machine loses neither the console nor the metrics.
- Scale: the fleet view comes from a copy each machine refreshes every 10 s (16 control planes at a
  time, 8 s each; failing ones retried every 30 s in their own lane), events are copied 16
  installations at a time, and the storage servers' histograms are dropped from scraping except the
  page server's read latency (`[scrape] storage_histograms`): a real installation of 3 writers is
  about 4,500 series instead of 8,600. Load test (`manager/examples/fakefleet.rs`,
  `manager_scale_check.py`): 300 installations, 900 clusters, two machines, see the results.
- `synodmgr-admin` on the manager machine: `init-admin`, `reset-password`, `verify-audit`,
  `add-installation`, `backup`, `backups`, `restore FILE`.
- `synod-install` (sangrhee88/stage3-neon-m1, branch `manager`) installs it as role `manager`.

- Console (step 4, under way): sign-in and the first password change, Fleet (clusters, writers,
  one-writer databases, hosts), Sessions, Events, Users, Backups, Your account.
- Operator actions, asked for ahead of milestone 2 (`manager/src/api/actions.rs`, control plane API
  level 2): stop, start and restart a one-writer database, one cluster writer or a whole cluster (a
  rolling restart, one writer at a time, each back in the cluster before the next); every writer's
  sessions in one list, with cancel and end session. Stop and restart need the target's name typed,
  a stop needs a reason; Admins only (Viewers may list sessions); each one is audited and its
  control plane events carry the user's ID. The manager won't stop its own repository.
  Checked by `manager_actions_check.py`, and the control plane side under load by `fleet_check.py`.

Next: the remaining console pages, the `synodmgr` CLI, and patching (a rolling Synod upgrade).

## Build and test

    cargo build --release                       # target/release/synod-manager, synodmgr-admin
    cargo test --release                        # unit tests
    SYNODMGR_TEST_DATABASE_URL="host=/var/tmp/synodmgr-pg port=55432 user=postgres" \
        cargo test --release --test api         # the API against a scratch PostgreSQL

Packed into the Synod build with `synod-install package --neon-dir <synod-storage> --manager-dir <this
checkout>`; a machine with role `manager` in the inventory gets it (`installer/test/local3-manager.toml`,
checked by `installer/test/manager_check.py`, `manager_failover.py` (the repository's writer killed)
`manager_backup_check.py` (everything lost, reinstalled, restored) and, with two manager machines
(`local3-manager2.toml`), `manager_ha_check.py` (one machine lost)).

## Layout

- `manager/src/config.rs` the configuration file (`/etc/synodmgr/manager.toml`, written by the installer)
- `manager/src/db.rs` the repository schema
- `manager/src/backup.rs` backups and restore; `lease.rs` the background lease (two machines);
  `fleet.rs` the fleet copy
- `manager/examples/fakefleet.rs` a simulated fleet for load tests
- `manager/src/auth.rs`, `passwords.rs`, `users.rs` sign-in, sessions, accounts
- `manager/src/audit.rs` the audit log
- `manager/src/cplane.rs` the control plane client; `tasks.rs` events and scrape configuration
- `manager/src/api.rs` the API

Related private repos: `sangrhee88/synod-storage` (Synod itself: the control plane, the `synod`
extension, the storage) and `sangrhee88/stage3-neon-m1` (installer and tests).
