# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — 2026-05-22

Large feature and hardening release covering everything developed since the
initial public version (`07e8b73`). Affects `bootstrap_awx.py`, `Dockerfile.awx`,
and `README.md`.

### Added

#### Infisical secrets manager integration (optional)

- Deploy self-hosted Infisical co-located on the AWX host as its own Compose
  stack (`compose/infisical/`) with its own Redis, joining AWX's network and
  **reusing AWX's PostgreSQL** (a dedicated `infisical` role/database is
  provisioned via `docker compose exec` into the AWX postgres container — no
  port exposure).
- TLS termination via a host NGINX vhost using the chosen SSL mode.
- Optional SMTP smart-host relay with `STARTTLS`/`SMTPS` and SMTP auth.
- Seed the instance via the Infisical API (admin user, organization reusing the
  AWX org name, project with default environments); the Infisical admin reuses
  the AWX admin email/password so dialog credentials work.
- Migrate generated secrets (AWX admin/DB passwords, AWX API token, deploy key,
  NetBox token) into the Infisical project.
- Generate the Ansible integration: an `infisical` lookup plugin (stdlib-only,
  Token-Auth or Universal-Auth), an `infisical_*` connection block in
  `group_vars`, and switch the `awx_config` role to read secrets from Infisical
  with local-file fallback.
- Create an AWX **"Infisical" custom credential type + credential** that injects
  the connection (`INFISICAL_URL`, `INFISICAL_TOKEN` or
  `INFISICAL_CLIENT_ID`/`_SECRET`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENV`) into
  job runs and attaches it to the job templates.
- When an existing Machine Identity is supplied (seeding skipped), still ensure
  the configured project exists so the lookup matches.

#### NetBox dynamic inventory (optional)

- Prompt for the NetBox URL and API token; store the token as a secret (migrated
  into Infisical when enabled).
- Enable the NetBox dynamic inventory (`inventories/dynamic/netbox.yml`).
- Add `netbox.netbox` to `collections/requirements.yml` and enable the
  `netbox.netbox.nb_inventory` plugin via an `[inventory] enable_plugins` line in
  `ansible.cfg`.
- Provision it fully in AWX: a `NetBox API Token` custom credential type, a
  credential holding the token, a `NetBox` inventory, and an SCM inventory source
  pointing at the project's `inventories/dynamic/netbox.yml`.
- Associate AWX's managed **Ansible Galaxy** credential with the organization
  (`POST /api/v2/organizations/<id>/galaxy_credentials/`) so project content-sync
  actually installs `collections/requirements.yml` into
  `/runner/requirements_collections`.

#### Authentication and user integration

- Standalone **LDAP / Microsoft AD authentication for AWX** (independent of
  Infisical), provisioned via `PATCH /api/v2/settings/ldap/`.
- AWX ↔ Infisical user-integration choice: `none`, `autoinvite`, or `idp`
  (LDAP/Microsoft AD), with a conditional dialog collecting IdP details.
- Best-effort Infisical LDAP provisioning for the `idp` path (Enterprise/licensed
  feature; manual UI guidance on failure).

#### TLS / reverse proxy

- New `acme_sh` SSL mode: issue/install a certificate with a pre-existing
  `acme.sh` (HTTP-01 via `--nginx`), with acme.sh's own cron handling renewals,
  alongside existing `none` / `provided` / `certbot_http` / `certbot_dns` modes.

#### AWX API bootstrap

- Create a job template for **each playbook** in the synced SCM project that
  lacks one (`Playbook: <name>`, default inventory + machine/Infisical creds
  pre-attached, inventory overridable on launch).
- Set the admin superuser's **First Name / Last Name** from the configured full
  name (split on the first space; AWX has no single "display name" field);
  re-runs backfill the name on existing installs.

#### `--force-pull` is now a full refresh

- Rebuilds the custom AWX/receptor images, **recreates** the containers
  (`up -d --force-recreate`) so they run the freshly built image, **re-seeds**
  the installer-managed scaffold files (`ansible.cfg`,
  `collections/requirements.yml`, `README`, and the `playbooks`/`roles`/
  `inventories` trees) into the project git repo, and **forces an AWX project
  content-sync** plus a NetBox inventory-source refresh.

#### Documentation

- Bilingual (English/German) `README.md` covering all features, CLI parameters,
  configuration questionnaire, execution phases, generated files, and security
  notes.
- This `CHANGELOG.md`.

### Changed

- `ansible.cfg` generation: repo-relative `roles_path = roles` and
  `collections_path = collections:...` (resolve both for local runs and under
  AWX/ansible-runner at `/runner/project`); portable
  `stdout_callback = ansible.builtin.default` + `result_format = yaml` (the
  `yaml` callback was removed in community.general 12.0.0); `lookup_plugins`
  pointed at `plugins/lookup`; `log_path` left unset to avoid a non-writable-log
  warning inside the EE.
- `Dockerfile.awx`: expose `ansible-galaxy` and `ansible-inventory` on PATH (in
  addition to `ansible-runner`/`ansible-playbook`) — required because project
  content-sync runs in the control plane and shells out to `ansible-galaxy`.
- Repo seeding now includes `collections/requirements.yml` (only that file, not
  the vendored `collections/ansible_collections/` tree) and supports re-seeding
  on `--force-pull`.
- Answers/upgrade ergonomics: on re-runs, if the answers file is missing options
  added since it was written, the questionnaire is re-run automatically (previous
  answers pre-loaded) instead of silently defaulting them off.
- `--force-pull` help text expanded to describe the rebuild/recreate/reseed/sync
  behavior.

### Fixed

- **Certbot DNS: `unrecognized arguments: --dns-<x>-propagation-seconds`.** Not
  every third-party plugin (e.g. `certbot-dns-ionos`) registers a
  propagation-seconds option. The flag is now applied best-effort: on an
  argparse rejection (which happens before any ACME request, so it is safe)
  certbot is retried once without it. The known-unsupported `ionos` default was
  also removed.
- **route53 now prompts for AWS credentials.** `certbot-dns-route53` authenticates
  via boto3 (no `--dns-route53-credentials` ini), so the installer prompts for the
  AWS Access Key ID / Secret Access Key and writes them to root's
  `~/.aws/credentials` (where boto3/certbot look at both issue and renewal time).
  Leaving the keys blank falls back to ambient credentials (IAM role / `AWS_*`
  env vars). (`ionos` already prompts for its `dns_ionos_*` credentials ini.)
- **DNS plugin install failed on Debian 13 (`externally-managed-environment`).**
  Certbot DNS plugins are now installed from the native distro package when one
  exists (e.g. `python3-certbot-dns-route53` on Debian/Ubuntu or RHEL+EPEL),
  which sidesteps the PEP-668 pip block entirely and pulls dependencies cleanly.
  Only when no OS package is available does it fall back to pip (bootstrapping
  pip if `pip3` is missing, and adding `--break-system-packages` on
  externally-managed systems). snap-based certbot still uses snap plugins.
- **Infisical SQL import aborted on `unrecognized configuration parameter
  "transaction_timeout"`.** A dump produced by PostgreSQL 17+ `pg_dump` emits
  session GUCs (e.g. `transaction_timeout`) that an older target server (the
  default `postgres:16`) rejects, which aborted the import under
  `ON_ERROR_STOP=1`. The importer now strips those harmless session settings
  before loading (keeping `ON_ERROR_STOP` for real errors) and, on any remaining
  "unrecognized configuration parameter" failure, points at the PostgreSQL
  major-version mismatch.
- **Websocket broadcast relay spammed `Connect call failed ...:443`.** AWX's
  `awx.main.wsrelay` defaults to `https://<web>:443`, but the `awx_web` container
  serves plain HTTP on port 80 over the internal docker network, so the
  task→web relay connection was refused (breaking live job-output streaming).
  The generated AWX `settings.py` now sets `BROADCAST_WEBSOCKET_PROTOCOL='http'`,
  `BROADCAST_WEBSOCKET_PORT=80`, `BROADCAST_WEBSOCKET_VERIFY_CERT=False` (mounted
  into both the web and task containers).
- **Login over plain HTTP (`ssl_mode: none`) failed with a missing CSRF header.**
  The generated AWX `settings.py` now emits `CSRF_TRUSTED_ORIGINS` for the
  deployment's scheme/host(/port), sets `SECURE_PROXY_SSL_HEADER` (so Django
  computes `request.is_secure()` correctly behind the nginx proxy), and turns
  off `SESSION_COOKIE_SECURE`/`CSRF_COOKIE_SECURE` when no TLS is used — so the
  browser keeps the CSRF cookie and the login POST carries `X-CSRFToken`.
- **Adding a DNS provider via git URL failed with `pip3: command not found`.**
  DNS plugins are now installed via `python -m pip` into the interpreter certbot
  actually uses (resolved from certbot's shebang), bootstrapping pip via
  `ensurepip`/`python3-pip` when absent and adding `--break-system-packages` on
  PEP-668 externally-managed systems. snap-based certbot installs published
  plugins via `snap` instead, with a clear error when a custom git/pip plugin is
  requested under snap.

### Added (deploy key & Infisical import)

- **Password-protected SSH deploy keys.** When generating a deploy key the
  installer now asks whether to protect it with a passphrase; when reusing an
  existing/supplied key it detects encryption and prompts for the passphrase
  (verifying it unlocks the key). The passphrase is stored in the state file and
  a `secrets/deploy_key_passphrase` (0600, never pushed to SCM), migrated to
  Infisical (`AWX_DEPLOY_KEY_PASSPHRASE`), passed to AWX's Machine and Source
  Control credentials as `ssh_key_unlock` (both the Python and playbook paths),
  and used to transparently unlock the key for the installer's own git
  operations (a throwaway decrypted copy is used for the clone/push and removed
  immediately after).
- **Import data from a previous Infisical instance.** When deploying Infisical
  the installer offers to import a PostgreSQL dump (default
  `~ansible/infisical.sql`) into the freshly provisioned database before the
  container starts, prompting for the old `ENCRYPTION_KEY`/`AUTH_SECRET` and
  reusing them (instead of generating new ones) so the imported, encrypted
  secrets stay decryptable. An optional Redis dump (`dump.rdb`) is staged into
  the Infisical Redis volume. Fresh bootstrap seeding/secret-migration is skipped
  in import mode so the imported admin/org/projects are preserved.

### Added (DNS)

- Expanded the Certbot DNS provider list to ~30 verified plugins, presented as a
  menu in the dialog (plus a `custom` option for any pip package or git URL with
  an operator-supplied authenticator name). Each provider's credential keys are
  prompted for and written automatically; optional fields, ambient-credential
  providers (Route 53), and file-based credentials (Google service-account JSON)
  are handled, and the correct `--authenticator`/propagation flags are passed to
  certbot.

- `awx_config` role generator: removed the invalid `awx.awx` role dependency from
  role meta (it is a collection used via FQCN) and dropped the dead
  `community.docker` handler reference.
- README markdown lint: resolved all `markdownlint` findings (MD012/MD022/MD032
  list/heading spacing, MD013 line length, MD033 inline HTML) — the file now
  lints clean.

### Notes

- The job-log line `[DEPRECATION WARNING]: ANSIBLE_COLLECTIONS_PATHS option ...`
  is **not** caused by this project's `ansible.cfg` (which uses the singular
  `collections_path`). The AWX controller itself injects the legacy plural
  `ANSIBLE_COLLECTIONS_PATHS` env var into every job environment (see `build_env`
  in `awx/main/tasks/jobs.py`); it is cosmetic and not removable from the EE or
  project config. Deprecation warnings are intentionally left enabled.
