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
