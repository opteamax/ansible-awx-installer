# AWX Bootstrap Project

English and German project documentation for the AWX bootstrap automation.

---

## English

### 1. Project Purpose

This project provides a production-oriented bootstrap script for deploying and
operating an Ansible AWX stack on a Linux host.

Main goals:

- Automated installation and configuration of AWX with Docker Compose
- Idempotent reruns with state tracking
- Integrated NGINX reverse proxy and TLS support
- Automated AWX API bootstrap (organization, credentials, project, inventory,
  host, template)
- Git repository readiness checks and optional scaffold population
- Operational smoke tests and human-readable summary output

Primary script:

- bootstrap_awx.py

Container image customization:

- Dockerfile.awx
- Dockerfile.receptor

### 2. Supported Platforms and Requirements

Supported OS targets:

- RHEL 9
- Debian 13
- Ubuntu 22.04
- Ubuntu 24.04

Runtime requirements:

- Python 3.9 or higher
- Root privileges
- Internet access (for packages and images)
- Docker runtime available or installable

### 3. High-Level Architecture

The bootstrap deploys these core services:

- awx_web
- awx_task
- awx_receptor
- postgres
- redis

Integration components:

- Host NGINX reverse proxy
- Optional Certbot certificate management
- AWX API token creation and resource provisioning

Runtime data and generated assets are stored under:

- /home/ansible (default)

### 4. Core Features

#### 4.1 Idempotent orchestration

- Uses a state file to track completed phases
- Supports reruns without repeating unnecessary work
- Can recover from partial previous runs

#### 4.2 Platform-aware provisioning

- Detects platform and applies package/service management accordingly
- Detects FIPS and SELinux mode

#### 4.3 Docker + AWX deployment

- Installs Docker if needed
- Generates Docker Compose runtime files
- Starts and validates container set

#### 4.4 AWX image hardening/customization

- Custom AWX image includes podman tooling
- Adds `ansible-runner`, `ansible-playbook`, `ansible-galaxy`, and
  `ansible-inventory` to the PATH (the latter two are required because project
  content-sync runs in the control plane and shells out to `ansible-galaxy`)
- Includes receptor binary in AWX image
- Applies AWX jobs.py patch to avoid problematic nested process isolation for
  project updates

#### 4.5 Database handling

- Supports containerized PostgreSQL or external PostgreSQL
- Synchronizes database user/password state safely

#### 4.6 Reverse proxy and TLS

- Generates NGINX configuration
- Supports SSL modes:
  - none
  - provided
  - certbot_http
  - certbot_dns
  - acme_sh — issue/install a certificate with a pre-existing acme.sh
    (HTTP-01 via `--nginx`); prompts for the acme.sh base directory. acme.sh's
    own cron handles renewals.
- Supports ~30 known DNS providers for Certbot DNS plugins (Cloudflare, Route 53,
  Google Cloud DNS, DigitalOcean, OVH, Hetzner, Gandi, Linode, netcup, IONOS,
  GoDaddy, deSEC, Porkbun, INWX, Vultr, RFC2136, and more), selectable from a
  menu in the dialog. Required credentials are prompted for and the credentials
  file is generated automatically; ambient-credential providers (Route 53) and
  file-based credentials (Google service-account JSON) are handled, and a
  `custom` choice installs any other plugin from a pip package or git URL.
  Plugins are installed from the native distro package when one exists (e.g.
  `python3-certbot-dns-route53` on Debian/Ubuntu or RHEL+EPEL) — which avoids the
  Debian 13 / PEP-668 `externally-managed-environment` pip block; otherwise they
  fall back to pip into the environment certbot runs from (pip is bootstrapped if
  missing and `--break-system-packages` is used on externally-managed systems).
  snap-based certbot uses snap plugins.
- For `none` (plain HTTP) deployments, AWX is configured with the matching
  `CSRF_TRUSTED_ORIGINS` and non-secure session/CSRF cookies so login works
  without TLS.
- The generated `ansible.cfg` uses repo-relative `roles_path = roles` and
  `collections_path = collections:...` (so roles/collections resolve both for
  local runs and under AWX/ansible-runner at `/runner/project`), sets a portable
  `stdout_callback = ansible.builtin.default` + `result_format = yaml` (the
  `yaml` callback was removed in community.general 12.0.0), and points
  `lookup_plugins` at `plugins/lookup`.

#### 4.7 AWX API bootstrap

- Creates OAuth token
- Ensures organization
- Ensures the admin superuser, setting its **First Name / Last Name** from the
  configured full name (split on the first space; AWX has no single
  "display name" field). Re-runs backfill the name on existing installs
- Ensures machine and SCM credentials
- Ensures project, inventory, and host
- Creates a job template for **each playbook** in the synced SCM project that
  doesn't already have one (name `Playbook: <name>`, default inventory +
  machine and Infisical credentials pre-attached, inventory overridable on
  launch). Idempotent and non-fatal; runs after the project sync.
- Generates `collections/requirements.yml` (the path AWX content sync /
  ansible-runner installs from) listing `awx.awx`
- Role generator fixes: the `awx_config` role meta has no invalid `awx.awx`
  role dependency (it is a collection, used via FQCN), and its handlers no
  longer reference `community.docker`

#### 4.8 Git project repository safety and onboarding

- Prints generated deploy public key for Git authorization
- Enforces key confirmation logic before repository validation/population
- Checks if target project repository is blank or incomplete
- Offers/executes scaffold population from local generated bootstrap content
- Does not clone seed content from the currently used AWX test/development repository

#### 4.9 Scheduler resilience fix

- Automatically ensures AWX controlplane queue exists
- Prevents project updates from getting stuck pending due to missing controlplane
  instance group

#### 4.10 Validation and reporting

- Performs smoke tests (container health, API ping/auth, NGINX, TLS expiry,
  PostgreSQL readiness, syntax check)
- Prints a final operations summary including deploy public key and key file locations

#### 4.11 Infisical secrets manager (optional)

- Optionally deploys self-hosted Infisical co-located on the AWX host
- Runs as its own compose stack (`compose/infisical/`) with its own Redis,
  joining AWX's compose network and **reusing AWX's PostgreSQL** (a dedicated
  `infisical` role/database is provisioned via `docker compose exec` into the
  AWX postgres container — no port exposure needed)
- Generates its secrets (encryption key, auth secret, DB password) into
  `secrets/infisical/`; the Infisical admin uses the **same email/password as
  the AWX admin** so the dialog credentials work
- Terminates TLS via a host NGINX vhost using the chosen SSL mode (incl. acme.sh)
- Optional SMTP smart-host relay with `STARTTLS` or `SMTPS` transport and
  SMTP_AUTH credentials
- Seeds the instance via the Infisical API: admin user, organization (reusing
  the AWX organization name), and a project with default environments
- Migrates generated secrets (AWX admin/DB passwords, AWX API token, deploy key,
  NetBox token) into the Infisical project
- Generates the ansible integration: an `infisical` lookup plugin, an
  `infisical_*` connection block in group_vars, and switches the `awx_config`
  role to read secrets from Infisical when available, falling back to local files
- Creates an AWX **"Infisical" custom credential type + credential** that injects
  the connection (`INFISICAL_URL`, `INFISICAL_TOKEN` or `INFISICAL_CLIENT_ID`/
  `_SECRET`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENV`) into job runs and attaches
  it to the job template — so the lookup uses the seeded project automatically,
  with no manual environment setup
- When an existing Machine Identity (`infisical_client_id`) is supplied (seeding
  skipped), still ensures the configured project exists so the lookup matches
- **Import from a previous Infisical instance:** optionally loads a PostgreSQL
  dump (`pg_dump`, default `~ansible/infisical.sql`) into the freshly
  provisioned database before the container starts, reusing the old
  `ENCRYPTION_KEY`/`AUTH_SECRET` you supply (so the imported encrypted secrets
  stay decryptable) instead of generating new ones. An optional Redis dump
  (`dump.rdb`) is staged into the Infisical Redis volume. In import mode the
  fresh bootstrap seeding and secret migration are skipped so the imported
  admin/org/projects/secrets are preserved

#### 4.12 NetBox dynamic inventory (optional)

- Prompts for the NetBox URL and API token
- Stores the token as a secret (and migrates it into Infisical when enabled)
- Enables the NetBox dynamic inventory (`inventories/dynamic/netbox.yml`)
- Adds `netbox.netbox` to `collections/requirements.yml` and enables the
  `netbox.netbox.nb_inventory` plugin via an `[inventory] enable_plugins` line
  in `ansible.cfg`, so the source passes the inventory plugin's `verify_file()`
  inside the execution environment (otherwise `ansible-inventory` reports
  `auto declined parsing .../netbox.yml as it did not pass its verify_file()`)
- Associates AWX's managed **Ansible Galaxy** credential with the organization
  (`POST /api/v2/organizations/<id>/galaxy_credentials/`) so project
  content-sync actually installs `collections/requirements.yml` (including
  `netbox.netbox`) into `/runner/requirements_collections`. A freshly created
  org has an empty `galaxy_credentials` list, so without this the collection is
  never installed and the plugin fails to load at inventory time — note this
  requires the AWX task containers to reach `galaxy.ansible.com` (or use a
  custom EE that bakes the collection in instead)
- Provisions it completely in AWX during bootstrap: a custom credential type
  injecting `NETBOX_TOKEN`, a credential holding the token, a `NetBox`
  inventory, and an SCM inventory source pointing at the project's
  `inventories/dynamic/netbox.yml`

#### 4.13 Authentication and user integration

- Standalone option to enable **LDAP / Microsoft AD authentication for AWX**
  (independent of Infisical), provisioned via `PATCH /api/v2/settings/ldap/`
- AWX ↔ Infisical user integration choice:
  - `none` — independent user stores (only the shared admin is aligned)
  - `autoinvite` — invite AWX users into the Infisical project via its API
    (accounts only; passwords are not synced — Infisical uses SRP)
  - `idp` — both use a shared LDAP/AD directory; AWX LDAP is configured and
    Infisical LDAP is attempted (best-effort: Infisical LDAP is an Enterprise/
    licensed feature, so on failure manual UI setup guidance is logged)
- LDAP/AD connection details are collected once and shared between AWX and
  Infisical when both use the directory

#### 4.14 Answers/upgrade ergonomics

- On re-runs, if the answers file is missing options that were added since it
  was written (e.g. a new feature), the questionnaire is re-run automatically
  (previous answers pre-loaded as defaults) instead of silently defaulting them
  off — no `--reconfigure` required

### 5. Command Line Parameters

bootstrap_awx.py supports:

- --home
  - Purpose: Set Ansible home directory
  - Default: /home/ansible

- --force-secrets
  - Purpose: Regenerate secrets even if present

- --force-pull
  - Purpose: Force image preparation even if already completed in a previous run
  - Effect: re-pulls base images, **rebuilds** the custom AWX/receptor images
    from their Dockerfiles, **recreates** the containers (`up -d
    --force-recreate`) so they actually run the freshly built image, and
    **re-seeds** the installer-managed scaffold files (`ansible.cfg`,
    `collections/requirements.yml`, `README`, and the
    `playbooks`/`roles`/`inventories` trees) into the project git repo even when
    it is already populated (only the delta is committed/pushed), and **forces an
    AWX project content-sync** (plus a NetBox inventory-source refresh) so the
    reseeded content is checked out instead of AWX's last synced revision
  - Use when: you changed `Dockerfile.awx`/`Dockerfile.receptor` (e.g. to add a
    tool to the control plane), or installer-side fixes to `ansible.cfg` /
    `collections/requirements.yml` need to reach the project repo AWX syncs
    from. Without this, a re-run keeps the existing image, containers, and
    already-seeded repo, so changes appear to have "no effect"

- --fresh-reinstall
  - Purpose: Destroy generated runtime data and reinstall from scratch
  - Prompts for confirmation unless non-interactive

- --non-interactive
  - Purpose: Non-interactive mode for automation
  - Important: repository key confirmation requires explicit override flag

- --reconfigure
  - Purpose: Re-run interactive questionnaire even when stored answers exist

- --assume-git-key-ready
  - Purpose: In non-interactive mode, bypass interactive key confirmation prompt
  - Use only when deploy key access has already been granted

### 6. Configuration Parameters (Interactive Questionnaire)

The script collects and persists non-secret parameters (in .answers.json) and
stores operational state in bootstrap_state.json.

Identity:

- fqdn
- admin_email

SSL/TLS:

- ssl_mode (none | provided | certbot_http | certbot_dns | acme_sh)
- ssl_cert_path (provided mode)
- ssl_key_path (provided mode)
- certbot_email
- certbot_dns_provider (a known provider name or `custom`)
- certbot_dns_plugin_source (custom provider: pip package or git URL)
- certbot_dns_plugin_name (custom provider: certbot authenticator name, e.g. `dns-foo`)
- acme_sh_basedir (acme_sh mode)

Authentication (LDAP / Microsoft AD — optional, independent of Infisical):

- ldap_enabled
- ldap_server_uri, ldap_start_tls
- ldap_bind_dn, ldap_bind_password (secret, not stored in answers file)
- ldap_user_search_base, ldap_user_search_filter
- ldap_group_search_base (optional)
- ldap_email_attr, ldap_first_name_attr, ldap_last_name_attr

Database:

- db_mode
- db_host
- db_port
- db_name
- db_user

AWX:

- awx_organization_name
- awx_admin_login
- awx_admin_name
- awx_admin_email
- awx_admin_password (secret, not stored in answers file)
- awx_listen_port

Git:

- git_ssh_url
- git_branch
- deploy key passphrase (optional): when generating a key you are asked whether
  to encrypt it; when reusing an existing/supplied key, encryption is detected
  and the passphrase prompted. Stored as a secret (not in the answers file),
  passed to AWX as `ssh_key_unlock`, and used to unlock the key for the
  installer's own git operations

Image tags:

- awx_image_tag
- redis_image_tag
- postgres_image_tag

Network:

- nginx_http_port
- nginx_https_port
- expose_postgres_port

Optional integration:

- netbox_url
- netbox_token (secret, not stored in answers file)

Infisical (optional secrets manager):

- infisical_enabled
- infisical_fqdn, infisical_image
- infisical_smtp_host, infisical_smtp_port, infisical_smtp_protocol (STARTTLS|SMTPS),
  infisical_smtp_user, infisical_smtp_password (secret), infisical_smtp_from_address,
  infisical_smtp_from_name
- infisical_client_id (+ infisical_client_secret, secret) — only if you already
  have a Universal Auth Machine Identity; otherwise one is created during seeding
- infisical_project_name, infisical_env_slug
- infisical_user_sync (none | autoinvite | idp)
- infisical_import_enabled (+ infisical_import_sql_path, infisical_import_redis_path)
  — import a previous instance's PostgreSQL/Redis dump; the old
  `ENCRYPTION_KEY`/`AUTH_SECRET` are prompted as secrets and reused so imported
  secrets stay decryptable

Secrets are kept out of .answers.json and stored under secrets/ (and in state).

### 7. Execution Phases

Major phases in order:

- Parameter collection and persistence
- Preflight checks
- Docker installation
- System user and directory preparation
- Secrets and deploy key handling
- File generation
- Optional repository population check
- NGINX and firewall setup
- Certbot setup (if selected)
- Image preparation
- Container startup and migrations
- AWX API bootstrap
- NetBox dynamic inventory provisioning (when configured)
- AWX LDAP/AD configuration (when enabled)
- Infisical deploy → DB provisioning → cert → vhost → compose up (when enabled)
- Infisical seeding (admin/org/project), secret migration, and user integration
  (autoinvite / Infisical LDAP) (when enabled)
- Final NGINX reload
- Smoke tests and summary

Note: certbot/acme.sh issue a certificate per FQDN; when Infisical is enabled a
separate certificate is obtained for the Infisical FQDN.

### 8. Generated Files and Directories

Common generated locations under Ansible home:

- compose/awx/docker-compose.yml
- compose/awx/.env
- config/bootstrap_state.json
- config/awx_settings.py
- config/receptor.conf
- `nginx/<fqdn>.conf`
- secrets/.awx.env
- secrets/.db.env
- secrets/.api_token
- keys/deploy_key
- keys/deploy_key.pub
- logs/bootstrap.log
- playbooks, roles, inventories scaffold
- collections/requirements.yml
- plugins/lookup/infisical.py (when Infisical is enabled)
- inventories/dynamic/netbox.yml (enabled) or netbox.yml.disabled (stub)

When Infisical is enabled:

- compose/infisical/docker-compose.yml
- compose/infisical/.env (secret)
- nginx/<infisical_fqdn>.conf
- secrets/infisical/{encryption_key,auth_secret,db_password,admin_password,admin_token}

Other secret files (mode 600), when the related feature is configured:

- secrets/netbox/token
- secrets/ldap/bind_password

Project-local support files:

- Dockerfile.awx
- Dockerfile.receptor

### 9. Typical Usage

Interactive setup:

- sudo python3 bootstrap_awx.py --home /home/ansible --reconfigure

Full rebuild from scratch:

- sudo python3 bootstrap_awx.py --home /home/ansible --fresh-reinstall --reconfigure

Automation mode:

- sudo python3 bootstrap_awx.py --home /home/ansible --non-interactive --assume-git-key-ready

### 10. Operational Notes

- If project sync appears stuck pending, ensure controlplane queue and instance
  group exist.
- If Git access fails, verify deploy key authorization in the Git provider.
- For non-interactive CI usage, provide all required values in stored
  configuration and use key-ready override only after access is granted.
- A job-log line `[DEPRECATION WARNING]: ANSIBLE_COLLECTIONS_PATHS option ... use
  the singular form ANSIBLE_COLLECTIONS_PATH instead` is harmless and is **not**
  caused by this project's `ansible.cfg` (which already uses the singular
  `collections_path` ini key). The AWX controller itself injects the legacy plural
  `ANSIBLE_COLLECTIONS_PATHS` env var into every job environment (see `build_env`
  in `awx/main/tasks/jobs.py`), deliberately setting both the plural and singular
  forms for backward compatibility. It is emitted before the execution environment
  starts, so no EE image or project-config change removes it; deprecation warnings
  are intentionally left enabled so genuine ones still surface.

### 11. Security Notes

- Do not commit secrets from generated runtime directories.
- Keep private key files protected by file permissions.
- Use dedicated deploy keys per environment.
- Review and minimize privileged container settings in production security reviews.
- Infisical/NetBox/LDAP secrets live under secrets/ (mode 600) and, when
  Infisical is enabled, are also migrated into the Infisical project. The
  Infisical admin token (secrets/infisical/admin_token) is an instance-admin
  credential — protect it accordingly.
- The Infisical admin reuses the AWX admin password; choose a strong one (it
  must also satisfy Infisical's password policy).
- LDAP bind password and NetBox token are excluded from .answers.json and kept
  only in the state file / secret files.
- The installer auto-creates an AWX "Infisical" credential that injects the
  connection (URL/token/project/env) and attaches it to the generated job
  template, so Infisical-backed secrets work immediately. Attach that same
  credential to any additional job templates that need Infisical lookups;
  without it, the awx_config role falls back to local files.

---

## Deutsch

### 1. Projektziel

Dieses Projekt stellt ein produktionsorientiertes Bootstrap-Skript zur
Verfügung, um einen Ansible AWX Stack auf einem Linux-Host automatisiert
bereitzustellen und zu betreiben.

Hauptziele:

- Automatisierte Installation und Konfiguration von AWX per Docker Compose
- Idempotente Wiederholbarkeit mit Zustandsverwaltung
- Integrierter NGINX Reverse Proxy und TLS-Unterstützung
- Automatischer AWX API Bootstrap (Organisation, Credentials, Projekt, Inventory,
  Host, Template)
- Prüfung der Git-Repository-Bereitschaft und optionale Initialbefüllung
- Smoke-Tests und gut lesbare Abschlussausgabe

Zentrales Skript:

- bootstrap_awx.py

Container-Image-Anpassungen:

- Dockerfile.awx
- Dockerfile.receptor

### 2. Unterstützte Plattformen und Voraussetzungen

Unterstützte Zielsysteme:

- RHEL 9
- Debian 13
- Ubuntu 22.04
- Ubuntu 24.04

Laufzeitvoraussetzungen:

- Python 3.9 oder höher
- Root-Rechte
- Internetzugang (Pakete und Images)
- Docker Runtime vorhanden oder installierbar

### 3. Architektur auf hoher Ebene

Das Bootstrap deployt diese Kernservices:

- awx_web
- awx_task
- awx_receptor
- postgres
- redis

Integrationskomponenten:

- Host-NGINX Reverse Proxy
- Optionale Certbot Zertifikatsverwaltung
- AWX API Token-Erstellung und Ressourcenvorbereitung

Laufzeitdaten und generierte Artefakte liegen standardmäßig unter:

- /home/ansible

### 4. Kernfunktionen

#### 4.1 Idempotente Orchestrierung

- Verwendet eine State-Datei für abgeschlossene Phasen
- Wiederholte Läufe ohne unnötige Duplikate
- Recovery bei unvollständigen vorherigen Läufen

#### 4.2 Plattformabhängige Provisionierung

- Erkennung des Betriebssystems und passende Paket-/Service-Logik
- Erkennung von FIPS und SELinux Modus

#### 4.3 Docker + AWX Deployment

- Installiert Docker bei Bedarf
- Generiert Docker Compose Runtime-Dateien
- Startet und validiert den Container-Stack

#### 4.4 AWX Image Härtung/Anpassung

- Eigenes AWX Image mit podman Tooling
- Ergänzt `ansible-runner`, `ansible-playbook`, `ansible-galaxy` und
  `ansible-inventory` im PATH (die letzten beiden sind nötig, weil der
  Project-Content-Sync in der Control Plane läuft und `ansible-galaxy` aufruft)
- Integriert receptor Binary ins AWX Image
- Patcht AWX jobs.py, um problematische verschachtelte Process-Isolation bei
  Project-Updates zu vermeiden

#### 4.5 Datenbank-Handling

- Unterstützt containerisierte oder externe PostgreSQL Instanz
- Synchronisiert DB-User/Passwort robust und idempotent

#### 4.6 Reverse Proxy und TLS

- Generiert NGINX Konfiguration
- Unterstützt SSL Modi:
  - none
  - provided
  - certbot_http
  - certbot_dns
  - acme_sh — Zertifikat über ein vorhandenes acme.sh ausstellen/installieren
    (HTTP-01 via `--nginx`); fragt das acme.sh-Basisverzeichnis ab. Erneuerung
    übernimmt der acme.sh-eigene Cron.
- Unterstützt ~30 bekannte DNS-Provider für Certbot-DNS-Plugins (Cloudflare,
  Route 53, Google Cloud DNS, DigitalOcean, OVH, Hetzner, Gandi, Linode, netcup,
  IONOS, GoDaddy, deSEC, Porkbun, INWX, Vultr, RFC2136 u. a.), auswählbar über ein
  Menü im Dialog. Die benötigten Zugangsdaten werden abgefragt und die
  Credentials-Datei automatisch erzeugt; Provider mit Umgebungs-Credentials
  (Route 53) und dateibasierte Credentials (Google Service-Account-JSON) werden
  ebenso unterstützt. Mit der Auswahl `custom` lässt sich jedes weitere Plugin
  aus einem pip-Paket oder einer Git-URL installieren. Plugins werden bevorzugt
  aus dem nativen Distributionspaket installiert, sofern vorhanden (z. B.
  `python3-certbot-dns-route53` unter Debian/Ubuntu oder RHEL+EPEL) — das umgeht
  die PEP-668-Sperre (`externally-managed-environment`) unter Debian 13;
  andernfalls Fallback auf pip in der certbot-Umgebung (pip wird bei Bedarf
  bereitgestellt, `--break-system-packages` auf externally-managed-Systemen).
  Snap-certbot nutzt Snap-Plugins.
- Bei `none` (reines HTTP) wird AWX mit passenden `CSRF_TRUSTED_ORIGINS` und
  nicht-sicheren Session-/CSRF-Cookies konfiguriert, damit der Login ohne TLS
  funktioniert.
- Die generierte `ansible.cfg` nutzt repo-relative `roles_path = roles` und
  `collections_path = collections:...` (damit Rollen/Collections lokal und unter
  AWX/ansible-runner unter `/runner/project` aufgelöst werden), setzt ein
  portables `stdout_callback = ansible.builtin.default` + `result_format = yaml`
  (das `yaml`-Callback wurde in community.general 12.0.0 entfernt) und setzt
  `lookup_plugins` auf `plugins/lookup`.

#### 4.7 AWX API Bootstrap

- Erstellt OAuth Token
- Stellt Organisation sicher
- Stellt den Admin-Superuser sicher und setzt **Vor-/Nachname** aus dem
  konfigurierten vollständigen Namen (Trennung am ersten Leerzeichen; AWX hat
  kein einzelnes „Anzeigename"-Feld). Erneute Läufe ergänzen den Namen auch bei
  bestehenden Installationen
- Stellt Machine- und SCM-Credentials sicher
- Stellt Projekt, Inventory und Host sicher
- Erstellt ein Job Template für **jedes Playbook** im synchronisierten SCM-Projekt,
  das noch keines hat (Name `Playbook: <name>`, Standard-Inventory + Machine- und
  Infisical-Credentials vorab zugewiesen, Inventory beim Start überschreibbar).
  Idempotent und non-fatal; läuft nach dem Projekt-Sync.
- Generiert `collections/requirements.yml` (der Pfad, von dem AWX-Content-Sync /
  ansible-runner installieren) mit `awx.awx`
- Korrekturen am Rollen-Generator: das `awx_config`-Meta hat keine ungültige
  `awx.awx`-Rollen-Abhängigkeit mehr (es ist eine Collection, FQCN-genutzt) und
  die Handler referenzieren kein `community.docker` mehr

#### 4.8 Git Projekt-Repository Onboarding und Schutz

- Gibt den generierten Deploy Public Key aus
- Erzwingt Key-Bestätigungslogik vor Repository-Prüfung/Befüllung
- Prüft, ob Ziel-Repository leer oder unvollständig ist
- Bietet Befüllung aus lokal generiertem Bootstrap-Scaffold an bzw. führt sie aus
- Nutzt nicht das aktuell verwendete AWX Test-/Entwicklungs-Repository als Seed-Quelle

#### 4.9 Scheduler-Resilienzfix

- Stellt automatisch die AWX controlplane Queue sicher
- Verhindert hängende Project-Updates im pending Status bei fehlender controlplane
  Instance Group

#### 4.10 Validierung und Reporting

- Smoke-Tests (Container-Health, API Ping/Auth, NGINX, TLS-Laufzeit, PostgreSQL
  Readiness, Syntax-Check)
- Abschlussbericht inkl. Deploy Public Key und Dateipfaden

#### 4.11 Infisical Secrets-Manager (optional)

- Deployt optional ein selbst gehostetes Infisical auf dem AWX-Host
- Läuft als eigener Compose-Stack (`compose/infisical/`) mit eigenem Redis, tritt
  dem AWX-Compose-Netzwerk bei und **nutzt die PostgreSQL von AWX mit** (eine
  dedizierte `infisical`-Rolle/-Datenbank wird per `docker compose exec` im
  AWX-Postgres-Container angelegt — keine Port-Freigabe nötig)
- Generiert Secrets (Encryption Key, Auth Secret, DB-Passwort) unter
  `secrets/infisical/`; der Infisical-Admin nutzt **dieselbe E-Mail/Passwort wie
  der AWX-Admin**
- TLS-Terminierung über einen Host-NGINX-vhost mit dem gewählten SSL-Modus (inkl.
  acme.sh)
- Optionaler SMTP-Smarthost mit `STARTTLS` oder `SMTPS` und SMTP_AUTH-Zugangsdaten
- Seedet die Instanz über die Infisical-API: Admin-User, Organisation (gleicher
  Name wie die AWX-Organisation) und ein Projekt mit Standard-Environments
- Migriert generierte Secrets (AWX-Admin/DB-Passwörter, AWX-API-Token, Deploy-Key,
  NetBox-Token) in das Infisical-Projekt
- Generiert die Ansible-Integration: ein `infisical`-Lookup-Plugin, einen
  `infisical_*`-Verbindungsblock in group_vars und stellt die `awx_config`-Rolle
  so um, dass sie Secrets aus Infisical liest (Fallback auf lokale Dateien)
- Erstellt einen AWX **„Infisical"-Custom-Credential-Type + Credential**, der die
  Verbindung (`INFISICAL_URL`, `INFISICAL_TOKEN` bzw. `INFISICAL_CLIENT_ID`/
  `_SECRET`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENV`) in Job-Läufe injiziert und
  ihn an das Job Template hängt — damit der Lookup ohne manuelle Umgebung das
  geseedete Projekt nutzt
- Bei vorhandener Machine Identity (`infisical_client_id`, Seeding übersprungen)
  wird das konfigurierte Projekt dennoch sichergestellt, damit der Lookup passt
- **Import einer früheren Infisical-Instanz:** optional wird ein
  PostgreSQL-Dump (`pg_dump`, Standard `~ansible/infisical.sql`) vor dem Start des
  Containers in die frisch provisionierte Datenbank geladen. Die alten
  `ENCRYPTION_KEY`/`AUTH_SECRET` werden abgefragt und wiederverwendet (statt neue
  zu erzeugen), damit die importierten verschlüsselten Secrets entschlüsselbar
  bleiben. Ein optionaler Redis-Dump (`dump.rdb`) wird in das Infisical-Redis-
  Volume eingespielt. Im Import-Modus werden das frische Bootstrap-Seeding und die
  Secret-Migration übersprungen, damit Admin/Org/Projekte/Secrets erhalten bleiben

#### 4.12 NetBox Dynamic Inventory (optional)

- Fragt NetBox-URL und API-Token ab
- Speichert das Token als Secret (und migriert es bei aktivem Infisical dorthin)
- Aktiviert das NetBox Dynamic Inventory (`inventories/dynamic/netbox.yml`)
- Ergänzt `netbox.netbox` in `collections/requirements.yml` und aktiviert das
  Plugin `netbox.netbox.nb_inventory` über eine `[inventory] enable_plugins`-
  Zeile in `ansible.cfg`, damit die Quelle im Execution Environment das
  `verify_file()` des Inventory-Plugins besteht (andernfalls meldet
  `ansible-inventory`: `auto declined parsing .../netbox.yml as it did not pass
  its verify_file()`)
- Verknüpft das von AWX verwaltete **Ansible-Galaxy**-Credential mit der
  Organisation (`POST /api/v2/organizations/<id>/galaxy_credentials/`), damit
  der Project-Content-Sync `collections/requirements.yml` (inkl.
  `netbox.netbox`) tatsächlich nach `/runner/requirements_collections`
  installiert. Eine frisch angelegte Organisation hat eine leere
  `galaxy_credentials`-Liste — ohne diese Verknüpfung wird die Collection nie
  installiert und das Plugin lädt zur Inventory-Zeit nicht. Voraussetzung: Die
  AWX-Task-Container erreichen `galaxy.ansible.com` (oder ein Custom EE mit
  einkompilierter Collection wird verwendet)
- Provisioniert es während des Bootstraps vollständig in AWX: ein Custom
  Credential Type (injiziert `NETBOX_TOKEN`), ein Credential mit dem Token, ein
  `NetBox`-Inventory und eine SCM-Inventory-Source auf
  `inventories/dynamic/netbox.yml`

#### 4.13 Authentifizierung und User-Integration

- Eigenständige Option: **LDAP / Microsoft AD Authentifizierung für AWX**
  (unabhängig von Infisical), via `PATCH /api/v2/settings/ldap/`
- Auswahl der AWX ↔ Infisical User-Integration:
  - `none` — getrennte User-Stores (nur der gemeinsame Admin ist abgeglichen)
  - `autoinvite` — AWX-User per API ins Infisical-Projekt einladen (nur Accounts;
    Passwörter werden nicht synchronisiert — Infisical nutzt SRP)
  - `idp` — beide nutzen ein gemeinsames LDAP/AD; AWX-LDAP wird konfiguriert,
    Infisical-LDAP wird versucht (best effort: Infisical-LDAP ist ein
    Enterprise-/lizenziertes Feature; bei Fehler wird Anleitung zur manuellen
    Einrichtung geloggt)
- LDAP/AD-Verbindungsdaten werden einmal erfasst und zwischen AWX und Infisical
  geteilt, wenn beide das Verzeichnis nutzen

#### 4.14 Antworten/Upgrade-Ergonomie

- Bei erneuten Läufen wird der Fragebogen automatisch erneut ausgeführt
  (vorherige Antworten als Defaults), wenn die Answers-Datei seit ihrer
  Erstellung hinzugekommene Optionen nicht enthält (z. B. ein neues Feature) —
  ohne `--reconfigure`

### 5. Kommandozeilenparameter

Unterstützte Parameter von bootstrap_awx.py:

- --home
  - Zweck: Setzt das Ansible Home-Verzeichnis
  - Default: /home/ansible

- --force-secrets
  - Zweck: Secrets neu erzeugen, auch wenn bereits vorhanden

- --force-pull
  - Zweck: Image-Vorbereitung erzwingen, auch wenn sie in einem früheren Lauf
    bereits erfolgt ist
  - Wirkung: lädt Basis-Images neu, **baut** die Custom-AWX-/Receptor-Images aus
    ihren Dockerfiles **neu**, **erzeugt die Container neu** (`up -d
    --force-recreate`), damit sie tatsächlich das frisch gebaute Image verwenden,
    und **seedet die installer-verwalteten Scaffold-Dateien neu** (`ansible.cfg`,
    `collections/requirements.yml`, `README` sowie die Bäume
    `playbooks`/`roles`/`inventories`) in das Projekt-Git-Repository, auch wenn
    es bereits befüllt ist (es wird nur das Delta committed/gepusht), und
    **erzwingt einen AWX-Project-Content-Sync** (plus eine Aktualisierung der
    NetBox-Inventory-Source), damit der reseedete Inhalt ausgecheckt wird statt
    der letzten von AWX synchronisierten Revision
  - Anwendung: wenn `Dockerfile.awx`/`Dockerfile.receptor` geändert wurde (z. B.
    um ein Tool zur Control Plane hinzuzufügen) oder installer-seitige Korrekturen
    an `ansible.cfg` / `collections/requirements.yml` das Projekt-Repository
    erreichen sollen, aus dem AWX synchronisiert. Ohne diese Option behält ein
    erneuter Lauf das bestehende Image, die Container und das bereits geseedete
    Repository — Änderungen scheinen dann „keine Wirkung" zu haben

- --fresh-reinstall
  - Zweck: Laufzeitdaten entfernen und Neuinstallation von Grund auf
  - Fragt nach Bestätigung, wenn nicht non-interactive

- --non-interactive
  - Zweck: Nicht-interaktiver Automationsmodus
  - Wichtig: Repository-Key-Bestätigung benötigt dann expliziten Override

- --reconfigure
  - Zweck: Interaktiven Fragebogen erneut ausführen, auch bei vorhandenen Antworten

- --assume-git-key-ready
  - Zweck: Im non-interactive Modus die interaktive Key-Bestätigung überspringen
  - Nur verwenden, wenn Deploy-Key-Zugriff bereits freigeschaltet ist

### 6. Konfigurationsparameter (interaktiver Fragebogen)

Nicht-geheime Parameter werden in .answers.json gespeichert, der Betriebszustand
in bootstrap_state.json.

Identität:

- fqdn
- admin_email

SSL/TLS:

- ssl_mode (none | provided | certbot_http | certbot_dns | acme_sh)
- ssl_cert_path (bei provided)
- ssl_key_path (bei provided)
- certbot_email
- certbot_dns_provider (a known provider name or `custom`)
- certbot_dns_plugin_source (custom provider: pip package or git URL)
- certbot_dns_plugin_name (custom provider: certbot authenticator name, e.g. `dns-foo`)
- acme_sh_basedir (bei acme_sh)

Authentifizierung (LDAP / Microsoft AD — optional, unabhängig von Infisical):

- ldap_enabled
- ldap_server_uri, ldap_start_tls
- ldap_bind_dn, ldap_bind_password (Secret, nicht in answers gespeichert)
- ldap_user_search_base, ldap_user_search_filter
- ldap_group_search_base (optional)
- ldap_email_attr, ldap_first_name_attr, ldap_last_name_attr

Datenbank:

- db_mode
- db_host
- db_port
- db_name
- db_user

AWX:

- awx_organization_name
- awx_admin_login
- awx_admin_name
- awx_admin_email
- awx_admin_password (Secret, nicht in answers gespeichert)
- awx_listen_port

Git:

- git_ssh_url
- git_branch
- Deploy-Key-Passphrase (optional): bei Neuerzeugung wird gefragt, ob der
  Schlüssel verschlüsselt werden soll; bei einem vorhandenen/übergebenen
  Schlüssel wird die Verschlüsselung erkannt und die Passphrase abgefragt. Wird
  als Secret gespeichert (nicht in answers), AWX als `ssh_key_unlock` übergeben
  und zum Entsperren des Schlüssels für die Git-Operationen des Installers genutzt

Image Tags:

- awx_image_tag
- redis_image_tag
- postgres_image_tag

Netzwerk:

- nginx_http_port
- nginx_https_port
- expose_postgres_port

Optionale Integration:

- netbox_url
- netbox_token (Secret, nicht in answers gespeichert)

Infisical (optionaler Secrets-Manager):

- infisical_enabled
- infisical_fqdn, infisical_image
- infisical_smtp_host, infisical_smtp_port, infisical_smtp_protocol (STARTTLS|SMTPS),
  infisical_smtp_user, infisical_smtp_password (Secret), infisical_smtp_from_address,
  infisical_smtp_from_name
- infisical_client_id (+ infisical_client_secret, Secret) — nur falls bereits eine
  Universal-Auth Machine Identity existiert; sonst wird beim Seeding eine erstellt
- infisical_project_name, infisical_env_slug
- infisical_user_sync (none | autoinvite | idp)
- infisical_import_enabled (+ infisical_import_sql_path, infisical_import_redis_path)
  — Import des PostgreSQL-/Redis-Dumps einer früheren Instanz; die alten
  `ENCRYPTION_KEY`/`AUTH_SECRET` werden als Secrets abgefragt und wiederverwendet,
  damit importierte Secrets entschlüsselbar bleiben

Secrets werden nicht in .answers.json abgelegt, sondern unter secrets/ (und im State).

### 7. Ausführungsphasen

Wesentliche Phasen in Reihenfolge:

- Parameter erfassen und speichern
- Preflight-Prüfungen
- Docker Installation
- Systemuser und Verzeichnisstruktur
- Secrets und Deploy-Key
- Dateigenerierung
- Optionale Repository-Befüllungsprüfung
- NGINX- und Firewall-Setup
- Certbot-Setup (falls gewählt)
- Image-Preparation
- Containerstart und Migrationen
- AWX API Bootstrap
- NetBox Dynamic Inventory Provisioning (falls konfiguriert)
- AWX LDAP/AD-Konfiguration (falls aktiviert)
- Infisical Deploy → DB-Provisioning → Zertifikat → vhost → compose up (falls aktiviert)
- Infisical Seeding (Admin/Org/Projekt), Secret-Migration und User-Integration
  (autoinvite / Infisical-LDAP) (falls aktiviert)
- Finaler NGINX Reload
- Smoke-Tests und Abschlussbericht

Hinweis: certbot/acme.sh stellen je FQDN ein Zertifikat aus; bei aktivem
Infisical wird für die Infisical-FQDN ein separates Zertifikat bezogen.

### 8. Generierte Dateien und Verzeichnisse

Typische Pfade unter dem Ansible Home:

- compose/awx/docker-compose.yml
- compose/awx/.env
- config/bootstrap_state.json
- config/awx_settings.py
- config/receptor.conf
- `nginx/<fqdn>.conf`
- secrets/.awx.env
- secrets/.db.env
- secrets/.api_token
- keys/deploy_key
- keys/deploy_key.pub
- logs/bootstrap.log
- playbooks, roles, inventories Scaffold
- collections/requirements.yml
- plugins/lookup/infisical.py (bei aktivem Infisical)
- inventories/dynamic/netbox.yml (aktiv) bzw. netbox.yml.disabled (Stub)

Bei aktivem Infisical:

- compose/infisical/docker-compose.yml
- compose/infisical/.env (Secret)
- nginx/<infisical_fqdn>.conf
- secrets/infisical/{encryption_key,auth_secret,db_password,admin_password,admin_token}

Weitere Secret-Dateien (Modus 600), je nach konfiguriertem Feature:

- secrets/netbox/token
- secrets/ldap/bind_password

Projektdateien:

- Dockerfile.awx
- Dockerfile.receptor

### 9. Typische Nutzung

Interaktive Einrichtung:

- sudo python3 bootstrap_awx.py --home /home/ansible --reconfigure

Kompletter Neuaufbau:

- sudo python3 bootstrap_awx.py --home /home/ansible --fresh-reinstall --reconfigure

Automationsmodus:

- sudo python3 bootstrap_awx.py --home /home/ansible --non-interactive --assume-git-key-ready

### 10. Betriebs-Hinweise

- Wenn Project-Sync auf pending hängen bleibt, controlplane Queue und Instance
  Group prüfen.
- Bei Git-Zugriffsfehlern Deploy-Key-Freigabe im Git-Provider prüfen.
- Für CI/non-interactive alle Pflichtwerte vorab konfigurieren und key-ready
  Override nur nach Freigabe nutzen.
- Die Job-Log-Zeile `[DEPRECATION WARNING]: ANSIBLE_COLLECTIONS_PATHS option ...
  use the singular form ANSIBLE_COLLECTIONS_PATH instead` ist harmlos und stammt
  **nicht** aus der `ansible.cfg` dieses Projekts (diese nutzt bereits den
  Singular-INI-Schlüssel `collections_path`). Der AWX-Controller selbst injiziert
  die veraltete Plural-Variable `ANSIBLE_COLLECTIONS_PATHS` in jede Job-Umgebung
  (siehe `build_env` in `awx/main/tasks/jobs.py`) und setzt aus
  Kompatibilitätsgründen bewusst sowohl die Plural- als auch die Singular-Form.
  Sie wird gesetzt, bevor das Execution Environment startet — kein EE-Image- oder
  Projekt-Config-Change entfernt sie; Deprecation-Warnungen bleiben absichtlich
  aktiv, damit echte Hinweise weiterhin sichtbar sind.

### 11. Sicherheits-Hinweise

- Keine Secrets aus Laufzeitverzeichnissen ins Versionsmanagement übernehmen.
- Private Schlüssel strikt per Dateirechten schützen.
- Pro Umgebung dedizierte Deploy-Keys verwenden.
- Privilegierte Container-Einstellungen in Security-Reviews kritisch bewerten.
- Infisical-/NetBox-/LDAP-Secrets liegen unter secrets/ (Modus 600) und werden
  bei aktivem Infisical zusätzlich ins Infisical-Projekt migriert. Das
  Infisical-Admin-Token (secrets/infisical/admin_token) ist ein
  Instance-Admin-Credential — entsprechend schützen.
- Der Infisical-Admin nutzt das AWX-Admin-Passwort; ein starkes Passwort wählen
  (muss auch die Infisical-Passwortrichtlinie erfüllen).
- LDAP-Bind-Passwort und NetBox-Token werden nicht in .answers.json abgelegt,
  sondern nur im State / in Secret-Dateien.
- Der Installer erstellt automatisch ein AWX-„Infisical"-Credential, das die
  Verbindung (URL/Token/Projekt/Env) injiziert und an das generierte Job Template
  hängt — Infisical-gestützte Secrets funktionieren damit sofort. Dasselbe
  Credential an weitere Job Templates hängen, die Infisical-Lookups benötigen;
  ohne dieses greift die awx_config-Rolle auf lokale Dateien zurück.
