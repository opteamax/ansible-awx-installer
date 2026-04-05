# AWX Bootstrap Project

English and German project documentation for the AWX bootstrap automation.

---

## English

### 1. Project Purpose

This project provides a production-oriented bootstrap script for deploying and operating an Ansible AWX stack on a Linux host.

Main goals:
- Automated installation and configuration of AWX with Docker Compose
- Idempotent reruns with state tracking
- Integrated NGINX reverse proxy and TLS support
- Automated AWX API bootstrap (organization, credentials, project, inventory, host, template)
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
- Adds ansible-runner and ansible-playbook path support
- Includes receptor binary in AWX image
- Applies AWX jobs.py patch to avoid problematic nested process isolation for project updates

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
- Supports known DNS providers for Certbot DNS plugins

#### 4.7 AWX API bootstrap
- Creates OAuth token
- Ensures organization
- Ensures machine and SCM credentials
- Ensures project, inventory, and host
- Manages job template creation when playbook is available

#### 4.8 Git project repository safety and onboarding
- Prints generated deploy public key for Git authorization
- Enforces key confirmation logic before repository validation/population
- Checks if target project repository is blank or incomplete
- Offers/executes scaffold population from local generated bootstrap content
- Does not clone seed content from the currently used AWX test/development repository

#### 4.9 Scheduler resilience fix
- Automatically ensures AWX controlplane queue exists
- Prevents project updates from getting stuck pending due to missing controlplane instance group

#### 4.10 Validation and reporting
- Performs smoke tests (container health, API ping/auth, NGINX, TLS expiry, PostgreSQL readiness, syntax check)
- Prints a final operations summary including deploy public key and key file locations


### 5. Command Line Parameters

bootstrap_awx.py supports:

- --home
  - Purpose: Set Ansible home directory
  - Default: /home/ansible

- --force-secrets
  - Purpose: Regenerate secrets even if present

- --force-pull
  - Purpose: Force image preparation/pull/build

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

The script collects and persists non-secret parameters (in .answers.json) and stores operational state in bootstrap_state.json.

Identity:
- fqdn
- admin_email

SSL/TLS:
- ssl_mode
- ssl_cert_path (provided mode)
- ssl_key_path (provided mode)
- certbot_email
- certbot_dns_provider
- certbot_dns_plugin_source

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
- Final NGINX reload
- Smoke tests and summary


### 8. Generated Files and Directories

Common generated locations under Ansible home:
- compose/awx/docker-compose.yml
- compose/awx/.env
- config/bootstrap_state.json
- config/awx_settings.py
- config/receptor.conf
- nginx/<fqdn>.conf
- secrets/.awx.env
- secrets/.db.env
- secrets/.api_token
- keys/deploy_key
- keys/deploy_key.pub
- logs/bootstrap.log
- playbooks, roles, inventories scaffold

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

- If project sync appears stuck pending, ensure controlplane queue and instance group exist.
- If Git access fails, verify deploy key authorization in the Git provider.
- For non-interactive CI usage, provide all required values in stored configuration and use key-ready override only after access is granted.


### 11. Security Notes

- Do not commit secrets from generated runtime directories.
- Keep private key files protected by file permissions.
- Use dedicated deploy keys per environment.
- Review and minimize privileged container settings in production security reviews.


---

## Deutsch

### 1. Projektziel

Dieses Projekt stellt ein produktionsorientiertes Bootstrap-Skript zur Verfügung, um einen Ansible AWX Stack auf einem Linux-Host automatisiert bereitzustellen und zu betreiben.

Hauptziele:
- Automatisierte Installation und Konfiguration von AWX per Docker Compose
- Idempotente Wiederholbarkeit mit Zustandsverwaltung
- Integrierter NGINX Reverse Proxy und TLS-Unterstützung
- Automatischer AWX API Bootstrap (Organisation, Credentials, Projekt, Inventory, Host, Template)
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
- Ergänzt ansible-runner und ansible-playbook im PATH
- Integriert receptor Binary ins AWX Image
- Patcht AWX jobs.py, um problematische verschachtelte Process-Isolation bei Project-Updates zu vermeiden

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
- Unterstützt bekannte DNS Provider für Certbot DNS Plugins

#### 4.7 AWX API Bootstrap
- Erstellt OAuth Token
- Stellt Organisation sicher
- Stellt Machine- und SCM-Credentials sicher
- Stellt Projekt, Inventory und Host sicher
- Erstellt Job Template, wenn das Playbook verfügbar ist

#### 4.8 Git Projekt-Repository Onboarding und Schutz
- Gibt den generierten Deploy Public Key aus
- Erzwingt Key-Bestätigungslogik vor Repository-Prüfung/Befüllung
- Prüft, ob Ziel-Repository leer oder unvollständig ist
- Bietet Befüllung aus lokal generiertem Bootstrap-Scaffold an bzw. führt sie aus
- Nutzt nicht das aktuell verwendete AWX Test-/Entwicklungs-Repository als Seed-Quelle

#### 4.9 Scheduler-Resilienzfix
- Stellt automatisch die AWX controlplane Queue sicher
- Verhindert hängende Project-Updates im pending Status bei fehlender controlplane Instance Group

#### 4.10 Validierung und Reporting
- Smoke-Tests (Container-Health, API Ping/Auth, NGINX, TLS-Laufzeit, PostgreSQL Readiness, Syntax-Check)
- Abschlussbericht inkl. Deploy Public Key und Dateipfaden


### 5. Kommandozeilenparameter

Unterstützte Parameter von bootstrap_awx.py:

- --home
  - Zweck: Setzt das Ansible Home-Verzeichnis
  - Default: /home/ansible

- --force-secrets
  - Zweck: Secrets neu erzeugen, auch wenn bereits vorhanden

- --force-pull
  - Zweck: Image-Preparation/Pull/Build erzwingen

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

Nicht-geheime Parameter werden in .answers.json gespeichert, der Betriebszustand in bootstrap_state.json.

Identität:
- fqdn
- admin_email

SSL/TLS:
- ssl_mode
- ssl_cert_path (bei provided)
- ssl_key_path (bei provided)
- certbot_email
- certbot_dns_provider
- certbot_dns_plugin_source

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
- Finaler NGINX Reload
- Smoke-Tests und Abschlussbericht


### 8. Generierte Dateien und Verzeichnisse

Typische Pfade unter dem Ansible Home:
- compose/awx/docker-compose.yml
- compose/awx/.env
- config/bootstrap_state.json
- config/awx_settings.py
- config/receptor.conf
- nginx/<fqdn>.conf
- secrets/.awx.env
- secrets/.db.env
- secrets/.api_token
- keys/deploy_key
- keys/deploy_key.pub
- logs/bootstrap.log
- playbooks, roles, inventories Scaffold

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

- Wenn Project-Sync auf pending hängen bleibt, controlplane Queue und Instance Group prüfen.
- Bei Git-Zugriffsfehlern Deploy-Key-Freigabe im Git-Provider prüfen.
- Für CI/non-interactive alle Pflichtwerte vorab konfigurieren und key-ready Override nur nach Freigabe nutzen.


### 11. Sicherheits-Hinweise

- Keine Secrets aus Laufzeitverzeichnissen ins Versionsmanagement übernehmen.
- Private Schlüssel strikt per Dateirechten schützen.
- Pro Umgebung dedizierte Deploy-Keys verwenden.
- Privilegierte Container-Einstellungen in Security-Reviews kritisch bewerten.
