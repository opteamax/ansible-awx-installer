#!/usr/bin/env python3
"""
bootstrap_awx.py – Production bootstrap for Ansible AWX platform.

Supports: RHEL 9, Debian 13, Ubuntu 22.04/24.04
Requires: Python 3.9+, run as root.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import getpass
import hashlib
import json
import logging
import os
import platform as _platform_mod
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "2.0.0"
DEFAULT_ANSIBLE_HOME = "/home/ansible"
AWX_FALLBACK_TAG = "23.9.0"
AWX_DEFAULT_PORT = 8052
REDIS_DEFAULT_TAG = "7-alpine"
POSTGRES_DEFAULT_TAG = "16"

KNOWN_DNS_PLUGIN_CREDENTIALS: Dict[str, Any] = {
    "cloudflare": {
        "package": "certbot-dns-cloudflare",
        "credentials_arg": "--dns-cloudflare-credentials",
        "fields": {"dns_cloudflare_api_token": "Cloudflare API Token"},
    },
    "route53": {
        "package": "certbot-dns-route53",
        "credentials_arg": None,
        "fields": {},
    },
    "digitalocean": {
        "package": "certbot-dns-digitalocean",
        "credentials_arg": "--dns-digitalocean-credentials",
        "fields": {"dns_digitalocean_token": "DigitalOcean API Token"},
    },
    "hetzner": {
        "package": "certbot-dns-hetzner",
        "credentials_arg": "--dns-hetzner-credentials",
        "fields": {"dns_hetzner_api_token": "Hetzner DNS API Token"},
    },
    "ovh": {
        "package": "certbot-dns-ovh",
        "credentials_arg": "--dns-ovh-credentials",
        "fields": {
            "dns_ovh_endpoint": "OVH endpoint (e.g. ovh-eu)",
            "dns_ovh_application_key": "Application key",
            "dns_ovh_application_secret": "Application secret",
            "dns_ovh_consumer_key": "Consumer key",
        },
    },
    "linode": {
        "package": "certbot-dns-linode",
        "credentials_arg": "--dns-linode-credentials",
        "fields": {"dns_linode_key": "Linode API key"},
    },
    "gandi": {
        "package": "certbot-dns-gandi",
        "credentials_arg": "--dns-gandi-credentials",
        "fields": {"dns_gandi_api_key": "Gandi API key"},
    },
}

REDACT_PATTERNS = re.compile(
    r"(password|secret|token|key|passwd|cred)", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

log: logging.Logger = logging.getLogger("bootstrap")


def setup_logging(log_file: Optional[str] = None) -> None:
    """Configure root logger with console + optional file handler."""
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    if log_file:
        try:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as exc:
            log.warning("Cannot open log file %s: %s", log_file, exc)


# ---------------------------------------------------------------------------
# Run utilities
# ---------------------------------------------------------------------------

def _redact_cmd(cmd: List[str]) -> List[str]:
    """Return a copy of cmd with sensitive argument values masked."""
    redacted: List[str] = []
    skip_next = False
    for i, part in enumerate(cmd):
        if skip_next:
            redacted.append("***REDACTED***")
            skip_next = False
            continue
        if REDACT_PATTERNS.search(part):
            if "=" in part:
                k, _ = part.split("=", 1)
                redacted.append(f"{k}=***REDACTED***")
            else:
                redacted.append(part)
                skip_next = True
        else:
            redacted.append(part)
    return redacted


def run(
    cmd: List[str],
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    input: Optional[str] = None,  # noqa: A002
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a subprocess command with logging."""
    display_cmd = _redact_cmd(cmd)
    log.debug("run: %s (cwd=%s)", " ".join(display_cmd), cwd)
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)
    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=merged_env,
        input=input,
        text=True,
        capture_output=capture,
        check=check,
    )
    return result


def run_ok(cmd: List[str]) -> bool:
    """Return True if command exits with code 0."""
    try:
        run(cmd, capture=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def run_capture(cmd: List[str]) -> str:
    """Run command and return stdout as stripped string."""
    result = run(cmd, capture=True, check=True)
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# State checkpoint
# ---------------------------------------------------------------------------

class State:
    """Atomic JSON state file for idempotent re-runs."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._data: Dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                log.warning("State file corrupt or unreadable, starting fresh.")
                self._data = {}
        else:
            self._data = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2))
        os.replace(tmp, self._path)

    def is_complete(self, phase: str) -> bool:
        return bool(self._data.get(f"phase_complete_{phase}"))

    def complete(self, phase: str) -> None:
        self._data[f"phase_complete_{phase}"] = True
        self._data[f"phase_ts_{phase}"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save()
        log.debug("Phase '%s' marked complete.", phase)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, val: Any) -> None:
        self._data[key] = val
        self._save()


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Config:
    fqdn: str = ""
    admin_email: str = ""
    ansible_home: str = DEFAULT_ANSIBLE_HOME
    platform: str = ""  # rhel9 | debian13 | ubuntu2204 | ubuntu2404
    fips_enabled: bool = False
    selinux_mode: str = "disabled"  # enforcing | permissive | disabled
    ssl_mode: str = "none"  # none | provided | certbot_http | certbot_dns
    ssl_cert_path: str = ""
    ssl_key_path: str = ""
    certbot_email: str = ""
    certbot_dns_provider: str = ""
    certbot_dns_plugin_source: str = ""  # pip or git URL
    db_mode: str = "container"  # container | external
    db_host: str = "postgres"
    db_port: int = 5432
    db_name: str = "awx"
    db_user: str = "awx"
    awx_organization_name: str = "Default"
    awx_admin_login: str = "admin"
    awx_admin_name: str = "Administrator"
    awx_admin_email: str = ""
    awx_admin_password: str = ""
    awx_listen_port: int = AWX_DEFAULT_PORT
    git_ssh_url: str = ""
    git_branch: str = "main"
    awx_image_tag: str = AWX_FALLBACK_TAG
    redis_image_tag: str = REDIS_DEFAULT_TAG
    postgres_image_tag: str = POSTGRES_DEFAULT_TAG
    nginx_http_port: int = 80
    nginx_https_port: int = 443
    expose_postgres_port: bool = False
    netbox_url: str = ""


# ---------------------------------------------------------------------------
# Platform adapters
# ---------------------------------------------------------------------------

class PlatformAdapter:
    """Base class for platform-specific operations."""

    name: str = ""

    def pkg_update(self) -> None:
        raise NotImplementedError

    def pkg_install(self, packages: List[str]) -> None:
        raise NotImplementedError

    def pkg_installed(self, package: str) -> bool:
        raise NotImplementedError

    def service_enable_now(self, name: str) -> None:
        raise NotImplementedError

    def service_reload(self, name: str) -> None:
        run(["systemctl", "reload", name])

    def service_is_active(self, name: str) -> bool:
        return run_ok(["systemctl", "is-active", "--quiet", name])

    def nginx_conf_dir(self) -> str:
        raise NotImplementedError

    def nginx_enable_site(self, canonical_conf_path: str) -> None:
        raise NotImplementedError

    def certbot_install(self) -> None:
        raise NotImplementedError

    def docker_repo_setup(self) -> None:
        raise NotImplementedError

    def firewall_open_port(self, port: int) -> None:
        raise NotImplementedError

    def firewall_is_active(self) -> bool:
        raise NotImplementedError


class RHEL9Adapter(PlatformAdapter):
    name = "rhel9"

    def pkg_update(self) -> None:
        run(["dnf", "makecache", "--refresh", "-q"])

    def pkg_install(self, packages: List[str]) -> None:
        run(["dnf", "install", "-y"] + packages)

    def pkg_installed(self, package: str) -> bool:
        return run_ok(["rpm", "-q", package])

    def service_enable_now(self, name: str) -> None:
        run(["systemctl", "enable", "--now", name])

    def service_reload(self, name: str) -> None:
        run(["systemctl", "reload", name])

    def nginx_conf_dir(self) -> str:
        return "/etc/nginx/conf.d"

    def nginx_enable_site(self, canonical_conf_path: str) -> None:
        # On RHEL, conf.d is auto-included; the conf file is already there
        pass

    def certbot_install(self) -> None:
        # Requires EPEL
        if not self.pkg_installed("epel-release"):
            self.pkg_install(["epel-release"])
        self.pkg_install(["certbot", "python3-certbot-nginx"])

    def docker_repo_setup(self) -> None:
        run(
            [
                "dnf",
                "config-manager",
                "--add-repo",
                "https://download.docker.com/linux/rhel/docker-ce.repo",
            ]
        )

    def firewall_open_port(self, port: int) -> None:
        if self.firewall_is_active():
            run(
                [
                    "firewall-cmd",
                    "--permanent",
                    f"--add-port={port}/tcp",
                ]
            )
            run(["firewall-cmd", "--reload"])

    def firewall_is_active(self) -> bool:
        return self.service_is_active("firewalld")


class DebianAdapter(PlatformAdapter):
    name = "debian13"

    def pkg_update(self) -> None:
        run(["apt-get", "update", "-qq"])

    def pkg_install(self, packages: List[str]) -> None:
        env = {"DEBIAN_FRONTEND": "noninteractive"}
        run(["apt-get", "install", "-y", "-qq"] + packages, env=env)

    def pkg_installed(self, package: str) -> bool:
        try:
            out = run_capture(["dpkg-query", "-W", "-f=${Status}", package])
            return "install ok installed" in out
        except subprocess.CalledProcessError:
            return False

    def service_enable_now(self, name: str) -> None:
        run(["systemctl", "enable", name])
        run(["systemctl", "start", name])

    def nginx_conf_dir(self) -> str:
        return "/etc/nginx/sites-available"

    def nginx_enable_site(self, canonical_conf_path: str) -> None:
        enabled_dir = Path("/etc/nginx/sites-enabled")
        enabled_dir.mkdir(parents=True, exist_ok=True)
        link = enabled_dir / Path(canonical_conf_path).name
        default_site = enabled_dir / "default"
        if default_site.exists() or default_site.is_symlink():
            default_site.unlink()
            log.info("Removed default NGINX site symlink.")
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(canonical_conf_path)
        log.info("Enabled NGINX site: %s → %s", link, canonical_conf_path)

    def certbot_install(self) -> None:
        self.pkg_install(["certbot", "python3-certbot-nginx"])

    def docker_repo_setup(self) -> None:
        self.pkg_install(
            ["ca-certificates", "curl", "gnupg", "lsb-release"]
        )
        keyring_dir = Path("/etc/apt/keyrings")
        keyring_dir.mkdir(parents=True, exist_ok=True)
        keyring = keyring_dir / "docker.gpg"
        if not keyring.exists():
            run(
                [
                    "bash",
                    "-c",
                    "curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
                ]
            )
        run(
            [
                "bash",
                "-c",
                (
                    'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] '
                    'https://download.docker.com/linux/debian $(lsb_release -cs) stable" '
                    "> /etc/apt/sources.list.d/docker.list"
                ),
            ]
        )

    def firewall_open_port(self, port: int) -> None:
        if self.firewall_is_active():
            run(["ufw", "allow", f"{port}/tcp"])

    def firewall_is_active(self) -> bool:
        try:
            out = run_capture(["ufw", "status"])
            return "active" in out.lower()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False


class UbuntuAdapter(DebianAdapter):
    """Ubuntu uses same base as Debian with different Docker repo URL."""

    name = "ubuntu"

    def docker_repo_setup(self) -> None:
        self.pkg_install(
            ["ca-certificates", "curl", "gnupg", "lsb-release"]
        )
        keyring_dir = Path("/etc/apt/keyrings")
        keyring_dir.mkdir(parents=True, exist_ok=True)
        keyring = keyring_dir / "docker.gpg"
        if not keyring.exists():
            run(
                [
                    "bash",
                    "-c",
                    "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg",
                ]
            )
        run(
            [
                "bash",
                "-c",
                (
                    'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] '
                    'https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" '
                    "> /etc/apt/sources.list.d/docker.list"
                ),
            ]
        )

    def certbot_install(self) -> None:
        # Use snap on Ubuntu if certbot not in apt
        try:
            run(["snap", "install", "--classic", "certbot"])
            snap_bin = Path("/snap/bin/certbot")
            usr_bin = Path("/usr/bin/certbot")
            if snap_bin.exists() and not usr_bin.exists():
                usr_bin.symlink_to(snap_bin)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.pkg_install(["certbot", "python3-certbot-nginx"])


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def detect_platform() -> Tuple[str, PlatformAdapter]:
    """Parse /etc/os-release and return (platform_id, adapter)."""
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        raise RuntimeError("/etc/os-release not found – unsupported OS.")

    info: Dict[str, str] = {}
    for line in os_release.read_text().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip('"')

    os_id = info.get("ID", "").lower()
    version_id = info.get("VERSION_ID", "")
    id_like = info.get("ID_LIKE", "").lower()

    log.debug("OS detection: ID=%s VERSION_ID=%s ID_LIKE=%s", os_id, version_id, id_like)

    if os_id in ("rhel", "centos", "rocky", "almalinux") or "rhel" in id_like:
        major = version_id.split(".")[0]
        if major != "9":
            log.warning("RHEL-like OS with version %s detected; script targets RHEL 9.", version_id)
        return "rhel9", RHEL9Adapter()

    if os_id == "debian":
        major = version_id.split(".")[0]
        if major != "13":
            log.warning("Debian %s detected; script targets Debian 13.", version_id)
        return "debian13", DebianAdapter()

    if os_id == "ubuntu":
        plat = f"ubuntu{version_id.replace('.', '')}"
        if version_id not in ("22.04", "24.04"):
            log.warning("Ubuntu %s detected; script targets 22.04/24.04.", version_id)
        return plat, UbuntuAdapter()

    raise RuntimeError(
        f"Unsupported OS: ID={os_id} VERSION_ID={version_id}. "
        "Supported: RHEL 9, Debian 13, Ubuntu 22.04/24.04."
    )


def detect_fips() -> bool:
    """Return True if FIPS mode is enabled."""
    fips_path = Path("/proc/sys/crypto/fips_enabled")
    if fips_path.exists():
        try:
            return fips_path.read_text().strip() == "1"
        except OSError:
            pass
    return False


def detect_selinux() -> str:
    """Return 'enforcing', 'permissive', or 'disabled'."""
    if not shutil.which("getenforce"):
        return "disabled"
    try:
        out = run_capture(["getenforce"])
        return out.lower()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "disabled"


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def prompt(
    label: str,
    default: str = "",
    required: bool = True,
    choices: Optional[List[str]] = None,
    validator: Optional[Any] = None,
) -> str:
    """Interactively prompt the user for a value."""
    # If a choices list is given and the default is not among them (e.g. an
    # old answers file predates a version that changed valid options), drop the
    # default rather than looping forever on an un-enterable value.
    if choices and default and default not in choices:
        log.debug(
            "Stored default '%s' is not in allowed choices %s – ignoring.",
            default, choices,
        )
        default = ""

    hint = ""
    if choices:
        hint = f" [{'/'.join(choices)}]"
        if default:
            hint += f" (default: {default})"
    elif default:
        hint = f" [{default}]"

    while True:
        try:
            val = input(f"{label}{hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(1)

        if not val:
            if default:
                val = default
            elif required:
                print("  This field is required.")
                continue
            else:
                return ""

        if choices and val not in choices:
            print(f"  Must be one of: {', '.join(choices)}")
            continue

        if validator:
            error = validator(val)
            if error:
                print(f"  {error}")
                continue

        return val


def prompt_password(label: str) -> str:
    """Prompt for a password (no echo)."""
    while True:
        try:
            pw = getpass.getpass(f"{label}: ")
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(1)
        if pw:
            return pw
        print("  Password cannot be empty.")


def prompt_confirm(label: str, default: bool = False) -> bool:
    """Yes/No confirmation prompt."""
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            val = input(f"{label} [{hint}]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(1)
        if not val:
            return default
        if val in ("y", "yes"):
            return True
        if val in ("n", "no"):
            return False
        print("  Enter y or n.")


# ---------------------------------------------------------------------------
# Answers file — persist and reload interactive questionnaire answers
# ---------------------------------------------------------------------------

# Config fields excluded from the answers file.
# Secrets are excluded because the answers file is a plain-text operator
# artefact (copyable, version-controllable).  Runtime-detected values are
# excluded because they are re-set on every run from the environment.
_ANSWERS_EXCLUDE: frozenset = frozenset({
    "awx_admin_password",   # secret — kept only in the encrypted state file
    "platform",             # auto-detected
    "fips_enabled",         # auto-detected
    "selinux_mode",         # auto-detected
    "ansible_home",         # supplied via CLI --home flag
})


def _answers_path() -> Path:
    """Return the path to the answers file next to this script."""
    return Path(__file__).parent / ".answers.json"


def _load_answers(path: Path) -> dict:
    """Load previous answers from JSON.  Returns {} on missing or corrupt file."""
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            return data
        log.warning("Answers file %s has unexpected format – ignoring.", path)
    except FileNotFoundError:
        pass  # first run, no file yet — normal
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not read answers file %s (%s) – starting fresh.", path, exc)
    return {}


def _save_answers(path: Path, config: Config) -> None:
    """Persist all non-secret config fields to the answers file atomically."""
    data = {
        k: v
        for k, v in dataclasses.asdict(config).items()
        if k not in _ANSWERS_EXCLUDE
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Parameter collection
# ---------------------------------------------------------------------------

def _validate_fqdn(val: str) -> Optional[str]:
    if not re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$",
        val,
    ):
        return "Must be a valid fully-qualified domain name (e.g. awx.example.com)"
    return None


def _validate_email(val: str) -> Optional[str]:
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", val):
        return "Must be a valid email address"
    return None


def _validate_port(val: str) -> Optional[str]:
    try:
        p = int(val)
        if 1 <= p <= 65535:
            return None
        return "Port must be between 1 and 65535"
    except ValueError:
        return "Must be a numeric port number"


def _validate_nonempty(val: str) -> Optional[str]:
    if not val.strip():
        return "Value cannot be empty"
    return None


def collect_params(
    platform: str,
    state: State,
    args: argparse.Namespace,
    answers: Optional[dict] = None,
    existing_password: str = "",
) -> Config:
    """Interactively collect all configuration parameters.

    ``answers`` is a dict of previously stored values (from the answers file
    merged with any config saved in state).  Each value is offered as the
    default for its prompt so the operator can press Enter to confirm it.

    ``existing_password`` carries the AWX admin password from state (if any).
    It is never stored in the answers file; on re-run the operator is offered
    the option to keep the existing password or set a new one.
    """
    if answers is None:
        answers = {}

    cfg = Config()
    cfg.platform = platform
    cfg.ansible_home = args.home

    print("\n" + "=" * 60)
    print("  Ansible AWX Bootstrap Configuration")
    print("=" * 60 + "\n")

    # ── Identity ────────────────────────────────────────────────
    print("── Identity ──────────────────────────────────────────────")
    cfg.fqdn = prompt(
        "Fully-qualified domain name for AWX",
        default=answers.get("fqdn", ""),
        validator=_validate_fqdn,
    )
    cfg.admin_email = prompt(
        "System administrator email",
        default=answers.get("admin_email", ""),
        validator=_validate_email,
    )

    # ── SSL / TLS ────────────────────────────────────────────────
    print("\n── SSL/TLS ───────────────────────────────────────────────")
    cfg.ssl_mode = prompt(
        "SSL mode",
        default=answers.get("ssl_mode", "none"),
        choices=["none", "provided", "certbot_http", "certbot_dns"],
    )

    if cfg.ssl_mode == "provided":
        cfg.ssl_cert_path = prompt(
            "Path to SSL certificate (fullchain.pem)",
            default=answers.get("ssl_cert_path", ""),
            validator=lambda v: None if Path(v).exists() else "File not found",
        )
        cfg.ssl_key_path = prompt(
            "Path to SSL private key",
            default=answers.get("ssl_key_path", ""),
            validator=lambda v: None if Path(v).exists() else "File not found",
        )

    if cfg.ssl_mode in ("certbot_http", "certbot_dns"):
        cfg.certbot_email = prompt(
            "Email for Let's Encrypt notifications",
            default=answers.get("certbot_email", "") or cfg.admin_email,
            validator=_validate_email,
        )

    if cfg.ssl_mode == "certbot_dns":
        known_providers = list(KNOWN_DNS_PLUGIN_CREDENTIALS.keys())
        print(f"  Known DNS providers: {', '.join(known_providers)}")
        cfg.certbot_dns_provider = prompt(
            "DNS provider name (or leave blank for custom)",
            default=answers.get("certbot_dns_provider", ""),
            required=False,
        )
        if cfg.certbot_dns_provider and cfg.certbot_dns_provider not in KNOWN_DNS_PLUGIN_CREDENTIALS:
            print(f"  Unknown provider '{cfg.certbot_dns_provider}' – you will supply a git/pip source.")
        if not cfg.certbot_dns_provider or cfg.certbot_dns_provider not in KNOWN_DNS_PLUGIN_CREDENTIALS:
            cfg.certbot_dns_plugin_source = prompt(
                "DNS plugin pip package or git URL",
                default=answers.get("certbot_dns_plugin_source", ""),
            )

    # ── Database ─────────────────────────────────────────────────
    print("\n── Database ──────────────────────────────────────────────")
    cfg.db_mode = prompt(
        "Database mode",
        default=answers.get("db_mode", "container"),
        choices=["container", "external"],
    )

    if cfg.db_mode == "external":
        cfg.db_host = prompt(
            "PostgreSQL host",
            default=str(answers.get("db_host", "localhost")),
        )
        cfg.db_port = int(
            prompt(
                "PostgreSQL port",
                default=str(answers.get("db_port", "5432")),
                validator=_validate_port,
            )
        )
        cfg.db_name = prompt(
            "PostgreSQL database name",
            default=str(answers.get("db_name", "awx")),
        )
        cfg.db_user = prompt(
            "PostgreSQL user",
            default=str(answers.get("db_user", "awx")),
        )

    # ── AWX organization ─────────────────────────────────────────
    print("\n── AWX Organization ──────────────────────────────────────")
    cfg.awx_organization_name = prompt(
        "Organization name",
        default=str(answers.get("awx_organization_name", "Default")),
        validator=lambda v: None if v.strip() else "Organization name cannot be empty",
    )

    # ── AWX admin ───────────────────────────────────────────────
    print("\n── AWX Admin Account ─────────────────────────────────────")
    cfg.awx_admin_login = prompt(
        "AWX admin username",
        default=str(answers.get("awx_admin_login", "admin")),
        validator=lambda v: (
            None if re.match(r"^[a-zA-Z][a-zA-Z0-9_-]{2,31}$", v)
            else "Must be 3-32 chars, letters/digits/- only"
        ),
    )
    cfg.awx_admin_name = prompt(
        "AWX admin display name",
        default=str(answers.get("awx_admin_name", "Administrator")),
    )
    cfg.awx_admin_email = prompt(
        "AWX admin email",
        default=str(answers.get("awx_admin_email", "") or cfg.admin_email),
        validator=_validate_email,
    )

    # Password is never stored in the answers file.
    # If a password already exists (from a previous run stored in state),
    # offer the operator a keep-or-replace choice; otherwise require entry.
    if existing_password:
        print("  AWX admin password: already configured.")
        print("  Press Enter to keep the existing password, or type a new one.")
        while True:
            try:
                pw1 = getpass.getpass("  New password (Enter = keep existing): ")
            except (EOFError, KeyboardInterrupt):
                print()
                raise SystemExit(1)
            if not pw1:
                cfg.awx_admin_password = existing_password
                break
            try:
                pw2 = getpass.getpass("  Confirm new password: ")
            except (EOFError, KeyboardInterrupt):
                print()
                raise SystemExit(1)
            if pw1 == pw2:
                cfg.awx_admin_password = pw1
                break
            print("  Passwords do not match, try again.")
    else:
        while True:
            pw1 = prompt_password("AWX admin password")
            pw2 = prompt_password("Confirm password")
            if pw1 == pw2:
                cfg.awx_admin_password = pw1
                break
            print("  Passwords do not match, try again.")

    # ── Git repository ───────────────────────────────────────────
    print("\n── Git Repository (optional) ─────────────────────────────")
    cfg.git_ssh_url = prompt(
        "Git SSH URL for Ansible repo (leave blank to skip)",
        default=answers.get("git_ssh_url", ""),
        required=False,
    )
    if cfg.git_ssh_url:
        cfg.git_branch = prompt(
            "Branch name",
            default=str(answers.get("git_branch", "main")),
        )
        print("  Repository completeness check is enabled.")
        print("  If repo is blank/incomplete, bootstrap will prompt to populate from local scaffold.")

    # ── Versions ─────────────────────────────────────────────────
    print("\n── Image Tags / Versions ─────────────────────────────────")
    detected_awx = fetch_latest_awx_tag()
    cfg.awx_image_tag = prompt(
        "AWX image tag",
        default=str(answers.get("awx_image_tag", "") or detected_awx),
    )
    cfg.redis_image_tag = prompt(
        "Redis image tag",
        default=str(answers.get("redis_image_tag", REDIS_DEFAULT_TAG)),
    )
    cfg.postgres_image_tag = prompt(
        "PostgreSQL image tag",
        default=str(answers.get("postgres_image_tag", POSTGRES_DEFAULT_TAG)),
    )

    # ── Network ──────────────────────────────────────────────────
    print("\n── Network ───────────────────────────────────────────────")
    cfg.awx_listen_port = int(
        prompt(
            "Internal AWX listen port",
            default=str(answers.get("awx_listen_port", AWX_DEFAULT_PORT)),
            validator=_validate_port,
        )
    )
    cfg.nginx_http_port = int(
        prompt(
            "NGINX HTTP port",
            default=str(answers.get("nginx_http_port", 80)),
            validator=_validate_port,
        )
    )
    if cfg.ssl_mode != "none":
        cfg.nginx_https_port = int(
            prompt(
                "NGINX HTTPS port",
                default=str(answers.get("nginx_https_port", 443)),
                validator=_validate_port,
            )
        )
    cfg.expose_postgres_port = prompt_confirm(
        "Expose PostgreSQL port on host?",
        default=bool(answers.get("expose_postgres_port", False)),
    )

    # ── Optional integrations ────────────────────────────────────
    print("\n── Optional Integrations ─────────────────────────────────")
    cfg.netbox_url = prompt(
        "NetBox URL for dynamic inventory (leave blank to skip)",
        default=answers.get("netbox_url", ""),
        required=False,
    )

    print()
    return cfg


# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

def check_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("ERROR: This script must be run as root.")


def check_python_version() -> None:
    if sys.version_info < (3, 9):
        raise SystemExit(
            f"ERROR: Python 3.9+ required, found {sys.version}"
        )


def check_port_free(port: int) -> bool:
    """Return True if the TCP port is not bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
            return False  # port is in use
        except (ConnectionRefusedError, OSError):
            return True


def check_ssl_pair(cert: str, key: str) -> None:
    """Verify cert and key files exist and are readable."""
    for path in (cert, key):
        if not Path(path).is_file():
            raise SystemExit(f"ERROR: SSL file not found: {path}")


def run_preflight(config: Config) -> None:
    """Run all preflight checks before making any changes."""
    log.info("Running preflight checks ...")
    check_root()
    check_python_version()

    if config.ssl_mode == "provided":
        check_ssl_pair(config.ssl_cert_path, config.ssl_key_path)

    ports_to_check = [config.nginx_http_port]
    if config.ssl_mode != "none":
        ports_to_check.append(config.nginx_https_port)

    for port in ports_to_check:
        if not check_port_free(port):
            log.warning("Port %d is already in use – NGINX may fail to bind.", port)

    if not shutil.which("ssh-keygen"):
        raise SystemExit("ERROR: ssh-keygen not found. Install OpenSSH.")

    log.info("Preflight checks passed.")


# ---------------------------------------------------------------------------
# System user / directory
# ---------------------------------------------------------------------------

def ensure_ansible_user(home: str) -> Tuple[int, int]:
    """Create 'ansible' Linux user if missing. Return (uid, gid)."""
    try:
        import pwd
        pw = pwd.getpwnam("ansible")
        log.info("User 'ansible' already exists (uid=%d).", pw.pw_uid)
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        pass

    log.info("Creating system user 'ansible' with home %s ...", home)
    run(
        [
            "useradd",
            "--system",
            "--shell", "/bin/bash",
            "--home-dir", home,
            "--create-home",
            "ansible",
        ]
    )

    _add_ansible_to_docker_group()

    import pwd
    pw = pwd.getpwnam("ansible")
    return pw.pw_uid, pw.pw_gid


def _add_ansible_to_docker_group() -> None:
    try:
        import grp
        grp.getgrnam("docker")
        run(["usermod", "-aG", "docker", "ansible"])
        log.info("Added 'ansible' to docker group.")
    except KeyError:
        log.debug("Docker group not yet created; will add later.")


def create_directory_structure(home: str, uid: int, gid: int) -> None:
    """Create the full directory tree under ~ansible/."""
    h = Path(home)
    dirs = [
        h / "compose" / "awx",
        h / "data" / "awx" / "projects",
        h / "data" / "awx" / "receptor",
        h / "data" / "postgres",
        h / "data" / "redis",
        h / "inventories" / "static" / "host_vars",
        h / "inventories" / "static" / "group_vars" / "all",
        h / "inventories" / "static" / "group_vars" / "awx_hosts",
        h / "inventories" / "dynamic",
        h / "playbooks",
        h / "roles" / "awx_config" / "defaults",
        h / "roles" / "awx_config" / "tasks",
        h / "roles" / "awx_config" / "handlers",
        h / "roles" / "awx_config" / "vars",
        h / "roles" / "awx_config" / "meta",
        h / "keys",
        h / "logs",
        h / "secrets" / "certbot",
        h / "nginx",
        h / "config",
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        os.chown(d, uid, gid)
        d.chmod(0o755)

    # Receptor sidecar may run with a UID different from the host ansible user.
    # Keep this runtime socket directory writable across images/user mappings.
    receptor_runtime = h / "data" / "awx" / "receptor"
    receptor_runtime.chmod(0o777)

    # secrets/ and secrets/certbot/ need 700
    for secret_dir in [h / "secrets", h / "secrets" / "certbot"]:
        secret_dir.chmod(0o700)
        os.chown(secret_dir, uid, gid)

    log.info("Directory structure created under %s", home)


def ensure_runtime_permissions(home: str, uid: int, gid: int) -> None:
    """Normalize runtime directory permissions required by containers."""
    receptor_runtime = Path(home) / "data" / "awx" / "receptor"
    receptor_runtime.mkdir(parents=True, exist_ok=True)
    os.chown(receptor_runtime, uid, gid)
    receptor_runtime.chmod(0o777)


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

import secrets as _secrets_mod


def generate_secret(n: int = 32) -> str:
    """Generate a standard base64-encoded secret of n random bytes."""
    return base64.b64encode(_secrets_mod.token_bytes(n)).decode()


def write_secret_file(path: Path, content: str, uid: int = 0, gid: int = 0) -> None:
    """Atomically write a secret file with mode 600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp_secret")
    tmp.write_text(content)
    tmp.chmod(0o600)
    os.chown(tmp, uid, gid)
    os.replace(tmp, path)
    log.debug("Wrote secret file: %s", path)


def read_secret_file(path: Path) -> str:
    """Read and return content of a secret file."""
    return path.read_text().strip()


def generate_and_write_secrets(
    config: Config,
    state: State,
    home: str,
    uid: int,
    gid: int,
    external_db_password: str = "",
    force: bool = False,
) -> Dict[str, str]:
    """Generate random secrets, write env files, return dict of values."""
    secrets_dir = Path(home) / "secrets"

    # db_password is never rotated (tied to postgres data dir)
    db_password = state.get("db_password") or generate_secret(32)
    # AWX secret key: 38 bytes → ~51 base64 chars (50+ required)
    secret_key = (None if force else state.get("secret_key")) or generate_secret(38)
    ws_secret = (None if force else state.get("ws_secret")) or generate_secret(32)

    state.set("db_password", db_password)
    state.set("secret_key", secret_key)
    state.set("ws_secret", ws_secret)

    # Determine actual DB password
    if config.db_mode == "external":
        actual_db_pass = external_db_password
    else:
        actual_db_pass = db_password

    # .db.env (chmod 600)
    db_env_content = (
        f"POSTGRES_USER={config.db_user}\n"
        f"POSTGRES_PASSWORD={actual_db_pass}\n"
        f"POSTGRES_DB={config.db_name}\n"
    )
    write_secret_file(secrets_dir / ".db.env", db_env_content, uid, gid)

    # .awx.env (chmod 600) – all AWX secrets
    awx_env = (
        f"SECRET_KEY={secret_key}\n"
        f"BROADCAST_WEBSOCKET_SECRET={ws_secret}\n"
        f"AWX_ADMIN_USER={config.awx_admin_login}\n"
        f"AWX_ADMIN_PASSWORD={config.awx_admin_password}\n"
        f"AWX_ADMIN_EMAIL={config.awx_admin_email}\n"
        f"DATABASE_PASSWORD={actual_db_pass}\n"
    )
    write_secret_file(secrets_dir / ".awx.env", awx_env, uid, gid)

    # .env (non-secret, mode 644) – compose variables
    env_content = (
        f"AWX_TAG={config.awx_image_tag}\n"
        f"AWX_PORT={config.awx_listen_port}\n"
        f"REDIS_TAG={config.redis_image_tag}\n"
        f"DB_HOST={config.db_host if config.db_mode == 'external' else 'postgres'}\n"
        f"DB_PORT={config.db_port}\n"
        f"DB_NAME={config.db_name}\n"
        f"DB_USER={config.db_user}\n"
        f"POSTGRES_TAG={config.postgres_image_tag}\n"
            f"RECEPTOR_TAG=receptor-podman:5.0.0\n"
        f"POSTGRES_USER={config.db_user}\n"
    )
    env_path = Path(home) / "compose" / "awx" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_env = env_path.with_suffix(".tmp_env")
    tmp_env.write_text(env_content)
    tmp_env.chmod(0o644)
    os.chown(tmp_env, uid, gid)
    os.replace(tmp_env, env_path)
    log.debug("Wrote .env file: %s", env_path)

    log.info("Secret files written to %s", secrets_dir)
    return {
        "db_password": actual_db_pass,
        "secret_key": secret_key,
        "ws_secret": ws_secret,
    }


# ---------------------------------------------------------------------------
# SSH deploy key
# ---------------------------------------------------------------------------

def _find_cwd_key_pair() -> Optional[Tuple[Path, Path]]:
    """Return (private, public) key paths from CWD/keys/ if a complete pair exists."""
    keys_dir = Path.cwd() / "keys"
    if not keys_dir.is_dir():
        return None
    for candidate in sorted(keys_dir.iterdir()):
        if candidate.suffix == ".pub" or not candidate.is_file():
            continue
        pub = candidate.with_suffix(".pub")
        if pub.exists():
            return candidate, pub
    return None


def generate_deploy_key(path: Path, comment: str, fips: bool) -> None:
    """Generate SSH deploy key. Uses RSA-4096 in FIPS mode, ed25519 otherwise.

    If CWD/keys/ contains a matching private+public key pair, those are copied
    instead of generating new ones.
    """
    if path.exists():
        log.info("Deploy key already exists at %s, skipping generation.", path)
        return

    pair = _find_cwd_key_pair()
    if pair is not None:
        src_priv, src_pub = pair
        log.info("Reusing existing key pair from %s.", src_priv.parent)
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_priv, path)
        path.chmod(0o600)
        pub_dst = path.with_suffix(".pub")
        shutil.copy2(src_pub, pub_dst)
        pub_dst.chmod(0o644)
        log.info("Key pair copied: %s", path)
        return

    if fips:
        key_type = ["-t", "rsa", "-b", "4096"]
        log.info("FIPS mode detected – generating RSA-4096 deploy key.")
    else:
        key_type = ["-t", "ed25519"]
        log.info("Generating ed25519 deploy key.")

    run(
        [
            "ssh-keygen",
            *key_type,
            "-C", comment,
            "-f", str(path),
            "-N", "",  # no passphrase
        ]
    )
    path.chmod(0o600)
    pub = path.with_suffix(".pub")
    if pub.exists():
        pub.chmod(0o644)
    log.info("Deploy key generated: %s", path)


# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

def install_docker(platform_adapter: PlatformAdapter, state: State) -> None:
    """Install Docker CE + compose plugin from official repos."""
    if state.is_complete("docker_install"):
        log.info("Docker already installed (state checkpoint). Skipping.")
        return

    log.info("Setting up Docker CE repository ...")
    platform_adapter.docker_repo_setup()
    platform_adapter.pkg_update()

    log.info("Installing Docker CE ...")
    platform_adapter.pkg_install(
        ["docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"]
    )

    platform_adapter.service_enable_now("docker")

    # Ensure ansible user is in docker group
    try:
        import grp, pwd
        grp.getgrnam("docker")
        pwd.getpwnam("ansible")
        run(["usermod", "-aG", "docker", "ansible"])
        log.info("ansible user added to docker group.")
    except KeyError:
        pass

    state.complete("docker_install")
    log.info("Docker CE installed and started.")


def detect_compose_command() -> List[str]:
    """Return the compose command as a list. Prefers `docker compose` plugin."""
    try:
        out = run_capture(["docker", "compose", "version"])
        if "compose" in out.lower():
            log.debug("Using 'docker compose' plugin.")
            return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Legacy fallback
    if shutil.which("docker-compose"):
        log.debug("Falling back to 'docker-compose' binary.")
        return ["docker-compose"]

    raise RuntimeError(
        "No docker compose command found. Install docker-compose-plugin."
    )


def fetch_latest_awx_tag() -> str:
    """Fetch latest AWX release tag from GitHub API."""
    url = "https://api.github.com/repos/ansible/awx/releases/latest"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bootstrap-awx/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            tag = data.get("tag_name", AWX_FALLBACK_TAG)
            log.debug("Latest AWX tag: %s", tag)
            return tag
    except Exception as exc:
        log.warning("Could not fetch AWX tag from GitHub: %s. Using %s.", exc, AWX_FALLBACK_TAG)
        return AWX_FALLBACK_TAG


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

def configure_firewall(platform_adapter: PlatformAdapter, config: Config) -> None:
    """Open HTTP and HTTPS ports in firewall."""
    if not platform_adapter.firewall_is_active():
        log.info("Firewall not active – skipping port configuration.")
        return

    log.info("Opening firewall ports ...")
    platform_adapter.firewall_open_port(config.nginx_http_port)
    if config.ssl_mode != "none":
        platform_adapter.firewall_open_port(config.nginx_https_port)


# ---------------------------------------------------------------------------
# File generators
# ---------------------------------------------------------------------------

def gen_compose_file(
        config: Config,
        uid: int,
        gid: int,
        selinux_enforcing: bool,
) -> str:
        """Generate docker-compose.yml for AWX + Redis + PostgreSQL. NO build section.

        AWX requires two containers from the same image:
            awx_web  – Django/nginx web process; runs DB migrations on first boot
            awx_task – Celery task worker; skips migrations (AWX_SKIP_MIGRATIONS=1)
        Both must receive an explicit command or dumb-init (the image entrypoint)
        will abort with a usage error.
        """
        home = config.ansible_home
        secrets_dir = f"{home}/secrets"

        vol_z = ":z" if selinux_enforcing else ""
        vol_Z = ":Z" if selinux_enforcing else ""
        db_host = config.db_host if config.db_mode == "external" else "postgres"

        postgres_port_mapping = ""
        if config.expose_postgres_port and config.db_mode == "container":
                postgres_port_mapping = f"\n    ports:\n      - \"127.0.0.1:5432:5432\""

        postgres_service = ""
        if config.db_mode == "container":
                postgres_service = f"""
    postgres:
        image: postgres:${{POSTGRES_TAG}}
        container_name: awx_postgres
        restart: unless-stopped
        env_file:
            - {secrets_dir}/.db.env
        volumes:
            - {home}/data/postgres:/var/lib/postgresql/data{vol_Z}{postgres_port_mapping}
        networks:
            - awx_net
        healthcheck:
            test: ["CMD-SHELL", "pg_isready -U ${{POSTGRES_USER:-awx}}"]
            interval: 10s
            timeout: 5s
            retries: 5
"""

        if config.db_mode == "container":
                awx_depends = """\
        depends_on:
            postgres:
                condition: service_healthy
            receptor:
                condition: service_started
            redis:
                condition: service_started
"""
        else:
                awx_depends = """\
        depends_on:
            receptor:
                condition: service_started
            redis:
                condition: service_started
"""

        awx_env = f"""\
        env_file:
            - {secrets_dir}/.awx.env
        environment:
            - PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
            - DATABASE_HOST={db_host}
            - DATABASE_NAME=${{DB_NAME}}
            - DATABASE_USER=${{DB_USER}}
            - DATABASE_PORT=${{DB_PORT}}
            - REDIS_HOST=redis
            - REDIS_PORT=6379"""

        awx_volumes = f"""\
        volumes:
            - {home}/data/awx/projects:/var/lib/awx/projects{vol_z}
            - {home}/data/awx/receptor:/var/run/receptor{vol_z}
            - {home}/config/receptor.conf:/etc/receptor/receptor.conf:ro{vol_z}
            - {home}/config/awx_settings.py:/etc/tower/settings.py:ro{vol_z}
            - {home}/config/awx_nginx.conf:/etc/nginx/conf.d/awx.conf:ro{vol_z}
            - awx_private:/awxdata"""

        return f"""\
---
# Generated by bootstrap_awx.py – DO NOT edit manually.
# Secrets are loaded via env_file from {secrets_dir}/
# AWX runs as two services (web + task) from the same official image.
# Each must pass an explicit command; without one dumb-init exits immediately.

services:
    awx_web:
        image: awx-podman:{config.awx_image_tag}
        container_name: awx_web
        restart: unless-stopped
        user: "0"
        command: /usr/bin/launch_awx_web.sh
{awx_depends}        ports:
            - "127.0.0.1:${{AWX_PORT}}:80"
{awx_env}
{awx_volumes}
        networks:
            - awx_net
        healthcheck:
            test: ["CMD", "curl", "-sf", "http://localhost/api/v2/ping/"]
            interval: 30s
            timeout: 10s
            retries: 20
            start_period: 300s

    awx_task:
        image: awx-podman:{config.awx_image_tag}
        container_name: awx_task
        hostname: awx_task
        restart: unless-stopped
        user: "0"
        privileged: true
        cap_add:
            - CAP_SYS_ADMIN
            - CAP_SYS_PTRACE
            - CAP_NET_ADMIN
            - CAP_SYS_RESOURCE
        # launch_awx_task.sh calls `awx-manage provision_instance` without --hostname,
        # which fails on recent AWX with a K8s-only registration CommandError.
        command: /bin/bash -c "set -e; wait-for-migrations; awx-manage provision_instance --hostname=$${{HOSTNAME}} --node_type=hybrid; exec supervisord -c /etc/supervisord_task.conf"
{awx_depends}        environment:
            - AWX_SKIP_MIGRATIONS=1
            - DATABASE_HOST={db_host}
            - DATABASE_NAME=${{DB_NAME}}
            - DATABASE_USER=${{DB_USER}}
            - DATABASE_PORT=${{DB_PORT}}
            - REDIS_HOST=redis
            - REDIS_PORT=6379
        env_file:
            - {secrets_dir}/.awx.env
{awx_volumes}
        networks:
            - awx_net

    receptor:
        image: awx-podman:{config.awx_image_tag}
        container_name: awx_receptor
        restart: unless-stopped
        privileged: true
        cap_add:
            - CAP_SYS_ADMIN
            - CAP_SYS_PTRACE
            - CAP_NET_ADMIN
            - CAP_SYS_RESOURCE
        command: receptor --config /etc/receptor/receptor.conf
        volumes:
            - {home}/data/awx/projects:/var/lib/awx/projects{vol_z}
            - {home}/data/awx/receptor:/var/run/receptor{vol_z}
            - {home}/config/receptor.conf:/etc/receptor/receptor.conf:ro{vol_z}
            - awx_private:/awxdata
        networks:
            - awx_net

    redis:
        image: redis:${{REDIS_TAG}}
        container_name: awx_redis
        restart: unless-stopped
        networks:
            - awx_net
{postgres_service}
networks:
    awx_net:
        driver: bridge

volumes:
    awx_private:
"""


def gen_compose_env(config: Config) -> str:
    """Generate .env file with non-secret compose variables only."""
    return (
        f"# Non-secret compose variables – generated by bootstrap_awx.py\n"
        f"# Secrets are in secrets/.awx.env and secrets/.db.env\n"
        f"AWX_TAG={config.awx_image_tag}\n"
        f"AWX_PORT={config.awx_listen_port}\n"
        f"REDIS_TAG={config.redis_image_tag}\n"
        f"DB_HOST={config.db_host if config.db_mode == 'external' else 'postgres'}\n"
        f"DB_PORT={config.db_port}\n"
        f"DB_NAME={config.db_name}\n"
        f"DB_USER={config.db_user}\n"
        f"POSTGRES_TAG={config.postgres_image_tag}\n"
        f"POSTGRES_USER={config.db_user}\n"
    )
def gen_nginx_config(config: Config) -> str:
    """Generate NGINX virtual host config for AWX."""
    upstream_port = config.awx_listen_port
    fqdn = config.fqdn

    websocket_headers = """\
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";"""

    proxy_block = f"""\
        proxy_pass http://127.0.0.1:{upstream_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
{websocket_headers}"""

    if config.ssl_mode == "none":
        return f"""\
# NGINX config for AWX (HTTP only) – generated by bootstrap_awx.py
server {{
    listen {config.nginx_http_port};
    server_name {fqdn};

    access_log /var/log/nginx/{fqdn}_access.log;
    error_log  /var/log/nginx/{fqdn}_error.log;

    location / {{
{proxy_block}
    }}
}}
"""

    # HTTPS with redirect
    if config.ssl_mode == "provided":
        cert_path = config.ssl_cert_path
        key_path = config.ssl_key_path
    else:
        # certbot-managed paths
        le_dir = f"/etc/letsencrypt/live/{fqdn}"
        cert_path = f"{le_dir}/fullchain.pem"
        key_path = f"{le_dir}/privkey.pem"

    return f"""\
# NGINX config for AWX (HTTPS) – generated by bootstrap_awx.py
server {{
    listen {config.nginx_http_port};
    server_name {fqdn};
    return 301 https://$host$request_uri;
}}

server {{
    listen {config.nginx_https_port} ssl;
    http2 on;
    server_name {fqdn};

    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS (6 months)
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains" always;

    access_log /var/log/nginx/{fqdn}_access.log;
    error_log  /var/log/nginx/{fqdn}_error.log;

    location / {{
{proxy_block}
    }}
}}
"""


def gen_awx_settings_py() -> str:
    """Generate /etc/tower/settings.py for AWX containers.

    AWX's production.py unconditionally includes this file at startup.
    We keep it minimal: actual DB/Redis/secret credentials arrive as
    environment variables injected by docker-compose.
    """
    return """\
# AWX settings override – generated by bootstrap_awx.py
# DB, Redis, and secret credentials arrive via docker-compose environment variables.
import os

ALLOWED_HOSTS = ['*']

SECRET_KEY = os.environ.get('SECRET_KEY', '')

DATABASES = {
    'default': {
        'ATOMIC_REQUESTS': True,
        'ENGINE': 'awx.main.db.profiled_pg',
        'NAME': os.environ.get('DATABASE_NAME', 'awx'),
        'USER': os.environ.get('DATABASE_USER', 'awx'),
        'PASSWORD': os.environ.get('DATABASE_PASSWORD', ''),
        'HOST': os.environ.get('DATABASE_HOST', 'localhost'),
        'PORT': int(os.environ.get('DATABASE_PORT', '5432')),
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [(
                os.environ.get('REDIS_HOST', 'localhost'),
                int(os.environ.get('REDIS_PORT', '6379')),
            )],
        },
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

BROKER_URL = "redis://{}:{}/0".format(
    os.environ.get('REDIS_HOST', 'localhost'),
    os.environ.get('REDIS_PORT', '6379'),
)

AWX_ISOLATION_SHOW_PATHS = []

AWX_ISOLATION_BASE_PATH = '/awxdata'
"""


def gen_awx_container_nginx_config() -> str:
    """Generate the nginx config to be bind-mounted into the AWX container.

    The official AWX image ships only the default RHEL nginx.conf (port 80,
    static files).  The AWX-specific reverse-proxy rules that forward requests
    to uWSGI (port 8050) and daphne/WebSocket (port 8051) must be provided by
    the deployment tooling via /etc/nginx/conf.d/.
    """
    return """\
# AWX container nginx config – generated by bootstrap_awx.py
# Loaded by the default /etc/nginx/nginx.conf via include conf.d/*.conf

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # AWX static assets
    location /static/ {
        alias /var/lib/awx/public/static/;
    }

    location /favicon.ico {
        alias /var/lib/awx/public/static/favicon.ico;
        access_log off;
    }

    # WebSocket connections go to daphne (ASGI)
    location ~ /websocket {
        proxy_pass http://127.0.0.1:8051;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 75s;
        proxy_read_timeout 120s;
    }

    # Everything else goes to uWSGI (Django)
    location / {
        uwsgi_pass 127.0.0.1:8050;
        include uwsgi_params;
        uwsgi_read_timeout 120s;
    }
}
"""


def gen_receptor_config() -> str:
    """Generate receptor config consumed by sidecar and awx_task receptorctl."""
    return """\
---
- local-only: null

- log-level: info

- node:
    id: awx_task
    firewallrules:
      - action: reject
        tonode: awx_task
        toservice: control

- control-service:
    service: control
    filename: /var/run/receptor/receptor.sock
    permissions: '0660'

- work-command:
    worktype: local
    command: ansible-runner
    params: worker
    allowruntimeparams: true
"""


def gen_ansible_cfg(config: Config) -> str:
    """Generate ansible.cfg."""
    home = config.ansible_home
    return f"""\
# ansible.cfg – generated by bootstrap_awx.py
[defaults]
inventory          = {home}/inventories/static/hosts.yml
roles_path         = {home}/roles
collections_paths  = {home}/ansible/collections:/usr/share/ansible/collections
log_path           = {home}/logs/ansible.log
host_key_checking  = False
retry_files_enabled = False
forks              = 10
stdout_callback    = yaml

[ssh_connection]
pipelining         = True
ssh_args           = -C -o ControlMaster=auto -o ControlPersist=300s
"""


def _git_ssh_hostname(url: str) -> str:
    """Extract the hostname from a git SSH URL (scp-style or ssh://)."""
    if url.startswith("ssh://"):
        # ssh://[user@]host[:port]/path
        rest = url[6:]  # strip "ssh://"
        if "@" in rest:
            rest = rest.split("@", 1)[1]
        return rest.split("/")[0].split(":")[0]
    # SCP-style: [user@]host:path
    if "@" in url:
        url = url.split("@", 1)[1]
    return url.split(":")[0]


def gen_ansible_ssh_config(config: Config) -> str:
    """Generate ~/.ssh/config for the ansible user.

    Configures the git server host to authenticate with the deploy key so that
    git+ssh operations (both local and driven by AWX) use the correct identity.
    """
    lines = ["# SSH client config – generated by bootstrap_awx.py"]
    if config.git_ssh_url:
        hostname = _git_ssh_hostname(config.git_ssh_url)
        if hostname:
            lines += [
                "",
                f"Host {hostname}",
                f"    IdentityFile {config.ansible_home}/keys/deploy_key",
                "    StrictHostKeyChecking accept-new",
                "    BatchMode yes",
            ]
    return "\n".join(lines) + "\n"


def gen_inventory_hosts(config: Config) -> str:
    """Generate static inventory hosts.yml with awx_hosts group."""
    hostname = config.fqdn.split(".")[0]
    return f"""\
---
# Static inventory – generated by bootstrap_awx.py
all:
  children:
    awx_hosts:
      hosts:
        {hostname}:
          ansible_host: {config.fqdn}
          ansible_user: ansible
          ansible_ssh_private_key_file: {config.ansible_home}/keys/deploy_key
"""


def gen_host_vars(config: Config) -> str:
    """Generate host_vars main.yml."""
    hostname = config.fqdn.split(".")[0]
    return f"""\
---
# Host variables for {hostname} – generated by bootstrap_awx.py
awx_fqdn: "{config.fqdn}"
awx_port: {config.awx_listen_port}
awx_ssl_mode: "{config.ssl_mode}"
"""


def gen_group_vars_all(config: Config) -> str:
    """Generate group_vars/all/main.yml."""
    return f"""\
---
# Global group variables – generated by bootstrap_awx.py
ansible_home: "{config.ansible_home}"
admin_email: "{config.admin_email}"
git_branch: "{config.git_branch}"
"""


def gen_group_vars_awx(config: Config) -> str:
    """Generate group_vars/awx_hosts/main.yml."""
    return f"""\
---
# AWX host group variables – generated by bootstrap_awx.py
awx_image_tag: "{config.awx_image_tag}"
redis_image_tag: "{config.redis_image_tag}"
postgres_image_tag: "{config.postgres_image_tag}"
awx_admin_login: "{config.awx_admin_login}"
awx_admin_email: "{config.awx_admin_email}"
awx_db_name: "{config.db_name}"
awx_db_user: "{config.db_user}"
awx_db_host: "{config.db_host if config.db_mode == 'external' else 'postgres'}"
"""


def gen_netbox_stub(config: Config) -> str:
    """Generate disabled NetBox dynamic inventory stub."""
    nb_url = config.netbox_url or "https://netbox.example.com"
    return f"""\
---
# NetBox dynamic inventory – disabled by default.
# Rename to netbox.yml and set NETBOX_TOKEN env var to enable.
plugin: netbox.netbox.nb_inventory
api_endpoint: {nb_url}
token: "{{{{ lookup('env', 'NETBOX_TOKEN') }}}}"
validate_certs: true
config_context: true
group_by:
  - device_roles
  - platforms
  - sites
"""


def gen_playbook_site(config: Config) -> str:
    """Generate site.yml playbook targeting awx_hosts group."""
    return """\
---
# site.yml – Top-level playbook
# Generated by bootstrap_awx.py
- name: Apply awx_config role to all AWX hosts
  hosts: awx_hosts
  become: true
  gather_facts: true
  roles:
    - role: awx_config
      tags: [awx]
"""


def gen_playbook_awx_bootstrap(config: Config) -> str:
    """Generate awx_bootstrap.yml playbook."""
    return f"""\
---
# awx_bootstrap.yml – Bootstrap AWX API objects via awx.awx collection
# Generated by bootstrap_awx.py
- name: Bootstrap AWX via REST API
  hosts: awx_hosts
  gather_facts: false
  vars:
    awx_api_url: "http://{{{{ ansible_host }}}}:{config.awx_listen_port}"
    awx_token_file: "{config.ansible_home}/secrets/.api_token"
  roles:
    - role: awx_config
      tags: [api_bootstrap]
"""


def gen_role_defaults(config: Config) -> str:
    """Generate role defaults/main.yml with all awx_* variables documented."""
    return f"""\
---
# defaults/main.yml for awx_config role
# Generated by bootstrap_awx.py – override in host_vars or group_vars

# === AWX connection ===
awx_api_url: "http://127.0.0.1:{config.awx_listen_port}"
awx_token_file: "{config.ansible_home}/secrets/.api_token"

# === Organization ===
awx_organization_name: "{config.awx_organization_name}"

# === Project configuration ===
awx_project_name: "Ansible Repo"
awx_scm_credential_name: "scm_deploy_key"

# === Machine credential ===
awx_machine_credential_name: "deploy_key"

# === Inventory ===
awx_inventory_name: "Static Inventory"

# === Job Template ===
awx_job_template_name: "Deploy Site"
awx_job_template_playbook: "playbooks/site.yml"

# === Git repository ===
awx_git_url: "{config.git_ssh_url}"
awx_git_branch: "{config.git_branch}"

# === Admin ===
awx_admin_login: "{config.awx_admin_login}"
awx_admin_email: "{config.awx_admin_email}"

# === NetBox integration ===
awx_netbox_url: "{config.netbox_url}"
awx_netbox_token: ""
"""


def gen_role_vars(config: Config) -> str:
    """Generate role vars/main.yml."""
    return """\
---
# vars/main.yml for awx_config role
# These override defaults and group_vars but NOT extra_vars.
# Keep sensitive values out of here – use secrets/ files.
_awx_api_headers:
  Content-Type: "application/json"
  Accept: "application/json"
"""


def gen_role_meta(config: Config) -> str:
    """Generate role meta/main.yml."""
    return """\
---
galaxy_info:
  role_name: awx_config
  author: bootstrap_awx
  description: "Configure AWX via awx.awx collection"
  license: MIT
  min_ansible_version: "2.14"
  platforms:
    - name: EL
      versions: ["9"]
    - name: Debian
      versions: ["13"]
    - name: Ubuntu
      versions: ["22.04", "24.04"]
  galaxy_tags:
    - awx
    - ansible
    - automation

dependencies:
  - name: awx.awx
    source: galaxy
"""


def gen_role_handlers(config: Config) -> str:
    """Generate role handlers/main.yml."""
    home = config.ansible_home
    return f"""\
---
# handlers/main.yml for awx_config role
- name: reload nginx
  become: true
  ansible.builtin.service:
    name: nginx
    state: reloaded

- name: restart awx
  community.docker.docker_compose_v2:
    project_src: "{home}/compose/awx"
    state: present
    recreate: always
  listen: restart_awx
"""


def gen_role_tasks_main(config: Config) -> str:
    """Generate role tasks/main.yml importing all task files."""
    return """\
---
# tasks/main.yml for awx_config role
- name: Preflight checks
  ansible.builtin.import_tasks: preflight.yml
  tags: [always, preflight]

- name: Load API authentication
  ansible.builtin.import_tasks: auth.yml
  tags: [always, auth]

- name: Manage organizations
  ansible.builtin.import_tasks: organizations.yml
  tags: [organizations]

- name: Manage credentials
  ansible.builtin.import_tasks: credentials.yml
  tags: [credentials]

- name: Manage projects
  ansible.builtin.import_tasks: projects.yml
  tags: [projects]
  when: awx_git_url | length > 0

- name: Manage inventories
  ansible.builtin.import_tasks: inventories.yml
  tags: [inventories]

- name: Manage job templates
  ansible.builtin.import_tasks: job_templates.yml
  tags: [job_templates]
  when: awx_git_url | length > 0

- name: Manage users
  ansible.builtin.import_tasks: users.yml
  tags: [users]

- name: NetBox integration
  ansible.builtin.import_tasks: netbox.yml
  tags: [netbox]
  when: awx_netbox_url | length > 0
"""


def gen_role_tasks_preflight(config: Config) -> str:
    """Generate role tasks/preflight.yml – verify AWX API /api/v2/ping/ reachable."""
    return """\
---
# tasks/preflight.yml – verify AWX API is reachable
- name: Verify AWX API is reachable via /api/v2/ping/
  ansible.builtin.uri:
    url: "{{ awx_api_url }}/api/v2/ping/"
    method: GET
    status_code: 200
    timeout: 15
  register: _awx_ping
  retries: 20
  delay: 15
  until: _awx_ping.status == 200
  failed_when: _awx_ping.status != 200

- name: Display AWX ping response
  ansible.builtin.debug:
    msg: "AWX API reachable – ping response: {{ _awx_ping.json | default('unknown') }}"
"""


def gen_role_tasks_auth(config: Config) -> str:
    """Generate role tasks/auth.yml – read .api_token file and set awx_api_token fact."""
    return """\
---
# tasks/auth.yml – read API token and set bearer fact
- name: Read AWX API token from file
  ansible.builtin.slurp:
    src: "{{ awx_token_file }}"
  register: _token_raw
  no_log: true

- name: Set awx_api_token fact
  ansible.builtin.set_fact:
    awx_api_token: "{{ _token_raw.content | b64decode | trim }}"
  no_log: true

- name: Verify token is valid via /api/v2/me/
  ansible.builtin.uri:
    url: "{{ awx_api_url }}/api/v2/me/"
    method: GET
    headers:
      Authorization: "Bearer {{ awx_api_token }}"
      Accept: "application/json"
    status_code: 200
  register: _token_check
  no_log: true
  failed_when: _token_check.status != 200
"""


def gen_role_tasks_organizations(config: Config) -> str:
    """Generate role tasks/organizations.yml – manage orgs via awx.awx.organization."""
    return """\
---
# tasks/organizations.yml – manage AWX organizations
- name: Ensure Default organization exists
  awx.awx.organization:
    name: "{{ awx_organization_name }}"
    state: present
    controller_host: "{{ awx_api_url }}"
    controller_oauthtoken: "{{ awx_api_token }}"
  register: _awx_org

- name: Display organization result
  ansible.builtin.debug:
    msg: "Organization '{{ awx_organization_name }}' id={{ _awx_org.id | default('N/A') }}"
"""


def gen_role_tasks_credentials(config: Config) -> str:
    """Generate role tasks/credentials.yml – manage Machine + SCM creds via awx.awx.credential."""
    return """\
---
# tasks/credentials.yml – manage AWX credentials
- name: Read deploy private key
  ansible.builtin.slurp:
    src: "{{ ansible_home }}/keys/deploy_key"
  register: _deploy_key_raw
  no_log: true

- name: Ensure machine credential 'deploy_key' exists
  awx.awx.credential:
    name: "{{ awx_machine_credential_name }}"
    organization: "{{ awx_organization_name }}"
    credential_type: "Machine"
    state: present
    inputs:
      ssh_key_data: "{{ _deploy_key_raw.content | b64decode }}"
    controller_host: "{{ awx_api_url }}"
    controller_oauthtoken: "{{ awx_api_token }}"
  no_log: true
  register: _machine_cred

- name: Ensure SCM credential 'scm_deploy_key' exists (when git URL configured)
  when: awx_git_url | length > 0
  awx.awx.credential:
    name: "{{ awx_scm_credential_name }}"
    organization: "{{ awx_organization_name }}"
    credential_type: "Source Control"
    state: present
    inputs:
      ssh_key_data: "{{ _deploy_key_raw.content | b64decode }}"
    controller_host: "{{ awx_api_url }}"
    controller_oauthtoken: "{{ awx_api_token }}"
  no_log: true
  register: _scm_cred

- name: Display credential results
  ansible.builtin.debug:
    msg:
      - "Machine credential '{{ awx_machine_credential_name }}' id={{ _machine_cred.id | default('N/A') }}"
      - "SCM credential configured: {{ awx_git_url | length > 0 }}"
"""


def gen_role_tasks_projects(config: Config) -> str:
    """Generate role tasks/projects.yml – manage projects via awx.awx.project."""
    return """\
---
# tasks/projects.yml – manage AWX projects (only when git URL configured)
- name: Ensure project exists
  awx.awx.project:
    name: "{{ awx_project_name }}"
    organization: "{{ awx_organization_name }}"
    scm_type: git
    scm_url: "{{ awx_git_url }}"
    scm_branch: "{{ awx_git_branch }}"
    credential: "{{ awx_scm_credential_name }}"
    state: present
    wait: true
    controller_host: "{{ awx_api_url }}"
    controller_oauthtoken: "{{ awx_api_token }}"
  register: _awx_project

- name: Display project result
  ansible.builtin.debug:
    msg: "Project '{{ awx_project_name }}' id={{ _awx_project.id | default('N/A') }} status={{ _awx_project.status | default('N/A') }}"
"""


def gen_role_tasks_inventories(config: Config) -> str:
    """Generate role tasks/inventories.yml – manage inventories + hosts via awx.awx.inventory + awx.awx.host."""
    hostname = config.fqdn.split(".")[0]
    return f"""\
---
# tasks/inventories.yml – manage AWX inventories and hosts
- name: Ensure static inventory exists
  awx.awx.inventory:
    name: "{{{{ awx_inventory_name }}}}"
    organization: "{{{{ awx_organization_name }}}}"
    state: present
    variables: "---\\n"
    controller_host: "{{{{ awx_api_url }}}}"
    controller_oauthtoken: "{{{{ awx_api_token }}}}"
  register: _awx_inventory

- name: Ensure host exists in inventory
  awx.awx.host:
    name: "{hostname}"
    inventory: "{{{{ awx_inventory_name }}}}"
    state: present
    variables: |
      ansible_host: {config.fqdn}
    controller_host: "{{{{ awx_api_url }}}}"
    controller_oauthtoken: "{{{{ awx_api_token }}}}"
  register: _awx_host

- name: Display inventory result
  ansible.builtin.debug:
    msg: "Inventory '{{{{ awx_inventory_name }}}}' id={{{{ _awx_inventory.id | default('N/A') }}}}, host '{hostname}' id={{{{ _awx_host.id | default('N/A') }}}}"
"""


def gen_role_tasks_job_templates(config: Config) -> str:
    """Generate role tasks/job_templates.yml – manage templates via awx.awx.job_template."""
    return """\
---
# tasks/job_templates.yml – manage AWX job templates (only when project configured)
- name: Ensure job template exists
  awx.awx.job_template:
    name: "{{ awx_job_template_name }}"
    job_type: run
    inventory: "{{ awx_inventory_name }}"
    project: "{{ awx_project_name }}"
    playbook: "{{ awx_job_template_playbook }}"
    credentials:
      - "{{ awx_machine_credential_name }}"
    ask_credential_on_launch: false
    state: present
    controller_host: "{{ awx_api_url }}"
    controller_oauthtoken: "{{ awx_api_token }}"
  register: _awx_jt

- name: Display job template result
  ansible.builtin.debug:
    msg: "Job template '{{ awx_job_template_name }}' id={{ _awx_jt.id | default('N/A') }}"
"""


def gen_role_tasks_users(config: Config) -> str:
    """Generate role tasks/users.yml – manage users via awx.awx.user."""
    return """\
---
# tasks/users.yml – manage AWX users
- name: Get current user info
  ansible.builtin.uri:
    url: "{{ awx_api_url }}/api/v2/me/"
    method: GET
    headers:
      Authorization: "Bearer {{ awx_api_token }}"
      Accept: "application/json"
    status_code: 200
  register: _current_user

- name: Display current AWX user
  ansible.builtin.debug:
    msg: "Currently authenticated as: {{ _current_user.json.results[0].username | default('unknown') }}"
"""


def gen_role_tasks_netbox(config: Config) -> str:
    """Generate role tasks/netbox.yml – NetBox integration."""
    return """\
---
# tasks/netbox.yml – NetBox integration (only when awx_netbox_url defined)
- name: Verify NetBox is reachable
  ansible.builtin.uri:
    url: "{{ awx_netbox_url }}/api/"
    method: GET
    headers:
      Authorization: "Token {{ awx_netbox_token }}"
      Accept: "application/json"
    status_code: 200
    timeout: 10
  register: _netbox_ping
  failed_when: false

- name: Warn if NetBox is unreachable
  when: _netbox_ping.status | default(0) != 200
  ansible.builtin.debug:
    msg: "WARNING: NetBox at {{ awx_netbox_url }} is not reachable (status={{ _netbox_ping.status | default('N/A') }}). Skipping NetBox tasks."

- name: Display NetBox API version
  when: _netbox_ping.status | default(0) == 200
  ansible.builtin.debug:
    msg: "NetBox reachable – API version: {{ _netbox_ping.json.netbox_version | default('unknown') }}"
"""


# ---------------------------------------------------------------------------
# Write all files
# ---------------------------------------------------------------------------

def write_all_files(
    config: Config,
    home: str,
    uid: int,
    gid: int,
    selinux_enforcing: bool,
) -> None:
    """Write all generated config / playbook / role files. No Dockerfile written."""
    h = Path(home)

    def write_file(rel_path: str, content: str, mode: int = 0o644) -> None:
        p = h / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp_gen")
        tmp.write_text(content)
        tmp.chmod(mode)
        os.chown(tmp, uid, gid)
        os.replace(tmp, p)
        log.debug("Wrote %s", p)

    # Compose files (NO Dockerfile)
    write_file(
        "compose/awx/docker-compose.yml",
        gen_compose_file(config, uid, gid, selinux_enforcing),
    )
    write_file("compose/awx/.env", gen_compose_env(config))

    # AWX Django settings (mounted into containers at /etc/tower/settings.py)
    write_file("config/awx_settings.py", gen_awx_settings_py())

    # AWX container nginx config (mounted at /etc/nginx/conf.d/awx.conf)
    write_file("config/awx_nginx.conf", gen_awx_container_nginx_config())

    # Receptor mesh config (used by awx_receptor sidecar + awx_task receptorctl)
    write_file("config/receptor.conf", gen_receptor_config())

    # Ansible cfg
    write_file("ansible.cfg", gen_ansible_cfg(config))

    # SSH client config – scopes deploy key to the git server host
    ssh_dir = h / ".ssh"
    if not ssh_dir.exists():
        ssh_dir.mkdir(mode=0o700, parents=True)
        os.chown(ssh_dir, uid, gid)
    write_file(".ssh/config", gen_ansible_ssh_config(config), mode=0o600)

    # Inventory
    write_file("inventories/static/hosts.yml", gen_inventory_hosts(config))

    hostname = config.fqdn.split(".")[0]
    host_vars_dir = f"inventories/static/host_vars/{hostname}"
    (h / host_vars_dir).mkdir(parents=True, exist_ok=True)
    os.chown(h / host_vars_dir, uid, gid)
    write_file(f"{host_vars_dir}/main.yml", gen_host_vars(config))

    write_file("inventories/static/group_vars/all/main.yml", gen_group_vars_all(config))
    write_file(
        "inventories/static/group_vars/awx_hosts/main.yml",
        gen_group_vars_awx(config),
    )
    write_file("inventories/dynamic/netbox.yml.disabled", gen_netbox_stub(config))

    # Playbooks
    write_file("playbooks/site.yml", gen_playbook_site(config))
    write_file("playbooks/awx_bootstrap.yml", gen_playbook_awx_bootstrap(config))

    # Role files
    role_base = "roles/awx_config"
    write_file(f"{role_base}/defaults/main.yml", gen_role_defaults(config))
    write_file(f"{role_base}/vars/main.yml", gen_role_vars(config))
    write_file(f"{role_base}/meta/main.yml", gen_role_meta(config))
    write_file(f"{role_base}/handlers/main.yml", gen_role_handlers(config))
    write_file(f"{role_base}/tasks/main.yml", gen_role_tasks_main(config))
    write_file(f"{role_base}/tasks/preflight.yml", gen_role_tasks_preflight(config))
    write_file(f"{role_base}/tasks/auth.yml", gen_role_tasks_auth(config))
    write_file(f"{role_base}/tasks/organizations.yml", gen_role_tasks_organizations(config))
    write_file(f"{role_base}/tasks/credentials.yml", gen_role_tasks_credentials(config))
    write_file(f"{role_base}/tasks/projects.yml", gen_role_tasks_projects(config))
    write_file(f"{role_base}/tasks/inventories.yml", gen_role_tasks_inventories(config))
    write_file(f"{role_base}/tasks/job_templates.yml", gen_role_tasks_job_templates(config))
    write_file(f"{role_base}/tasks/users.yml", gen_role_tasks_users(config))
    write_file(f"{role_base}/tasks/netbox.yml", gen_role_tasks_netbox(config))

    # NGINX config
    nginx_conf = gen_nginx_config(config)
    write_file(f"nginx/{config.fqdn}.conf", nginx_conf)

    log.info("All configuration files written.")


# ---------------------------------------------------------------------------
# Docker pull & start
# ---------------------------------------------------------------------------

def build_custom_awx_image(
    config: Config,
    state: State,
    force: bool = False,
) -> str:
    """Build custom AWX image with podman for process isolation.
    
    Returns the image name:tag to use in compose file.
    """
    custom_image = f"awx-podman:{config.awx_image_tag}"
    
    if state.is_complete("custom_awx_image_built") and not force:
        log.info("Custom AWX image already built (state checkpoint). Using %s.", custom_image)
        return custom_image
    
    dockerfile_path = Path(__file__).parent / "Dockerfile.awx"
    if not dockerfile_path.exists():
        log.warning("Dockerfile.awx not found at %s; using standard image.", dockerfile_path)
        return f"quay.io/ansible/awx:{config.awx_image_tag}"
    
    log.info("Building custom AWX image with podman support: %s", custom_image)
    log.info("  Base image: quay.io/ansible/awx:%s", config.awx_image_tag)
    
    # Detect docker/podman command
    build_cmd = None
    for cmd in ["docker", "podman"]:
        if run_ok([cmd, "--version"]):
            build_cmd = cmd
            break
    
    if not build_cmd:
        log.error("Neither docker nor podman found; cannot build custom image.")
        log.warning("Falling back to standard AWX image without podman.")
        return f"quay.io/ansible/awx:{config.awx_image_tag}"
    
    # Build with base image specified
    try:
        run(
            [
                build_cmd, "build",
                "-t", custom_image,
                "-f", str(dockerfile_path),
                "--build-arg", f"BASE_IMAGE=quay.io/ansible/awx:{config.awx_image_tag}",
                str(dockerfile_path.parent),
            ],
            check=True,
        )
        state.complete("custom_awx_image_built")
        log.info("Custom AWX image built successfully: %s", custom_image)
        return custom_image
    except subprocess.CalledProcessError as e:
        log.error("Failed to build custom AWX image: %s", e)
        log.warning("Falling back to standard AWX image without podman.")
        return f"quay.io/ansible/awx:{config.awx_image_tag}"



def build_custom_receptor_image(
    config: Config,
    state: State,
    force: bool = False,
) -> str:
    """Build custom receptor image with podman for process isolation.
    
    Returns the image name:tag to use in compose file.
    """
    custom_image = f"receptor-podman:5.0.0"
    
    if state.is_complete("custom_receptor_image_built") and not force:
        log.info("Custom receptor image already built (state checkpoint). Using %s.", custom_image)
        return custom_image
    
    dockerfile_path = Path(__file__).parent / "Dockerfile.receptor"
    if not dockerfile_path.exists():
        log.warning("Dockerfile.receptor not found at %s; using standard image.", dockerfile_path)
        return "quay.io/ansible/receptor:latest"
    
    log.info("Building custom receptor image with podman support: %s", custom_image)
    log.info("  Base image: quay.io/ansible/receptor:latest")
    
    # Detect docker/podman command
    build_cmd = None
    for cmd in ["docker", "podman"]:
        if run_ok([cmd, "--version"]):
            build_cmd = cmd
            break
    
    if not build_cmd:
        log.error("Neither docker nor podman found; cannot build custom docker image.")
        log.warning("Falling back to standard receptor image without podman.")
        return "quay.io/ansible/receptor:latest"
    
    # Build with base image specified
    try:
        run(
            [
                build_cmd, "build",
                "-t", custom_image,
                "-f", str(dockerfile_path),
                "--build-arg", "BASE_IMAGE=quay.io/ansible/receptor:latest",
                str(dockerfile_path.parent),
            ],
            check=True,
        )
        state.complete("custom_receptor_image_built")
        log.info("Custom receptor image built successfully: %s", custom_image)
        return custom_image
    except subprocess.CalledProcessError as e:
        log.error("Failed to build custom receptor image: %s", e)
        log.warning("Falling back to standard receptor image without podman.")
        return "quay.io/ansible/receptor:latest"
def pull_image(
    config: Config,
    compose_cmd: List[str],
    compose_file: str,
    state: State,
    force: bool = False,
) -> None:
    """Build/pull AWX image and pull supporting images."""
    if state.is_complete("image_pulled") and not force:
        log.info("Images already prepared (state checkpoint). Skipping.")
        return

    # Build custom AWX image with podman support
    custom_image = build_custom_awx_image(config, state, force=force)
    
    # If using custom image, update .env to reference it directly
    if custom_image.startswith("awx-podman:"):
        log.info("Using custom image: %s", custom_image)
        
        # Update .env file to use the custom image directly
        env_path = Path(compose_file).parent / ".env"
        if env_path.exists():
            content = env_path.read_text()
            # Replace AWX_TAG line with custom image name
            content = re.sub(
                r"^AWX_TAG=.*$",
                f"AWX_TAG={custom_image}",
                content,
                flags=re.MULTILINE
            )
            env_path.write_text(content)
            log.debug("Updated .env to use custom image: %s", custom_image)
        
        # Also directly update docker-compose.yml to use custom image
        compose_path = Path(compose_file)
        if compose_path.exists():
            content = compose_path.read_text()
            # Replace the template variable with direct image reference for both awx_web and awx_task
            content = re.sub(
                r"image: quay\.io/ansible/awx:\$\{AWX_TAG\}",
                f"image: {custom_image}",
                content
            )
            compose_path.write_text(content)
            log.debug("Updated docker-compose.yml to use custom image: %s", custom_image)

    # Build custom receptor image with podman support
    custom_receptor_image = build_custom_receptor_image(config, state, force=force)

    # Update .env and docker-compose.yml for both AWX and receptor images
    env_path = Path(compose_file).parent / ".env"
    if env_path.exists():
        content = env_path.read_text()
        
        # Update AWX_TAG if using custom AWX image
        if custom_image.startswith("awx-podman:"):
            content = re.sub(
                r"^AWX_TAG=.*$",
                f"AWX_TAG={custom_image}",
                content,
                flags=re.MULTILINE
            )
            log.debug("Updated .env to use custom AWX image: %s", custom_image)
        
        # Update RECEPTOR_TAG if using custom receptor image
        if custom_receptor_image.startswith("receptor-podman:"):
            if "RECEPTOR_TAG=" in content:
                content = re.sub(
                    r"^RECEPTOR_TAG=.*$",
                    f"RECEPTOR_TAG={custom_receptor_image}",
                    content,
                    flags=re.MULTILINE
                )
            else:
                # Add RECEPTOR_TAG if it doesn't exist
                content += f"\nRECEPTOR_TAG={custom_receptor_image}\n"
            log.debug("Updated .env to use custom receptor image: %s", custom_receptor_image)
        else:
            # Default receptor tag
            if "RECEPTOR_TAG=" not in content:
                content += "\nRECEPTOR_TAG=quay.io/ansible/receptor:latest\n"
        
        env_path.write_text(content)
    
    # Update docker-compose.yml to use the environment variables
    compose_path = Path(compose_file)
    if compose_path.exists():
        content = compose_path.read_text()
        
        # Replace the template variable with environment variables for both awx and receptor
        if custom_image.startswith("awx-podman:"):
            content = re.sub(
                r"image: quay\.io/ansible/awx:\$\{AWX_TAG\}",
                f"image: {custom_image}",
                content
            )
        
        if custom_receptor_image.startswith("receptor-podman:"):
            content = re.sub(
                r"image: \$\{RECEPTOR_TAG\}",
                f"image: {custom_receptor_image}",
                content
            )
        
        compose_path.write_text(content)
        log.debug("Updated docker-compose.yml with custom images")

    pull_services = ["redis"]
    if config.db_mode == "container":
        pull_services.append("postgres")

    log.info("Pulling supporting images (%s) ...", ", ".join(pull_services))
    run(
        compose_cmd + ["-f", compose_file, "pull", *pull_services],
        cwd=str(Path(compose_file).parent),
    )
    state.complete("image_pulled")
    log.info("Images prepared successfully.")

def _awx_settings_fingerprint(home: str) -> str:
    """SHA-256 prefix of awx_settings.py — used to detect when it changes."""
    p = Path(home) / "config" / "awx_settings.py"
    if not p.exists():
        return ""
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def _wait_for_postgres(
    compose_cmd: List[str],
    compose_file: str,
    db_user: str,
    db_name: str,
    timeout: int = 90,
) -> None:
    """Poll until the postgres container accepts local connections."""
    log.info("Waiting for postgres to be ready (timeout=%ds) ...", timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = run(
            ["docker", "exec", "awx_postgres",
             "pg_isready", "-U", db_user, "-d", db_name],
            capture=True,
            check=False,
        )
        if result.returncode == 0:
            log.info("Postgres is ready.")
            return
        time.sleep(3)
    raise TimeoutError(f"Postgres did not become ready within {timeout}s.")


def _find_pg_superuser(container: str, db_user: str) -> str:
    """Return the first postgres role that can connect via unix socket trust auth.

    The cluster may have been initialized with a different POSTGRES_USER than
    the one currently configured (e.g. on a re-deployed host reusing an old
    data volume, or after a config change).  We probe the two candidates that
    the official postgres docker image can produce:

      1. db_user   — POSTGRES_USER as currently configured (e.g. "awx")
      2. "postgres" — the default when POSTGRES_USER was not set at init time

    Raises RuntimeError if neither works.
    """
    for candidate in [db_user, "postgres"]:
        result = run(
            ["docker", "exec", "-i", container,
             "psql", "-U", candidate, "-d", "postgres", "-tAc", "SELECT 1"],
            capture=True,
            check=False,
        )
        if result.returncode == 0:
            if candidate != db_user:
                log.info(
                    "Connected to postgres as '%s' (cluster was initialized "
                    "with that superuser, not '%s').",
                    candidate, db_user,
                )
            return candidate
    raise RuntimeError(
        f"Cannot connect to postgres container '{container}' as any known "
        f"superuser (tried {[db_user, 'postgres']}).  "
        f"Ensure the container is running and pg_hba.conf allows local trust auth."
    )


def sync_postgres_password(
    config: "Config",
    home: str,
    compose_cmd: List[str],
    compose_file: str,
    state: Optional["State"] = None,
) -> bool:
    """Ensure the AWX DB user's password in postgres matches .awx.env.

    Returns True if the password was applied (caller should restart AWX services).

    Uses a SHA-256 hash of DATABASE_PASSWORD stored in the bootstrap state to
    determine whether a sync is needed.  This avoids the unreliable TCP loopback
    test (postgres pg_hba.conf typically uses trust auth for 127.0.0.1, so that
    test always succeeds regardless of the actual password).

    Uses _find_pg_superuser() to discover the actual superuser role for the
    cluster, which may differ from db_user when the data dir was initialized
    with a different POSTGRES_USER.
    """
    if config.db_mode != "container":
        return False  # Can't manage external DB passwords automatically.

    awx_env_path = Path(home) / "secrets" / ".awx.env"
    if not awx_env_path.exists():
        log.warning("secrets/.awx.env not found – cannot sync postgres password.")
        return False

    current_password: Optional[str] = None
    for line in awx_env_path.read_text().splitlines():
        if line.startswith("DATABASE_PASSWORD="):
            current_password = line[len("DATABASE_PASSWORD="):]
            break
    if not current_password:
        log.warning("DATABASE_PASSWORD not found in .awx.env – skipping password sync.")
        return False

    db_user = config.db_user
    db_name = config.db_name

    # Skip sync if we've already applied this exact password before.
    pw_hash = hashlib.sha256(current_password.encode()).hexdigest()
    if state and state.get("postgres_password_hash") == pw_hash:
        log.debug("Postgres password hash unchanged – skipping sync.")
        return False

    escaped_pw = current_password.replace("'", "''")

    # Discover which role can actually connect as superuser.  The cluster may
    # have been initialized with a different POSTGRES_USER than db_user.
    log.info("Provisioning postgres user '%s' ...", db_user)
    superuser = _find_pg_superuser("awx_postgres", db_user)

    # Single idempotent DO block: create the role if missing, else update password.
    user_sql = (
        f"DO $do$\n"
        f"BEGIN\n"
        f"  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='{db_user}') THEN\n"
        f"    CREATE USER {db_user} WITH PASSWORD '{escaped_pw}';\n"
        f"  ELSE\n"
        f"    ALTER USER {db_user} WITH PASSWORD '{escaped_pw}';\n"
        f"  END IF;\n"
        f"END $do$;\n"
    )
    result = run(
        ["docker", "exec", "-i", "awx_postgres",
         "psql", "-U", superuser, "-d", "postgres"],
        input=user_sql,
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to provision postgres user '{db_user}': {result.stderr}"
        )

    # CREATE DATABASE cannot run inside a transaction/DO block so check
    # pg_database first and create only when missing.
    db_check = run(
        ["docker", "exec", "-i", "awx_postgres",
         "psql", "-U", superuser, "-d", "postgres", "-tAc",
         f"SELECT 1 FROM pg_database WHERE datname='{db_name}'"],
        capture=True,
        check=False,
    )
    if db_check.stdout.strip() != "1":
        log.info("Creating postgres database '%s' ...", db_name)
        db_result = run(
            ["docker", "exec", "-i", "awx_postgres",
             "psql", "-U", superuser, "-d", "postgres"],
            input=(
                f"CREATE DATABASE {db_name} OWNER {db_user};\n"
                f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {db_user};\n"
            ),
            capture=True,
            check=False,
        )
        if db_result.returncode != 0:
            raise RuntimeError(
                f"Failed to create postgres database '{db_name}': {db_result.stderr}"
            )

    log.info("Postgres provisioning complete (user '%s', database '%s').", db_user, db_name)
    if state:
        state.set("postgres_password_hash", pw_hash)
    return True


def _run_awx_migrations(config: "Config", timeout: int = 300) -> None:
    """Run AWX database migrations and initial data inside the awx_web container.

    ``launch_awx_web.sh`` starts supervisord directly without calling
    ``awx-manage migrate``, so the bootstrap must do it.  The command is
    idempotent: on subsequent runs it only applies new migrations and
    returns quickly when the schema is already up-to-date.

    Sequence:
      1. migrate         — apply pending DB schema migrations
      2. create superuser — create_preload_data requires a superuser to exist
      3. create_preload_data — sets up install UUID, default org, demo objects
    All three steps are idempotent.
    """
    transient = ("No such container", "is not running", "executable file not found")

    def _exec(cmd: List[str], label: str, t: int) -> None:
        log.info("%s (timeout=%ds) ...", label, t)
        deadline = time.time() + t
        while time.time() < deadline:
            result = run(["docker", "exec", "awx_web"] + cmd,
                         capture=True, check=False)
            if result.returncode == 0:
                return
            if any(s in result.stderr for s in transient):
                time.sleep(3)
                continue
            raise RuntimeError(
                f"{label} failed (exit {result.returncode}):\n"
                f"{result.stderr[-1000:]}"
            )
        raise TimeoutError(f"{label} did not complete within {t}s.")

    _exec(["awx-manage", "migrate"], "Running AWX database migrations", timeout)
    log.info("AWX migrations complete.")

    # create_preload_data requires a superuser — create or update ours first.
    admin_script = (
        "from django.contrib.auth import get_user_model; "
        "User = get_user_model(); "
        f"u, _ = User.objects.get_or_create(username={config.awx_admin_login!r}); "
        "u.is_superuser = True; u.is_staff = True; "
        f"u.email = {config.awx_admin_email!r}; "
        f"u.set_password({config.awx_admin_password!r}); "
        "u.save()"
    )
    _exec(["awx-manage", "shell", "-c", admin_script],
          "Creating AWX admin user", 30)
    _exec(["awx-manage", "create_preload_data"],
          "Initialising AWX default data", 60)
    _exec(
        ["awx-manage", "register_default_execution_environments"],
        "Registering AWX default execution environments",
        30,
    )


def _ensure_controlplane_queue(timeout: int = 60) -> None:
    """Ensure AWX has the required control-plane instance group membership.

    Some fresh installs can end up with no controlplane group, or with the
    group present but empty. Both conditions leave project updates stuck in
    pending/needs_capacity. This helper repairs the group and ensures the
    local hybrid node is attached to it.
    """
    deadline = time.time() + timeout
    transient = ("No such container", "is not running")

    check_cmd = [
        "docker",
        "exec",
        "awx_web",
        "awx-manage",
        "shell",
        "-c",
        (
            "from awx.main.models.ha import InstanceGroup; "
            "ig = InstanceGroup.objects.filter(name='controlplane').first(); "
            "print('ok' if ig and ig.instances.filter(hostname='awx_task').exists() "
            "else ('missing-member' if ig else 'missing-group'))"
        ),
    ]
    repair_cmd = [
        "docker",
        "exec",
        "awx_task",
        "awx-manage",
        "register_queue",
        "--queuename=controlplane",
        "--hostnames=awx_task",
    ]
    attach_cmd = [
        "docker",
        "exec",
        "awx_web",
        "awx-manage",
        "shell",
        "-c",
        (
            "from awx.main.models.ha import Instance, InstanceGroup; "
            "ig, _ = InstanceGroup.objects.get_or_create(name='controlplane'); "
            "inst = Instance.objects.filter(hostname='awx_task').first(); "
            "print('no-instance' if inst is None else (ig.instances.add(inst) or 'ok'))"
        ),
    ]

    while time.time() < deadline:
        check = run(check_cmd, capture=True, check=False)
        out = (check.stdout or "").strip()
        if check.returncode == 0 and out.endswith("ok"):
            log.info("AWX controlplane queue is present and awx_task is attached.")
            return

        if any(s in (check.stderr or "") for s in transient):
            time.sleep(3)
            continue

        log.warning(
            "AWX controlplane queue topology incomplete (%s); attempting repair.",
            out or "unknown",
        )
        repair = run(repair_cmd, capture=True, check=False)
        if repair.returncode != 0 and any(s in (repair.stderr or "") for s in transient):
            time.sleep(3)
            continue
        attach = run(attach_cmd, capture=True, check=False)
        attach_out = (attach.stdout or "").strip()
        if attach.returncode != 0 and any(s in (attach.stderr or "") for s in transient):
            time.sleep(3)
            continue
        if attach_out.endswith("no-instance"):
            time.sleep(3)
            continue
        time.sleep(2)

    raise RuntimeError(
        "Could not ensure AWX controlplane queue membership within timeout; scheduler may remain stuck."
    )


def start_containers(
    compose_cmd: List[str],
    compose_file: str,
    state: State,
    home: str,
    config: "Config",
) -> None:
    """Ensure containers are up and healthy.

    Container-DB startup sequence (db_mode=container):
      1. Start postgres and redis only.
      2. Wait for postgres to be healthy.
      3. Provision the AWX database user and database with the correct password
         BEFORE AWX ever starts — eliminates auth-failure crash loops.
      4. Start all remaining containers; HTTP readiness is polled by
         wait_for_http() after this function returns.

    For external DB (db_mode=external) steps 1-3 are skipped.

    Re-run behaviour:
      - Fingerprint unchanged + containers healthy: check DB provisioning
        (detects state-wipe / new password), restart AWX only if needed.
      - Fingerprint changed: stop AWX containers, then go through steps 1-4
        so they restart with updated settings.
    """
    cwd = str(Path(compose_file).parent)
    was_started = state.is_complete("containers_started")
    current_fp = _awx_settings_fingerprint(home)
    stored_fp = state.get("settings_fingerprint", "")

    if was_started and current_fp == stored_fp:
        # Fast path: if containers are running and nothing changed, check DB only.
        result = run(
            compose_cmd + ["-f", compose_file, "ps", "--status", "running"],
            cwd=cwd, capture=True, check=False,
        )
        if "awx" in result.stdout:
            if sync_postgres_password(config, home, compose_cmd, compose_file, state):
                log.info("Restarting AWX services after DB provisioning ...")
                run(
                    compose_cmd + ["-f", compose_file, "restart", "awx_web", "awx_task"],
                    cwd=cwd, check=False,
                )
                run(compose_cmd + ["-f", compose_file, "up", "-d"], cwd=cwd)
                _ensure_controlplane_queue()
                state.set("settings_fingerprint", current_fp)
                state.complete("containers_started")
            else:
                _ensure_controlplane_queue()
                log.info("Containers running; settings and password unchanged.")
            return
        log.info("Containers not running despite state checkpoint – restarting ...")

    if was_started and current_fp != stored_fp:
        log.info(
            "awx_settings.py changed (fingerprint %s → %s) – stopping AWX services ...",
            stored_fp, current_fp,
        )
        run(
            compose_cmd + ["-f", compose_file, "stop", "awx_web", "awx_task"],
            cwd=cwd, check=False,
        )

    if config.db_mode == "container":
        # Phase 1: Start postgres and redis only — do NOT start AWX yet.
        log.info("Starting postgres and redis ...")
        run(
            compose_cmd + ["-f", compose_file, "up", "-d", "postgres", "redis"],
            cwd=cwd,
        )

        # Phase 2: Wait until postgres accepts connections.
        _wait_for_postgres(compose_cmd, compose_file, config.db_user, config.db_name)

        # Phase 3: Provision AWX user+database before AWX starts.
        # sync_postgres_password creates the role/db if missing or updates the
        # password if it changed.  Running this now means AWX will have valid
        # credentials from its very first connection attempt.
        log.info("Provisioning AWX database user and database ...")
        sync_postgres_password(config, home, compose_cmd, compose_file, state)

    # Phase 4: Start all services (AWX included).
    # Readiness is polled later via wait_for_http(); the Docker healthcheck
    # is kept for 'docker ps' status but not used as a blocking gate here
    # because AWX runs DB migrations on first boot, which can take minutes.
    log.info("Starting all containers ...")
    run(compose_cmd + ["-f", compose_file, "up", "-d"], cwd=cwd)

    # Phase 5: Run Django migrations.
    # launch_awx_web.sh starts supervisord directly without migrating, so
    # we must call awx-manage migrate ourselves.
    _run_awx_migrations(config)
    _ensure_controlplane_queue()

    state.set("settings_fingerprint", current_fp)
    state.complete("containers_started")
    log.info("Containers are up and healthy.")


def wait_for_http(url: str, timeout: int = 600) -> None:
    """Poll a URL until it returns HTTP 200 or timeout expires.

    Does NOT follow redirects so that AWX's 302→/migrations_notran/ is
    distinguishable from a real 400/500, giving the operator a useful log
    message instead of a confusing 400 timeout.
    """
    class _NoFollow(urllib.request.HTTPRedirectHandler):
        """Raise HTTPError on any redirect so we can inspect the Location."""
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    opener = urllib.request.build_opener(_NoFollow())
    log.info("Waiting for %s to become available (timeout=%ds) ...", url, timeout)
    deadline = time.time() + timeout
    last_msg = ""
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url)
            with opener.open(req, timeout=10) as resp:
                if resp.status == 200:
                    log.info("Service at %s is up.", url)
                    return
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location", "")
            if exc.code in (301, 302) and "migration" in location:
                msg = "AWX is applying database migrations, waiting ..."
            elif exc.code in (301, 302):
                msg = f"Redirected ({exc.code}) → {location}"
            else:
                msg = f"HTTP {exc.code} from {url}"
            if msg != last_msg:
                log.info(msg)
                last_msg = msg
        except Exception as exc:
            msg = str(exc)
            if msg != last_msg:
                log.debug("Connection error: %s", msg)
                last_msg = msg
        time.sleep(10)
    raise TimeoutError(f"Service at {url} did not respond within {timeout}s.")


# ---------------------------------------------------------------------------
# AWX API helpers
# ---------------------------------------------------------------------------

def awx_api_call(
    method: str,
    base_url: str,
    path: str,
    token: Optional[str] = None,
    basic_user: Optional[str] = None,
    basic_pass: Optional[str] = None,
    data: Optional[Any] = None,
    params: Optional[Dict[str, str]] = None,
) -> Tuple[int, Any]:
    """Make an AWX API call. Returns (status_code, parsed_json_or_string).

    Supports Bearer token auth or HTTP Basic auth.
    Handles AWX paginated responses (count/results format) transparently.
    """
    # Build URL with optional query params
    url = f"{base_url}{path}"
    if params:
        query = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in params.items())
        url = f"{url}?{query}" if "?" not in url else f"{url}&{query}"

    body: Optional[bytes] = None
    headers: Dict[str, str] = {"Accept": "application/json"}

    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"

    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif basic_user is not None and basic_pass is not None:
        creds = base64.b64encode(f"{basic_user}:{basic_pass}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"

    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except urllib.error.URLError as exc:
        raise RuntimeError(f"API call to {url} failed: {exc}") from exc

    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = raw.decode(errors="replace")

    log.debug("AWX API %s %s → %d", method.upper(), path, status)
    return status, parsed


def awx_create_token(
    base_url: str,
    admin_user: str,
    admin_pass: str,
) -> str:
    """POST /api/v2/tokens/ with Basic auth, return the token string."""
    status, body = awx_api_call(
        "POST",
        base_url,
        "/api/v2/tokens/",
        basic_user=admin_user,
        basic_pass=admin_pass,
        data={"scope": "write"},
    )
    if status not in (200, 201):
        raise RuntimeError(f"AWX token creation failed: HTTP {status}: {body}")
    if isinstance(body, dict):
        token = body.get("token")
        if token:
            return str(token)
    raise RuntimeError(f"Unexpected AWX token response: {body}")


def awx_find_by_name(
    base_url: str,
    path: str,
    token: str,
    name: str,
    params: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """GET a paginated AWX list and find an object by name field.

    AWX wraps list responses as {"count": N, "results": [...]}.
    """
    query = dict(params) if params else {}
    query["name"] = name
    status, body = awx_api_call("GET", base_url, path, token=token, params=query)
    if status != 200:
        return None
    if isinstance(body, dict):
        results = body.get("results", [])
        for item in results:
            if isinstance(item, dict) and item.get("name") == name:
                return item
    elif isinstance(body, list):
        for item in body:
            if isinstance(item, dict) and item.get("name") == name:
                return item
    return None


def awx_get_credential_type_id(
    base_url: str,
    token: str,
    kind: str,
    name: str,
) -> int:
    """Fetch the id of a managed credential type by kind and name."""
    status, body = awx_api_call(
        "GET",
        base_url,
        "/api/v2/credential_types/",
        token=token,
        params={"kind": kind, "managed": "true"},
    )
    if status != 200:
        raise RuntimeError(f"Failed to list credential types: HTTP {status}: {body}")
    results = body.get("results", []) if isinstance(body, dict) else []
    for item in results:
        if isinstance(item, dict) and item.get("name") == name:
            return int(item["id"])
    raise RuntimeError(
        f"Credential type '{name}' (kind={kind}) not found in AWX. "
        f"Available: {[r.get('name') for r in results]}"
    )


def awx_project_has_playbook(
    base_url: str,
    token: str,
    project_id: int,
    playbook: str,
) -> bool:
    """Return True if a playbook is currently discoverable for the project."""
    status, body = awx_api_call(
        "GET",
        base_url,
        f"/api/v2/projects/{project_id}/playbooks/",
        token=token,
    )
    if status != 200:
        log.warning(
            "Could not query project playbooks for id=%d (HTTP %d): %s",
            project_id,
            status,
            body,
        )
        return False

    candidates: List[str] = []
    if isinstance(body, list):
        candidates = [str(x) for x in body]
    elif isinstance(body, dict):
        results = body.get("results", [])
        if isinstance(results, list):
            candidates = [str(x) for x in results]

    return playbook in candidates


def awx_update_project_and_wait(
    base_url: str,
    token: str,
    project_id: int,
    timeout: int = 300,
) -> None:
    """Trigger a project update and wait until the project sync settles."""
    awx_cancel_queued_project_updates(base_url, token, project_id)
    status, body = awx_api_call(
        "POST",
        base_url,
        f"/api/v2/projects/{project_id}/update/",
        token=token,
        data={},
    )
    if status not in (200, 201, 202):
        raise RuntimeError(
            f"Failed to start project update for id={project_id}: HTTP {status}: {body}"
        )
    awx_wait_for_project_sync(base_url, token, project_id, timeout=timeout)


def awx_cancel_queued_project_updates(
    base_url: str,
    token: str,
    project_id: int,
) -> None:
    """Cancel non-terminal project updates that can deadlock new sync attempts."""
    status, body = awx_api_call(
        "GET",
        base_url,
        f"/api/v2/projects/{project_id}/project_updates/",
        token=token,
        params={"page_size": "200", "order_by": "id"},
    )
    if status != 200:
        log.warning(
            "Could not list existing project updates for id=%d (HTTP %d): %s",
            project_id,
            status,
            body,
        )
        return

    results = body.get("results", []) if isinstance(body, dict) else []
    if not isinstance(results, list):
        return

    cancel_statuses = {"new", "pending", "waiting", "running"}
    queued = [
        item
        for item in results
        if isinstance(item, dict) and str(item.get("status", "")) in cancel_statuses
    ]
    if not queued:
        return

    log.warning(
        "Found %d non-terminal project updates for project id=%d; cancelling stale queue.",
        len(queued),
        project_id,
    )
    for item in queued:
        upd_id = item.get("id")
        if upd_id is None:
            continue
        c_status, c_body = awx_api_call(
            "POST",
            base_url,
            f"/api/v2/project_updates/{upd_id}/cancel/",
            token=token,
            data={},
        )
        if c_status in (200, 202, 204):
            log.info("Requested cancellation of project update id=%s.", upd_id)
        else:
            log.warning(
                "Could not cancel project update id=%s (HTTP %d): %s",
                upd_id,
                c_status,
                c_body,
            )

    # Give AWX a short window to clear its queue before creating a new update.
    deadline = time.time() + 30
    while time.time() < deadline:
        r_status, r_body = awx_api_call(
            "GET",
            base_url,
            f"/api/v2/projects/{project_id}/project_updates/",
            token=token,
            params={"page_size": "50", "order_by": "-id"},
        )
        if r_status != 200:
            break
        r_results = r_body.get("results", []) if isinstance(r_body, dict) else []
        if not isinstance(r_results, list):
            break
        still_queued = False
        for item in r_results:
            if not isinstance(item, dict):
                continue
            if str(item.get("status", "")) in cancel_statuses:
                still_queued = True
                break
        if not still_queued:
            return
        time.sleep(2)


def awx_prune_stale_instances(
    base_url: str,
    token: str,
    preserve_hostnames: Set[str],
) -> int:
    """Remove stale AWX instance records left from previous failed runs."""
    status, body = awx_api_call(
        "GET",
        base_url,
        "/api/v2/instances/",
        token=token,
        params={"page_size": "200"},
    )
    if status != 200:
        log.warning("Could not list AWX instances for pruning (HTTP %d): %s", status, body)
        return 0

    results = body.get("results", []) if isinstance(body, dict) else []
    if not isinstance(results, list):
        return 0

    removed = 0
    for item in results:
        if not isinstance(item, dict):
            continue
        inst_id = item.get("id")
        hostname = str(item.get("hostname", ""))
        node_state = str(item.get("node_state", ""))
        capacity = int(item.get("capacity") or 0)
        version = str(item.get("version") or "")
        last_seen = item.get("last_seen")

        if not inst_id or hostname in preserve_hostnames:
            continue

        stale = False
        if node_state in ("unavailable", "deprovisioning", "deprovisioned"):
            stale = True
        elif last_seen in (None, "") and capacity == 0 and version == "":
            stale = True

        if not stale:
            continue

        result = run(
            [
                "docker",
                "exec",
                "awx_task",
                "awx-manage",
                "deprovision_instance",
                f"--hostname={hostname}",
            ],
            capture=True,
            check=False,
        )
        if result.returncode == 0:
            removed += 1
            log.warning(
                "Removed stale AWX instance id=%s hostname=%s state=%s.",
                inst_id,
                hostname,
                node_state,
            )
        else:
            log.warning(
                "Could not remove stale AWX instance id=%s hostname=%s via deprovision_instance (exit %d): %s",
                inst_id,
                hostname,
                result.returncode,
                (result.stderr or result.stdout).strip(),
            )
    return removed


def awx_latest_project_update_issue(
    base_url: str,
    token: str,
    project_id: int,
) -> str:
    """Return known fatal project-update issue text, or empty string."""
    status, body = awx_api_call(
        "GET",
        base_url,
        f"/api/v2/projects/{project_id}/project_updates/",
        token=token,
        params={"order_by": "-id", "page_size": "1"},
    )
    if status != 200 or not isinstance(body, dict):
        return ""
    results = body.get("results", [])
    if not isinstance(results, list) or not results:
        return ""
    item = results[0] if isinstance(results[0], dict) else {}
    explanation = str(item.get("job_explanation") or "")
    if "Failed to find default control plane EE" in explanation:
        return "missing_default_control_plane_ee"
    if "Unable to find process isolation executable: podman" in explanation:
        return "missing_podman_runtime"
    return ""


def awx_recover_project_sync(
    base_url: str,
    token: str,
    project_id: int,
    home: str,
) -> None:
    """Attempt targeted recovery when project updates are stuck or queue-lost."""
    log.warning(
        "Attempting AWX project sync recovery for project id=%d (queue cleanup + stale instance pruning + service restart).",
        project_id,
    )
    awx_cancel_queued_project_updates(base_url, token, project_id)
    awx_prune_stale_instances(base_url, token, preserve_hostnames={"awx_web", "awx_task"})

    compose_file = str(Path(home) / "compose" / "awx" / "docker-compose.yml")
    compose_cmd = ["docker", "compose"]
    run(
        compose_cmd + ["-f", compose_file, "restart", "awx_web", "awx_task", "receptor"],
        cwd=str(Path(compose_file).parent),
        check=False,
    )
    time.sleep(10)
    wait_for_http(f"{base_url}/api/v2/ping/", timeout=240)


def awx_sync_project_with_recovery(
    base_url: str,
    token: str,
    project_id: int,
    home: str,
    timeout: int = 300,
    trigger_update: bool = True,
    attempts: int = 3,
) -> None:
    """Sync project with bounded retries and runtime recovery between attempts."""
    do_update = trigger_update
    for attempt in range(1, attempts + 1):
        try:
            if do_update:
                awx_update_project_and_wait(base_url, token, project_id, timeout=timeout)
            else:
                awx_wait_for_project_sync(base_url, token, project_id, timeout=timeout)
            return
        except (RuntimeError, TimeoutError) as exc:
            issue = awx_latest_project_update_issue(base_url, token, project_id)
            if issue == "missing_default_control_plane_ee":
                raise RuntimeError(
                    "AWX project update failed because no default control-plane execution "
                    "environment is available. Ensure 'awx-manage "
                    "register_default_execution_environments' succeeds during bootstrap."
                ) from exc
            if issue == "missing_podman_runtime":
                raise RuntimeError(
                    "AWX project update failed because process-isolation runtime 'podman' "
                    "is unavailable in the execution worker environment. Ensure the worker "
                    "container that runs ansible-runner has podman installed and reachable in PATH."
                ) from exc
            if attempt >= attempts:
                raise
            log.warning(
                "Project sync attempt %d/%d failed for project id=%d: %s",
                attempt,
                attempts,
                project_id,
                exc,
            )
            awx_recover_project_sync(base_url, token, project_id, home)
            # After recovery, always trigger a fresh update.
            do_update = True


def _awx_playbook_not_found_error(body: Any) -> bool:
    """Return True if API error body indicates project playbook discovery lag."""
    if not isinstance(body, dict):
        return False
    playbook_err = body.get("playbook")
    if isinstance(playbook_err, list):
        return any("Playbook not found for project" in str(msg) for msg in playbook_err)
    if isinstance(playbook_err, str):
        return "Playbook not found for project" in playbook_err
    return False


def awx_controlplane_has_capacity(base_url: str, token: str) -> Tuple[bool, str]:
    """Return whether AWX controlplane has at least one schedulable member.

    A pending project update can remain queued forever when the controlplane
    instance group exists but has no READY+enabled control/hybrid members.
    """
    group = awx_find_by_name(
        base_url,
        "/api/v2/instance_groups/",
        token,
        "controlplane",
        params={"page_size": "200"},
    )
    if not group:
        return False, "AWX controlplane instance group is missing."

    related = group.get("related", {}) if isinstance(group, dict) else {}
    members_path = related.get("instances") if isinstance(related, dict) else None
    if not members_path:
        group_id = group.get("id") if isinstance(group, dict) else None
        if not group_id:
            return False, "AWX controlplane instance group has no inspectable instance list."
        members_path = f"/api/v2/instance_groups/{group_id}/instances/"

    status, body = awx_api_call(
        "GET",
        base_url,
        str(members_path),
        token=token,
        params={"page_size": "200"},
    )
    if status != 200:
        return False, f"Could not query controlplane members (HTTP {status})."

    results = body.get("results", []) if isinstance(body, dict) else []
    if not isinstance(results, list):
        return False, "Unexpected response from controlplane instance membership API."

    schedulable = []
    seen = []
    for item in results:
        if not isinstance(item, dict):
            continue
        hostname = str(item.get("hostname", "unknown"))
        node_type = str(item.get("node_type", ""))
        node_state = str(item.get("node_state", ""))
        enabled = bool(item.get("enabled", False))
        capacity = int(item.get("capacity") or 0)
        seen.append(
            f"{hostname}(type={node_type},state={node_state},enabled={enabled},cap={capacity})"
        )
        if (
            node_type in ("control", "hybrid")
            and enabled
            and node_state in ("ready", "installed")
            and capacity > 0
        ):
            schedulable.append(hostname)

    if schedulable:
        return True, f"Schedulable control-plane instances: {', '.join(schedulable)}"

    if not seen:
        status, body = awx_api_call(
            "GET",
            base_url,
            "/api/v2/instances/",
            token=token,
            params={"page_size": "200"},
        )
        if status == 200 and isinstance(body, dict):
            all_results = body.get("results", [])
            if isinstance(all_results, list):
                registered = [
                    str(item.get("hostname", "unknown"))
                    for item in all_results
                    if isinstance(item, dict)
                ]
                if registered:
                    return False, (
                        "AWX controlplane instance group has no members. "
                        f"Registered instances: {', '.join(registered)}"
                    )
        return False, "AWX controlplane instance group has no members."

    if seen:
        return False, "No schedulable control-plane members found. " + "; ".join(seen)
    return False, "No AWX instances registered yet."


def awx_wait_for_project_sync(
    base_url: str,
    token: str,
    project_id: int,
    timeout: int = 300,
) -> None:
    """Poll project status until sync succeeds or fails. Timeout in seconds."""
    log.info("Waiting for AWX project (id=%d) to sync (timeout=%ds) ...", project_id, timeout)
    deadline = time.time() + timeout
    first_pending_at: Optional[float] = None
    while time.time() < deadline:
        status, body = awx_api_call(
            "GET", base_url, f"/api/v2/projects/{project_id}/", token=token
        )
        if status != 200:
            raise RuntimeError(
                f"Failed to get project status: HTTP {status}: {body}"
            )
        sync_status = body.get("status", "") if isinstance(body, dict) else ""
        log.debug("Project %d sync status: %s", project_id, sync_status)
        if sync_status == "successful":
            log.info("Project (id=%d) sync successful.", project_id)
            return
        elif sync_status == "pending":
            if first_pending_at is None:
                first_pending_at = time.time()
            # Give AWX some time to schedule work before flagging capacity issues.
            if time.time() - first_pending_at >= 60:
                has_capacity, detail = awx_controlplane_has_capacity(base_url, token)
                if not has_capacity:
                    raise RuntimeError(
                        "Project sync is still pending and AWX has no schedulable "
                        "control-plane capacity. "
                        f"{detail} "
                        "Check awx_task container logs and instance registration."
                    )
        elif sync_status in ("failed", "error", "canceled"):
            raise RuntimeError(
                f"Project sync failed with status: {sync_status}"
            )
        time.sleep(10)
    raise TimeoutError(
        f"Project (id={project_id}) did not finish syncing within {timeout}s."
    )


def _git_env_with_deploy_key(home: str) -> Dict[str, str]:
    """Return environment with deploy key injected for git/ssh commands."""
    key_path = Path(home) / "keys" / "deploy_key"
    if not key_path.exists():
        raise RuntimeError(f"Deploy key not found at {key_path}")
    ssh_cmd = (
        f"ssh -i {key_path} "
        "-o IdentitiesOnly=yes "
        "-o StrictHostKeyChecking=accept-new"
    )
    return {"GIT_SSH_COMMAND": ssh_cmd}


def _sync_tree_without_git(source: Path, target: Path) -> None:
    """Copy source tree into target, excluding .git metadata."""
    for item in source.iterdir():
        if item.name == ".git":
            continue
        dest = target / item.name
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)


def _prepare_seed_source_from_local_scaffold(home: str, dest: Path) -> bool:
    """Copy generated local scaffold files into seed destination."""
    h = Path(home)
    copied_any = False
    for name in ["README.md", "ansible.cfg", "playbooks", "roles", "inventories"]:
        src = h / name
        if not src.exists():
            continue
        dst = dest / name
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
        copied_any = True

    # Ensure repository contains starter README files for discoverability.
    readmes = {
        dest / "README.md": (
            "# Ansible Repository\n\n"
            "This repository was initialized by bootstrap_awx.py.\n"
            "It contains playbooks, roles, and inventories for AWX.\n"
        ),
        dest / "playbooks" / "README.md": "# Playbooks\n\nStore entry-point playbooks here.\n",
        dest / "roles" / "README.md": "# Roles\n\nStore Ansible roles here.\n",
        dest / "inventories" / "README.md": "# Inventories\n\nStore static and dynamic inventories here.\n",
    }
    for path, content in readmes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content)
            copied_any = True

    return copied_any


def confirm_git_repo_key_access(
    config: Config,
    home: str,
    state: State,
    non_interactive: bool,
    assume_git_key_ready: bool,
) -> None:
    """Print deploy public key and wait for operator confirmation."""
    if not config.git_ssh_url:
        return

    pub_key_path = Path(home) / "keys" / "deploy_key.pub"
    if not pub_key_path.exists():
        raise RuntimeError(f"Deploy public key not found at {pub_key_path}")
    pub_key = pub_key_path.read_text().strip()

    print("\n=== Git Deploy Key Confirmation Required ===")
    print("Target repository:", config.git_ssh_url)
    print("Deploy public key (grant read/write access):")
    print(pub_key)
    print("============================================\n")

    if non_interactive:
        if not assume_git_key_ready:
            raise RuntimeError(
                "Non-interactive mode requires --assume-git-key-ready for repository seeding."
            )
        log.info("Assuming deploy key is already authorized (--assume-git-key-ready).")
    else:
        ok = prompt_confirm(
            "Has this deploy key been granted read/write access to the target repository?",
            default=False,
        )
        if not ok:
            raise RuntimeError("Repository key access not confirmed by operator.")

    # Keep confirmation explicit per run; do not cache in state.


def seed_blank_repo_from_current_awx(
    config: Config,
    home: str,
    state: State,
    non_interactive: bool,
    assume_git_key_ready: bool,
) -> None:
    """Ensure target Git repo has required scaffold content.

    Behavior:
    - If repo is blank: populate from local scaffold.
    - If repo exists but misses required structure: prompt to populate (interactive)
      or auto-populate when explicitly allowed in non-interactive mode.
    - If repo already has required structure: do nothing.
    """
    if not config.git_ssh_url:
        return

    seeded_key = f"git_repo_seeded::{config.git_ssh_url}::{config.git_branch}"

    confirm_git_repo_key_access(
        config,
        home,
        state,
        non_interactive=non_interactive,
        assume_git_key_ready=assume_git_key_ready,
    )

    git_env = _git_env_with_deploy_key(home)
    ls_remote_result = run(
        ["git", "ls-remote", "--heads", config.git_ssh_url],
        env=git_env,
        capture=True,
        check=False,
    )
    if ls_remote_result.returncode != 0:
        err = (ls_remote_result.stderr or ls_remote_result.stdout or "").strip()
        raise RuntimeError(
            "Could not access target repository with deploy key. "
            f"Repository: {config.git_ssh_url}. "
            f"git ls-remote exit={ls_remote_result.returncode}. "
            f"Details: {err}"
        )
    ls_heads = ls_remote_result.stdout.strip()
    repo_is_blank = not bool(ls_heads)

    required_paths = ["README.md", "playbooks", "roles", "inventories"]

    with tempfile.TemporaryDirectory(prefix="awx_repo_seed_") as tmpdir:
        target_worktree = Path(tmpdir) / "target"
        run(["git", "clone", config.git_ssh_url, str(target_worktree)], env=git_env, check=True)

        if repo_is_blank:
            run(["git", "checkout", "--orphan", config.git_branch], cwd=str(target_worktree), check=True)
        else:
            # Move to target branch if it exists; otherwise create it from current HEAD.
            branch_exists = run(
                ["git", "show-ref", "--verify", f"refs/remotes/origin/{config.git_branch}"],
                cwd=str(target_worktree),
                check=False,
                capture=True,
            ).returncode == 0
            if branch_exists:
                run(["git", "checkout", "-B", config.git_branch, f"origin/{config.git_branch}"], cwd=str(target_worktree), check=True)
            else:
                run(["git", "checkout", "-B", config.git_branch], cwd=str(target_worktree), check=True)

        missing_paths = [p for p in required_paths if not (target_worktree / p).exists()]
        if not repo_is_blank and not missing_paths:
            log.info(
                "Target repository %s already contains required scaffold; no population needed.",
                config.git_ssh_url,
            )
            state.set(seeded_key, True)
            return

        if repo_is_blank:
            should_populate = True
            log.info("Target repository %s is blank; preparing initial scaffold population.", config.git_ssh_url)
        else:
            if non_interactive:
                if not assume_git_key_ready:
                    raise RuntimeError(
                        "Target repository is missing required scaffold paths "
                        f"({', '.join(missing_paths)}). Re-run interactively to confirm population, "
                        "or use --assume-git-key-ready for automated population."
                    )
                should_populate = True
                log.info(
                    "Non-interactive mode with --assume-git-key-ready: auto-populating missing scaffold paths: %s",
                    ", ".join(missing_paths),
                )
            else:
                print("\nTarget repository is not fully populated for AWX automation.")
                print("Missing paths:", ", ".join(missing_paths))
                should_populate = prompt_confirm(
                    "Populate missing repository structure from bootstrap scaffold now?",
                    default=True,
                )
            if not should_populate:
                raise RuntimeError("Repository population was declined by operator.")

        # For blank repos, start from a clean tree. For non-blank repos,
        # preserve existing files and layer scaffold on top.
        if repo_is_blank:
            for item in list(target_worktree.iterdir()):
                if item.name == ".git":
                    continue
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()

        copied = _prepare_seed_source_from_local_scaffold(home, target_worktree)
        if copied:
            log.info(
                "Seed source: local scaffold under %s (no access to existing AWX project repositories).",
                home,
            )

        if not copied:
            raise RuntimeError(
                "Could not find local scaffold seed content under ansible home."
            )

        run(["git", "add", "-A"], cwd=str(target_worktree), check=True)
        delta = run(
            ["git", "status", "--porcelain"],
            cwd=str(target_worktree),
            capture=True,
            check=True,
        ).stdout.strip()
        if not delta:
            log.info("Seed content already present in target repository; nothing to commit.")
            state.set(seeded_key, True)
            return

        committer_email = config.awx_admin_email or config.admin_email or "awx-bootstrap@localhost"
        run(["git", "config", "user.name", "AWX Bootstrap"], cwd=str(target_worktree), check=True)
        run(["git", "config", "user.email", committer_email], cwd=str(target_worktree), check=True)
        run(
            ["git", "commit", "-m", "Initial seed from current AWX repository content"],
            cwd=str(target_worktree),
            check=True,
        )
        run(
            ["git", "push", "-u", "origin", f"HEAD:{config.git_branch}"],
            cwd=str(target_worktree),
            env=git_env,
            check=True,
        )

    state.set(seeded_key, True)
    log.info("Repository scaffold population completed for %s on branch %s.", config.git_ssh_url, config.git_branch)


def awx_bootstrap(
    config: Config,
    home: str,
    state: State,
    non_interactive: bool = False,
    assume_git_key_ready: bool = False,
) -> None:
    """Full AWX bootstrap sequence via REST API v2."""
    if state.is_complete("awx_bootstrap"):
        log.info("AWX already bootstrapped (state checkpoint). Skipping.")
        return

    secrets_dir = Path(home) / "secrets"
    base_url = f"http://127.0.0.1:{config.awx_listen_port}"

    # Step 1: Wait for AWX API to be ready (timeout 600s for Django migrations)
    log.info("Waiting for AWX API /api/v2/ping/ ...")
    wait_for_http(f"{base_url}/api/v2/ping/", timeout=600)

    # Step 2: Create OAuth2 token using Basic auth
    log.info("Creating AWX OAuth2 token for admin user '%s' ...", config.awx_admin_login)
    token = awx_create_token(base_url, config.awx_admin_login, config.awx_admin_password)
    log.info("AWX API token created.")

    # Write token to secrets/.api_token (chmod 600)
    try:
        import pwd
        pw = pwd.getpwnam("ansible")
        t_uid, t_gid = pw.pw_uid, pw.pw_gid
    except KeyError:
        t_uid, t_gid = 0, 0
    write_secret_file(secrets_dir / ".api_token", token, t_uid, t_gid)
    log.info("AWX API token written to %s", secrets_dir / ".api_token")

    # Step 3: Ensure organization exists (find by name, create if absent)
    org_name = config.awx_organization_name
    log.info("Ensuring AWX organization '%s' exists ...", org_name)
    existing_org = awx_find_by_name(base_url, "/api/v2/organizations/", token, org_name)
    if existing_org:
        org_id = int(existing_org["id"])
        log.info("Organization '%s' already exists (id=%d).", org_name, org_id)
    else:
        log.info("Organization '%s' not found, creating ...", org_name)
        status, body = awx_api_call(
            "POST", base_url, "/api/v2/organizations/", token=token,
            data={"name": org_name},
        )
        if status not in (200, 201):
            raise RuntimeError(
                f"Failed to create organization '{org_name}': HTTP {status}: {body}"
            )
        org_id = int(body["id"])
        log.info("Organization '%s' created (id=%d).", org_name, org_id)
    state.set("awx_org_id", org_id)

    # Step 4: GET credential type IDs
    log.info("Fetching AWX credential type IDs ...")
    machine_type_id = awx_get_credential_type_id(base_url, token, "ssh", "Machine")
    scm_type_id = awx_get_credential_type_id(base_url, token, "scm", "Source Control")
    log.debug("Credential type IDs: Machine=%d, SCM=%d", machine_type_id, scm_type_id)

    # Step 5: Create machine credential (deploy_key)
    key_path = Path(home) / "keys" / "deploy_key"
    key_name = "deploy_key"
    log.info("Ensuring machine credential '%s' exists ...", key_name)
    existing_machine_cred = awx_find_by_name(
        base_url, "/api/v2/credentials/", token, key_name,
        params={"organization": str(org_id)},
    )
    if existing_machine_cred:
        machine_cred_id = int(existing_machine_cred["id"])
        log.info("Machine credential '%s' already exists (id=%d).", key_name, machine_cred_id)
    else:
        private_key_content = key_path.read_text()
        status, body = awx_api_call(
            "POST",
            base_url,
            "/api/v2/credentials/",
            token=token,
            data={
                "name": key_name,
                "credential_type": machine_type_id,
                "organization": org_id,
                "inputs": {"ssh_key_data": private_key_content},
            },
        )
        if status not in (200, 201):
            raise RuntimeError(f"Failed to create machine credential: HTTP {status}: {body}")
        machine_cred_id = int(body["id"])
        log.info("Machine credential '%s' created (id=%d).", key_name, machine_cred_id)

    state.set("awx_machine_cred_id", machine_cred_id)

    # Step 6: Create SCM credential (if git URL provided)
    scm_cred_id: Optional[int] = None
    if config.git_ssh_url:
        scm_name = "scm_deploy_key"
        log.info("Ensuring SCM credential '%s' exists ...", scm_name)
        existing_scm_cred = awx_find_by_name(
            base_url, "/api/v2/credentials/", token, scm_name,
            params={"organization": str(org_id)},
        )
        if existing_scm_cred:
            scm_cred_id = int(existing_scm_cred["id"])
            log.info("SCM credential '%s' already exists (id=%d).", scm_name, scm_cred_id)
        else:
            private_key_content = key_path.read_text()
            status, body = awx_api_call(
                "POST",
                base_url,
                "/api/v2/credentials/",
                token=token,
                data={
                    "name": scm_name,
                    "credential_type": scm_type_id,
                    "organization": org_id,
                    "inputs": {"ssh_key_data": private_key_content},
                },
            )
            if status not in (200, 201):
                raise RuntimeError(f"Failed to create SCM credential: HTTP {status}: {body}")
            scm_cred_id = int(body["id"])
            log.info("SCM credential '%s' created (id=%d).", scm_name, scm_cred_id)

        state.set("awx_scm_cred_id", scm_cred_id)

    # Step 7: Create project (if git URL provided)
    project_id: Optional[int] = None
    if config.git_ssh_url and scm_cred_id is not None:
        project_name = "Ansible Repo"
        expected_playbook = "playbooks/site.yml"

        log.info("Ensuring AWX project '%s' exists ...", project_name)
        existing_project = awx_find_by_name(
            base_url, "/api/v2/projects/", token, project_name,
            params={"organization": str(org_id)},
        )
        if existing_project:
            project_id = int(existing_project["id"])
            log.info("Project '%s' already exists (id=%d).", project_name, project_id)

            patch_payload: Dict[str, Any] = {}
            if str(existing_project.get("scm_url") or "") != config.git_ssh_url:
                patch_payload["scm_url"] = config.git_ssh_url
            if str(existing_project.get("scm_branch") or "") != config.git_branch:
                patch_payload["scm_branch"] = config.git_branch
            if int(existing_project.get("credential") or 0) != int(scm_cred_id):
                patch_payload["credential"] = scm_cred_id

            if patch_payload:
                log.info(
                    "Updating project '%s' to configured repository/branch/credential.",
                    project_name,
                )
                status, body = awx_api_call(
                    "PATCH",
                    base_url,
                    f"/api/v2/projects/{project_id}/",
                    token=token,
                    data=patch_payload,
                )
                if status not in (200, 202):
                    raise RuntimeError(
                        f"Failed to update project '{project_name}': HTTP {status}: {body}"
                    )

            if not awx_project_has_playbook(base_url, token, project_id, expected_playbook):
                log.info(
                    "Project '%s' is missing playbook '%s'; triggering project sync ...",
                    project_name,
                    expected_playbook,
                )
                awx_sync_project_with_recovery(
                    base_url,
                    token,
                    project_id,
                    home,
                    timeout=300,
                    trigger_update=True,
                )
        else:
            status, body = awx_api_call(
                "POST",
                base_url,
                "/api/v2/projects/",
                token=token,
                data={
                    "name": project_name,
                    "scm_type": "git",
                    "scm_url": config.git_ssh_url,
                    "scm_branch": config.git_branch,
                    "credential": scm_cred_id,
                    "organization": org_id,
                },
            )
            if status not in (200, 201):
                raise RuntimeError(f"Failed to create project: HTTP {status}: {body}")
            project_id = int(body["id"])
            log.info("Project '%s' created (id=%d). Waiting for sync ...", project_name, project_id)
            awx_sync_project_with_recovery(
                base_url,
                token,
                project_id,
                home,
                timeout=300,
                trigger_update=False,
            )

        if not awx_project_has_playbook(base_url, token, project_id, expected_playbook):
            log.warning(
                "Project '%s' (id=%d) synced successfully but does not expose playbook '%s'. "
                "Continuing bootstrap without playbook validation; verify repository/branch content.",
                project_name,
                project_id,
                expected_playbook,
            )

        state.set("awx_project_id", project_id)

    # Step 8: Create inventory
    inventory_name = "Static Inventory"
    hostname = config.fqdn.split(".")[0]
    log.info("Ensuring inventory '%s' exists ...", inventory_name)
    existing_inv = awx_find_by_name(
        base_url, "/api/v2/inventories/", token, inventory_name,
        params={"organization": str(org_id)},
    )
    if existing_inv:
        inventory_id = int(existing_inv["id"])
        log.info("Inventory '%s' already exists (id=%d).", inventory_name, inventory_id)
    else:
        status, body = awx_api_call(
            "POST",
            base_url,
            "/api/v2/inventories/",
            token=token,
            data={
                "name": inventory_name,
                "organization": org_id,
                "variables": "---\n",
            },
        )
        if status not in (200, 201):
            raise RuntimeError(f"Failed to create inventory: HTTP {status}: {body}")
        inventory_id = int(body["id"])
        log.info("Inventory '%s' created (id=%d).", inventory_name, inventory_id)

    state.set("awx_inventory_id", inventory_id)

    # Add host to inventory
    log.info("Ensuring host '%s' exists in inventory ...", hostname)
    existing_host = awx_find_by_name(
        base_url, "/api/v2/hosts/", token, hostname,
        params={"inventory": str(inventory_id)},
    )
    if existing_host:
        log.info("Host '%s' already exists (id=%d).", hostname, existing_host["id"])
    else:
        status, body = awx_api_call(
            "POST",
            base_url,
            "/api/v2/hosts/",
            token=token,
            data={
                "name": hostname,
                "inventory": inventory_id,
                "variables": f"ansible_host: {config.fqdn}\n",
            },
        )
        if status not in (200, 201):
            raise RuntimeError(f"Failed to create host: HTTP {status}: {body}")
        log.info("Host '%s' created (id=%d).", hostname, body["id"])

    # Step 9: Create job template (if project exists)
    if project_id is not None:
        jt_name = "Deploy Site"
        jt_playbook = "playbooks/site.yml"

        if not awx_project_has_playbook(base_url, token, project_id, jt_playbook):
            log.warning(
                "Skipping job template creation: project id=%d does not expose playbook '%s'.",
                project_id,
                jt_playbook,
            )
            state.set("awx_job_template_skipped", True)
            state.complete("awx_bootstrap")
            log.info("AWX bootstrap complete.")
            return

        log.info("Ensuring job template '%s' exists ...", jt_name)
        existing_jt = awx_find_by_name(
            base_url, "/api/v2/job_templates/", token, jt_name
        )
        if existing_jt:
            jt_id = int(existing_jt["id"])
            log.info("Job template '%s' already exists (id=%d).", jt_name, jt_id)
        else:
            payload = {
                "name": jt_name,
                "job_type": "run",
                "inventory": inventory_id,
                "project": project_id,
                "playbook": jt_playbook,
                "ask_credential_on_launch": False,
            }
            status, body = awx_api_call(
                "POST",
                base_url,
                "/api/v2/job_templates/",
                token=token,
                data=payload,
            )
            if status == 400 and _awx_playbook_not_found_error(body):
                log.warning(
                    "AWX reports playbook not found for project id=%d; forcing project sync and retrying job template creation once.",
                    project_id,
                )
                awx_sync_project_with_recovery(
                    base_url,
                    token,
                    project_id,
                    home,
                    timeout=300,
                    trigger_update=True,
                )
                status, body = awx_api_call(
                    "POST",
                    base_url,
                    "/api/v2/job_templates/",
                    token=token,
                    data=payload,
                )
            if status not in (200, 201):
                raise RuntimeError(f"Failed to create job template: HTTP {status}: {body}")
            jt_id = int(body["id"])
            log.info("Job template '%s' created (id=%d).", jt_name, jt_id)

            # Attach machine credential to job template
            log.info("Attaching machine credential (id=%d) to job template (id=%d) ...", machine_cred_id, jt_id)
            status, body = awx_api_call(
                "POST",
                base_url,
                f"/api/v2/job_templates/{jt_id}/credentials/",
                token=token,
                data={"id": machine_cred_id},
            )
            if status not in (200, 201, 204):
                log.warning(
                    "Credential attachment returned HTTP %d: %s (non-fatal)", status, body
                )

        state.set("awx_job_template_id", jt_id)

    state.complete("awx_bootstrap")
    log.info("AWX bootstrap complete.")


# ---------------------------------------------------------------------------
# NGINX
# ---------------------------------------------------------------------------

def install_nginx(platform_adapter: PlatformAdapter, state: State) -> None:
    """Install NGINX on the host."""
    if state.is_complete("nginx_install"):
        log.info("NGINX already installed (state checkpoint). Skipping.")
        return

    log.info("Installing NGINX ...")
    platform_adapter.pkg_install(["nginx"])
    platform_adapter.service_enable_now("nginx")
    state.complete("nginx_install")
    log.info("NGINX installed and started.")


def verify_generated_files(home: str, config: Config) -> None:
    """Ensure critical generated runtime files exist before container startup."""
    required = [
        Path(home) / "compose" / "awx" / "docker-compose.yml",
        Path(home) / "compose" / "awx" / ".env",
        Path(home) / "config" / "awx_settings.py",
        Path(home) / "config" / "awx_nginx.conf",
        Path(home) / "config" / "receptor.conf",
        Path(home) / "ansible.cfg",
        Path(home) / "playbooks" / "site.yml",
        Path(home) / "playbooks" / "awx_bootstrap.yml",
        Path(home) / "keys" / "deploy_key",
        Path(home) / "keys" / "deploy_key.pub",
        Path(home) / "secrets" / ".awx.env",
        Path(home) / "secrets" / ".db.env",
        Path(home) / "nginx" / f"{config.fqdn}.conf",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise RuntimeError(
            "Generated configuration is incomplete; missing required files: "
            + ", ".join(missing)
        )


def write_nginx_config(
    config: Config,
    home: str,
    platform_adapter: PlatformAdapter,
) -> str:
    """Write NGINX config, create symlinks, return canonical config path."""
    nginx_dir = Path(home) / "nginx"
    conf_name = f"{config.fqdn}.conf"
    canonical_path = nginx_dir / conf_name

    conf_dir = platform_adapter.nginx_conf_dir()

    if isinstance(platform_adapter, (DebianAdapter, UbuntuAdapter)):
        # sites-available / sites-enabled pattern
        sites_available = Path(conf_dir)
        sites_available.mkdir(parents=True, exist_ok=True)
        dest = sites_available / conf_name
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        dest.symlink_to(canonical_path)
        log.info("NGINX config symlinked: %s -> %s", dest, canonical_path)
        # nginx_enable_site creates the sites-enabled symlink
        platform_adapter.nginx_enable_site(str(dest))
    else:
        # RHEL: conf.d – symlink directly
        conf_d = Path(conf_dir)
        conf_d.mkdir(parents=True, exist_ok=True)
        dest = conf_d / conf_name
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        dest.symlink_to(canonical_path)
        log.info("NGINX config symlinked: %s -> %s", dest, canonical_path)

    return str(canonical_path)


def validate_reload_nginx() -> None:
    """Validate NGINX config and reload."""
    log.info("Validating NGINX configuration ...")
    run(["nginx", "-t"])
    log.info("Reloading NGINX ...")
    run(["systemctl", "reload", "nginx"])
    log.info("NGINX reloaded.")


# ---------------------------------------------------------------------------
# Certbot
# ---------------------------------------------------------------------------

def install_certbot(platform_adapter: PlatformAdapter, state: State) -> None:
    """Install Certbot on the host."""
    if state.is_complete("certbot_install"):
        log.info("Certbot already installed (state checkpoint). Skipping.")
        return

    log.info("Installing Certbot ...")
    platform_adapter.certbot_install()
    state.complete("certbot_install")
    log.info("Certbot installed.")


def install_dns_plugin(
    source: str,
    name: str,
    install_dir: str,
) -> str:
    """Install a Certbot DNS plugin from pip package name or git URL. Return installed name."""
    log.info("Installing DNS plugin '%s' from '%s' ...", name, source)

    if source.startswith("git+") or source.startswith("https://") or source.endswith(".git"):
        pip_source = source if source.startswith("git+") else f"git+{source}"
        run(["pip3", "install", "--quiet", pip_source])
    else:
        run(["pip3", "install", "--quiet", source])

    log.info("DNS plugin installed: %s", source)
    return name


def detect_plugin_credentials(name: str, plugin_dir: str) -> List[str]:
    """Return list of credential field names for the given DNS plugin."""
    info = KNOWN_DNS_PLUGIN_CREDENTIALS.get(name)
    if info:
        return list(info.get("fields", {}).keys())

    # Try to scan for ini files in plugin_dir
    fields: List[str] = []
    plugin_path = Path(plugin_dir)
    if plugin_path.exists():
        for ini_file in plugin_path.rglob("*.ini"):
            content = ini_file.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("dns_") and "=" in line:
                    key = line.split("=")[0].strip()
                    if key not in fields:
                        fields.append(key)
    return fields


def collect_and_write_credentials(
    fields: Dict[str, str],
    plugin_name: str,
    secrets_dir: str,
    uid: int,
    gid: int,
) -> str:
    """Prompt user for DNS credential values and write to credentials file."""
    certbot_dir = Path(secrets_dir) / "certbot"
    certbot_dir.mkdir(parents=True, exist_ok=True)
    certbot_dir.chmod(0o700)
    os.chown(certbot_dir, uid, gid)

    creds_path = certbot_dir / f"{plugin_name}.ini"

    lines = [f"# Certbot DNS plugin credentials for {plugin_name}\n"]
    print(f"\nEnter credentials for DNS plugin '{plugin_name}':")
    for field_key, field_label in fields.items():
        if any(kw in field_key.lower() for kw in ("secret", "key", "token", "password")):
            val = prompt_password(f"  {field_label}")
        else:
            val = prompt(f"  {field_label}")
        lines.append(f"{field_key} = {val}\n")

    write_secret_file(creds_path, "".join(lines), uid, gid)
    log.info("Credentials written to %s", creds_path)
    return str(creds_path)


def run_certbot(
    config: Config,
    home: str,
    credentials_path: Optional[str] = None,
) -> None:
    """Run certbot to obtain a certificate."""
    cmd: List[str] = [
        "certbot",
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email", config.certbot_email,
        "--domains", config.fqdn,
    ]

    if config.ssl_mode == "certbot_http":
        cmd += ["--nginx"]
    elif config.ssl_mode == "certbot_dns":
        plugin_info = KNOWN_DNS_PLUGIN_CREDENTIALS.get(config.certbot_dns_provider, {})
        plugin_name = config.certbot_dns_provider or "custom"
        authenticator = f"--dns-{plugin_name}"
        cmd += [authenticator]

        creds_arg = plugin_info.get("credentials_arg")
        if creds_arg and credentials_path:
            cmd += [creds_arg, credentials_path]
        elif credentials_path:
            cmd += [f"--dns-{plugin_name}-credentials", credentials_path]

        if plugin_name == "cloudflare":
            cmd += ["--dns-cloudflare-propagation-seconds", "60"]

    log.info("Running certbot to obtain certificate for %s ...", config.fqdn)
    run(cmd)
    log.info("Certificate obtained for %s.", config.fqdn)


def setup_certbot_renewal(platform_adapter: PlatformAdapter, home: str) -> None:
    """Set up automatic certificate renewal."""
    if isinstance(platform_adapter, RHEL9Adapter):
        timer_content = """\
[Unit]
Description=Certbot Renewal Timer
After=network-online.target

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
"""
        service_content = """\
[Unit]
Description=Certbot Renewal Service
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --post-hook "systemctl reload nginx"
"""
        timer_path = Path("/etc/systemd/system/certbot-renew.timer")
        service_path = Path("/etc/systemd/system/certbot-renew.service")
        timer_path.write_text(timer_content)
        service_path.write_text(service_content)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", "certbot-renew.timer"])
        log.info("Certbot renewal timer enabled (systemd).")
    else:
        try:
            run(["systemctl", "enable", "--now", "certbot.timer"])
            log.info("Certbot renewal timer enabled.")
        except subprocess.CalledProcessError:
            log.info("certbot.timer not found – renewal via snap auto-renewal or cron.")
            cron_line = "0 3 * * * root /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'\n"
            cron_path = Path("/etc/cron.d/certbot-renew")
            if not cron_path.exists():
                cron_path.write_text(cron_line)
                log.info("Certbot renewal cron job written to %s", cron_path)


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class TestResult:
    name: str
    passed: bool
    warning: bool = False
    message: str = ""


def _test_docker_running(compose_cmd: List[str], compose_file: str) -> TestResult:
    """Check that the 'awx' container is running."""
    cwd = str(Path(compose_file).parent)
    try:
        out = run_capture(
            compose_cmd + ["-f", compose_file, "ps", "--status", "running"]
        )
        if "awx" in out:
            return TestResult("docker_running", True, message="AWX container is running.")
        return TestResult("docker_running", False, message=f"AWX container not found in: {out}")
    except Exception as exc:
        return TestResult("docker_running", False, message=str(exc))


def _test_containers_healthy(compose_cmd: List[str], compose_file: str) -> TestResult:
    """Parse compose ps JSON to verify all containers are healthy."""
    cwd = str(Path(compose_file).parent)
    try:
        result = run(
            compose_cmd + ["-f", compose_file, "ps", "--format", "json"],
            cwd=cwd,
            capture=True,
            check=False,
        )
        data = result.stdout.strip()
        if not data:
            return TestResult("containers_healthy", False, message="No container data returned.")
        unhealthy = []
        try:
            containers = json.loads(data)
            if not isinstance(containers, list):
                containers = [containers]
        except json.JSONDecodeError:
            containers = []
            for line in data.splitlines():
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        for c in containers:
            health = c.get("Health", c.get("health", ""))
            name = c.get("Name", c.get("name", "?"))
            cstate = c.get("State", c.get("state", ""))
            if cstate == "running" and health not in ("healthy", ""):
                unhealthy.append(f"{name}:{health}")

        if unhealthy:
            return TestResult(
                "containers_healthy",
                False,
                message=f"Unhealthy containers: {', '.join(unhealthy)}",
            )
        return TestResult("containers_healthy", True, message="All containers healthy.")
    except Exception as exc:
        return TestResult("containers_healthy", False, message=str(exc))


def _test_awx_ping(config: Config) -> TestResult:
    """GET /api/v2/ping/ → 200 confirms AWX is fully up."""
    url = f"http://127.0.0.1:{config.awx_listen_port}/api/v2/ping/"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                return TestResult("awx_ping", True, message=f"AWX API ping OK ({url})")
        return TestResult("awx_ping", False, message=f"AWX ping returned HTTP {resp.status}")
    except Exception as exc:
        return TestResult("awx_ping", False, message=str(exc))


def _test_awx_auth(config: Config, home: str) -> TestResult:
    """GET /api/v2/me/ with stored token → 200 confirms auth works."""
    api_token_path = Path(home) / "secrets" / ".api_token"
    if not api_token_path.exists():
        return TestResult("awx_auth", False, message="API token file not found.")
    try:
        token = api_token_path.read_text().strip()
        base_url = f"http://127.0.0.1:{config.awx_listen_port}"
        status, body = awx_api_call("GET", base_url, "/api/v2/me/", token=token)
        if status == 200:
            return TestResult("awx_auth", True, message="AWX API token authentication OK.")
        return TestResult("awx_auth", False, message=f"Auth check returned HTTP {status}: {body}")
    except Exception as exc:
        return TestResult("awx_auth", False, message=str(exc))


def _test_nginx_http(config: Config) -> TestResult:
    url = f"http://{config.fqdn}/"
    try:
        req = urllib.request.Request(url)
        req.add_header("Host", config.fqdn)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return TestResult("nginx_http", True, message=f"NGINX HTTP OK (status={resp.status})")
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 200):
            return TestResult("nginx_http", True, message=f"NGINX HTTP OK (redirect={exc.code})")
        return TestResult("nginx_http", False, message=f"NGINX HTTP error: {exc.code}")
    except Exception as exc:
        return TestResult("nginx_http", False, warning=True, message=f"NGINX HTTP: {exc} (DNS may not resolve)")


def _test_nginx_https(config: Config) -> TestResult:
    if config.ssl_mode == "none":
        return TestResult("nginx_https", True, warning=True, message="SSL not configured – test skipped.")
    url = f"https://{config.fqdn}/"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return TestResult("nginx_https", True, message=f"NGINX HTTPS OK (status={resp.status})")
    except urllib.error.HTTPError as exc:
        if exc.code == 200:
            return TestResult("nginx_https", True)
        return TestResult("nginx_https", False, message=f"NGINX HTTPS error: {exc.code}")
    except Exception as exc:
        return TestResult("nginx_https", False, warning=True, message=f"NGINX HTTPS: {exc}")


def _test_ssl_expiry(config: Config) -> TestResult:
    if config.ssl_mode == "none":
        return TestResult("ssl_expiry", True, warning=True, message="SSL not configured – skipped.")
    import ssl
    import datetime
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=config.fqdn
        ) as s:
            s.settimeout(10)
            s.connect((config.fqdn, config.nginx_https_port))
            cert = s.getpeercert()
            not_after = cert.get("notAfter", "")
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 14:
                return TestResult(
                    "ssl_expiry", False,
                    message=f"Certificate expires in {days_left} days!",
                )
            return TestResult(
                "ssl_expiry", True,
                message=f"Certificate valid, expires in {days_left} days ({expiry.date()}).",
            )
    except Exception as exc:
        return TestResult("ssl_expiry", False, warning=True, message=str(exc))


def _test_postgres_ready(config: Config, compose_cmd: List[str], compose_file: str) -> TestResult:
    """Check PostgreSQL is ready inside the container or externally."""
    if config.db_mode == "external":
        try:
            with socket.create_connection((config.db_host, config.db_port), timeout=5):
                return TestResult(
                    "postgres_ready", True,
                    message=f"External PostgreSQL reachable at {config.db_host}:{config.db_port}",
                )
        except Exception as exc:
            return TestResult("postgres_ready", False, message=str(exc))

    cwd = str(Path(compose_file).parent)
    last_error = ""
    for service_name in ("postgres", "awx_postgres"):
        try:
            result = run(
                compose_cmd
                + [
                    "-f",
                    compose_file,
                    "exec",
                    "-T",
                    service_name,
                    "pg_isready",
                    "-U",
                    config.db_user,
                ],
                cwd=cwd,
                capture=True,
                check=False,
            )
            if result.returncode == 0:
                return TestResult("postgres_ready", True, message="PostgreSQL is ready.")
            last_error = (result.stdout or "") + (result.stderr or "")
        except Exception as exc:
            last_error = str(exc)

    return TestResult("postgres_ready", False, message=last_error)


def _test_playbook_syntax(config: Config, home: str) -> TestResult:
    """Run ansible-playbook --syntax-check on site.yml (if ansible-playbook is on PATH)."""
    if not shutil.which("ansible-playbook"):
        return TestResult(
            "playbook_syntax", True, warning=True,
            message="ansible-playbook not on host PATH – test skipped (AWX bundles its own).",
        )
    playbook = str(Path(home) / "playbooks" / "site.yml")
    try:
        run(
            ["ansible-playbook", "--syntax-check", playbook],
            env={"ANSIBLE_CONFIG": str(Path(home) / "ansible.cfg")},
            capture=True,
        )
        return TestResult("playbook_syntax", True, message="site.yml syntax OK.")
    except subprocess.CalledProcessError as exc:
        return TestResult("playbook_syntax", False, message=exc.stderr or str(exc))
    except Exception as exc:
        return TestResult("playbook_syntax", False, message=str(exc))


def run_smoke_tests(
    config: Config,
    home: str,
    compose_cmd: List[str],
    compose_file: str,
) -> List[TestResult]:
    """Run all smoke tests and return results."""
    log.info("Running smoke tests ...")
    results: List[TestResult] = []

    results.append(_test_docker_running(compose_cmd, compose_file))
    results.append(_test_containers_healthy(compose_cmd, compose_file))
    results.append(_test_awx_ping(config))
    results.append(_test_awx_auth(config, home))
    results.append(_test_nginx_http(config))
    if config.ssl_mode != "none":
        results.append(_test_nginx_https(config))
        results.append(_test_ssl_expiry(config))
    results.append(_test_postgres_ready(config, compose_cmd, compose_file))
    results.append(_test_playbook_syntax(config, home))

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed and not r.warning)
    warned = sum(1 for r in results if not r.passed and r.warning)

    log.info(
        "Smoke tests: %d passed, %d failed, %d warnings.",
        passed,
        failed,
        warned,
    )
    return results


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(
    config: Config,
    home: str,
    test_results: List[TestResult],
) -> None:
    """Print final bootstrap summary."""
    pub_key_path = Path(home) / "keys" / "deploy_key.pub"
    pub_key = ""
    if pub_key_path.exists():
        pub_key = pub_key_path.read_text().strip()

    proto = "https" if config.ssl_mode != "none" else "http"
    awx_url = f"{proto}://{config.fqdn}"

    width = 70
    sep = "=" * width

    print(f"\n{sep}")
    print("  BOOTSTRAP COMPLETE – Ansible AWX Platform")
    print(sep)
    print(f"  AWX URL:           {awx_url}")
    print(f"  AWX organization:  {config.awx_organization_name}")
    print(f"  AWX admin login:   {config.awx_admin_login}")
    print(f"  AWX admin email:   {config.awx_admin_email}")
    print(f"  AWX image tag:     {config.awx_image_tag}")
    print(f"  FQDN:              {config.fqdn}")
    print(f"  Ansible home:      {home}")
    print(f"  Platform:          {config.platform}")
    print(f"  FIPS mode:         {'Yes' if config.fips_enabled else 'No'}")
    print(f"  SELinux:           {config.selinux_mode}")
    print(f"  SSL mode:          {config.ssl_mode}")
    print(f"  DB mode:           {config.db_mode}")
    print()
    print("  Deploy Public Key (add to your Git provider):")
    print(f"  {pub_key}")
    print()

    api_token_path = Path(home) / "secrets" / ".api_token"
    if api_token_path.exists():
        print(f"  API token stored at: {api_token_path}")
    print()

    print("  Smoke Test Results:")
    for r in test_results:
        if r.passed:
            status = "PASS"
        elif r.warning:
            status = "WARN"
        else:
            status = "FAIL"
        msg = f" – {r.message}" if r.message else ""
        print(f"    [{status:4s}] {r.name}{msg}")

    print()
    print("  Next Steps:")
    print("  1. Add the deploy public key to your Git repository's deploy keys.")
    print(f"  2. Log in to the AWX UI at {awx_url}")
    print(f"     Username: {config.awx_admin_login}")
    print("     Password: (as configured during setup)")
    print("  3. Navigate to Templates and verify 'Deploy Site' job template.")
    print("  4. Run a test job from the AWX UI or via the awx CLI.")
    print("  5. Use 'awx.awx' collection tasks for further automation.")
    if config.ssl_mode == "none":
        print("  6. Consider enabling HTTPS (certbot or provided certificates).")
    print()
    print("  Key Files:")
    print(f"    Compose dir:   {home}/compose/awx/")
    print(f"    Secrets dir:   {home}/secrets/   (chmod 700)")
    print(f"    Deploy key:    {home}/keys/deploy_key")
    print(f"    Bootstrap log: {home}/logs/bootstrap.log")
    print(f"    State file:    {home}/config/bootstrap_state.json")
    print(sep)
    print()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Bootstrap an Ansible AWX automation platform.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--home",
        default=DEFAULT_ANSIBLE_HOME,
        help=f"Ansible user home directory (default: {DEFAULT_ANSIBLE_HOME})",
    )
    parser.add_argument(
        "--force-secrets",
        action="store_true",
        help="Regenerate secrets even if they already exist.",
    )
    parser.add_argument(
        "--force-pull",
        action="store_true",
        help="Force re-pull of the AWX image even if already pulled.",
    )
    parser.add_argument(
        "--fresh-reinstall",
        action="store_true",
        help=(
            "Destroy all containers, data, and generated config, then reinstall from scratch. "
            "Prompts for confirmation unless --non-interactive is also set."
        ),
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail if any required parameter is missing (for CI use).",
    )
    parser.add_argument(
        "--reconfigure",
        action="store_true",
        help="Re-run the interactive questionnaire even if answers are already stored.",
    )
    parser.add_argument(
        "--assume-git-key-ready",
        action="store_true",
        help=(
            "Skip interactive confirmation that the deploy public key has read/write access "
            "to the target Git repository (for automation runs)."
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Fresh reinstall
# ---------------------------------------------------------------------------

def do_fresh_reinstall(home: str, non_interactive: bool = False) -> None:
    """Stop containers and wipe all generated state/data for a clean reinstall."""
    h = Path(home)

    if not non_interactive:
        print(f"\nWARNING: --fresh-reinstall will destroy ALL data under {home}")
        print("This includes the PostgreSQL database, secrets, SSH keys, and all")
        print("generated configuration files. This action cannot be undone.")
        answer = input("\nType 'yes' to confirm: ").strip()
        if answer.lower() != "yes":
            print("Aborted.")
            sys.exit(0)

    # Stop and remove containers (ignore errors if compose file doesn't exist yet)
    compose_file = h / "compose" / "awx" / "docker-compose.yml"
    if compose_file.exists():
        print("Stopping and removing Docker containers...")
        compose_cmd = detect_compose_command()
        subprocess.run(
            compose_cmd + ["-f", str(compose_file), "down", "--volumes", "--remove-orphans"],
            check=False,
        )

    # Wipe all directories created by this script under home
    generated_dirs = [
        "compose",
        "data",
        "secrets",
        "config",
        "keys",
        "logs",
        "nginx",
        "inventories",
        "playbooks",
        "roles",
    ]
    for name in generated_dirs:
        target = h / name
        if target.exists():
            print(f"Removing {target} ...")
            shutil.rmtree(target)

    print("Wipe complete. Proceeding with fresh installation.\n")


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def main() -> None:
    """Main bootstrap orchestration."""
    args = parse_args()

    # Immediate root check before anything else
    check_root()
    check_python_version()

    if args.fresh_reinstall:
        do_fresh_reinstall(args.home, non_interactive=args.non_interactive)

    # Detect system properties
    platform_id, platform_adapter = detect_platform()
    fips = detect_fips()
    selinux_mode = detect_selinux()

    # Create minimal directories for logging before full structure is ready
    home = args.home
    logs_dir = Path(home) / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = str(logs_dir / "bootstrap.log")
    setup_logging(log_file)

    log.info(
        "bootstrap_awx.py v%s starting – platform=%s fips=%s selinux=%s",
        SCRIPT_VERSION,
        platform_id,
        fips,
        selinux_mode,
    )

    # Load state
    state_path = Path(home) / "config" / "bootstrap_state.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state = State(state_path)

    # ── Phase: Collect parameters ────────────────────────────────
    answers_file = _answers_path()
    answers = _load_answers(answers_file)

    if state.is_complete("params_collected") and not args.reconfigure:
        # Skip the questionnaire — use the config stored from the previous run.
        # Merge: answers file wins over state so edits to .answers.json are picked up.
        stored_cfg = state.get("config", {})
        merged = {
            **{k: v for k, v in stored_cfg.items() if k not in _ANSWERS_EXCLUDE},
            **answers,
        }
        # Rebuild Config from persisted values; fall back to dataclass defaults for
        # any field that is new since the answers were written.
        field_names = {f.name for f in dataclasses.fields(Config)}
        config = Config(**{k: v for k, v in merged.items() if k in field_names})
        # Runtime-detected fields must always be refreshed from the environment.
        config.fips_enabled = fips
        config.selinux_mode = selinux_mode
        config.platform = platform_id
        config.ansible_home = home
        # Restore password from state (never stored in answers file).
        config.awx_admin_password = stored_cfg.get("awx_admin_password", "")
        log.info(
            "Using stored answers (run with --reconfigure to change).",
        )
    else:
        # First run or operator requested reconfiguration: run questionnaire.
        if state.is_complete("params_collected"):
            # --reconfigure: pre-load previous answers as defaults.
            stored_cfg = state.get("config", {})
            answers = {
                **{k: v for k, v in stored_cfg.items() if k not in _ANSWERS_EXCLUDE},
                **answers,
            }
            log.info("Re-running questionnaire with previous answers as defaults.")
        elif answers:
            log.info(
                "Loaded %d answer(s) from %s.", len(answers), answers_file
            )

        existing_password = state.get("config", {}).get("awx_admin_password", "")
        config = collect_params(
            platform_id, state, args,
            answers=answers,
            existing_password=existing_password,
        )
        config.fips_enabled = fips
        config.selinux_mode = selinux_mode
        config.platform = platform_id

    # Always persist — ensures .answers.json is created even when the
    # questionnaire was skipped (e.g. first run after the feature was added
    # to an existing install that already had params_collected in state).
    state.set("config", dataclasses.asdict(config))
    state.complete("params_collected")
    _save_answers(answers_file, config)
    log.info("Answers saved to %s.", answers_file)

    selinux_enforcing = selinux_mode == "enforcing"

    # ── Phase: Preflight ─────────────────────────────────────────
    if not state.is_complete("preflight"):
        run_preflight(config)
        state.complete("preflight")
    else:
        log.info("Preflight already passed (state checkpoint).")

    # ── Phase: Install Docker ────────────────────────────────────
    if not state.is_complete("docker_install"):
        install_docker(platform_adapter, state)
    else:
        log.info("Docker already installed (state checkpoint).")

    # ── Phase: System user ───────────────────────────────────────
    if not state.is_complete("system_user"):
        uid, gid = ensure_ansible_user(home)
        state.set("uid", uid)
        state.set("gid", gid)
        state.complete("system_user")
    else:
        uid = state.get("uid", 0)
        gid = state.get("gid", 0)
        log.info("System user already configured (uid=%d).", uid)

    # ── Phase: Directory structure ───────────────────────────────
    if not state.is_complete("directory_structure"):
        create_directory_structure(home, uid, gid)
        state.complete("directory_structure")
    else:
        log.info("Directory structure already created (state checkpoint).")

    # ── Phase: Secrets ───────────────────────────────────────────
    if not state.is_complete("secrets") or args.force_secrets:
        external_db_pass = ""
        if config.db_mode == "external":
            print("\nEnter the external PostgreSQL password:")
            external_db_pass = prompt_password(f"Password for {config.db_user}@{config.db_host}")
        generate_and_write_secrets(config, state, home, uid, gid, external_db_pass, force=args.force_secrets)
        state.complete("secrets")
    else:
        log.info("Secrets already generated (state checkpoint).")

    # ── Phase: SSH deploy key ────────────────────────────────────
    deploy_key_path = Path(home) / "keys" / "deploy_key"
    if not state.is_complete("deploy_key"):
        generate_deploy_key(
            deploy_key_path,
            comment=f"ansible-deploy@{config.fqdn}",
            fips=fips,
        )
        os.chown(deploy_key_path, uid, gid)
        pub = deploy_key_path.with_suffix(".pub")
        if pub.exists():
            os.chown(pub, uid, gid)
        state.complete("deploy_key")
    else:
        log.info("Deploy key already generated (state checkpoint).")

    # ── Phase: Write files ───────────────────────────────────────
    # Always regenerate – idempotent and needed to pick up bootstrap updates.
    write_all_files(config, home, uid, gid, selinux_enforcing)
    ensure_runtime_permissions(home, uid, gid)
    verify_generated_files(home, config)

    # ── Phase: Optional repository population ────────────────────
    # This must run even if AWX API bootstrap was completed earlier, because
    # operators may update git_ssh_url/branch later and expect the check+prompt.
    if config.git_ssh_url:
        seed_blank_repo_from_current_awx(
            config,
            home,
            state,
            non_interactive=args.non_interactive,
            assume_git_key_ready=args.assume_git_key_ready,
        )

    # ── Phase: Install NGINX ─────────────────────────────────────
    install_nginx(platform_adapter, state)

    # ── Phase: Configure firewall ────────────────────────────────
    if not state.is_complete("firewall"):
        configure_firewall(platform_adapter, config)
        state.complete("firewall")
    else:
        log.info("Firewall already configured (state checkpoint).")

    # ── Phase: Certbot ───────────────────────────────────────────
    credentials_path: Optional[str] = None
    if config.ssl_mode in ("certbot_http", "certbot_dns"):
        install_certbot(platform_adapter, state)

        if config.ssl_mode == "certbot_dns":
            if not state.is_complete("certbot_dns_plugin"):
                plugin_source = (
                    KNOWN_DNS_PLUGIN_CREDENTIALS.get(config.certbot_dns_provider, {}).get("package")
                    or config.certbot_dns_plugin_source
                )
                plugin_name = config.certbot_dns_provider or "custom"
                install_dns_plugin(plugin_source, plugin_name, home)
                state.complete("certbot_dns_plugin")

            if not state.is_complete("certbot_credentials"):
                plugin_info = KNOWN_DNS_PLUGIN_CREDENTIALS.get(config.certbot_dns_provider, {})
                fields = plugin_info.get("fields", {})
                if fields:
                    credentials_path = collect_and_write_credentials(
                        fields,
                        config.certbot_dns_provider,
                        str(Path(home) / "secrets"),
                        uid,
                        gid,
                    )
                    state.set("certbot_credentials_path", credentials_path)
                    state.complete("certbot_credentials")
                else:
                    # Provider uses ambient credentials (e.g. route53 via IAM/env vars).
                    # No credential file needed; mark phase complete to avoid retrying.
                    state.complete("certbot_credentials")
            else:
                credentials_path = state.get("certbot_credentials_path")

        if not state.is_complete("certbot_obtain"):
            # For HTTP-01, NGINX must be running first; write a temporary HTTP config
            if config.ssl_mode == "certbot_http":
                temp_ssl_mode = config.ssl_mode
                config.ssl_mode = "none"
                http_conf = gen_nginx_config(config)
                config.ssl_mode = temp_ssl_mode
                nginx_canon = Path(home) / "nginx" / f"{config.fqdn}.conf"
                nginx_canon.write_text(http_conf)
                write_nginx_config(config, home, platform_adapter)
                validate_reload_nginx()

            run_certbot(config, home, credentials_path)
            setup_certbot_renewal(platform_adapter, home)
            state.complete("certbot_obtain")
        else:
            log.info("Certbot certificate already obtained (state checkpoint).")

    # ── Phase: Write NGINX config (final, with SSL if applicable) ─
    if not state.is_complete("nginx_config"):
        nginx_canon = Path(home) / "nginx" / f"{config.fqdn}.conf"
        nginx_canon.write_text(gen_nginx_config(config))
        write_nginx_config(config, home, platform_adapter)
        validate_reload_nginx()
        state.complete("nginx_config")
    else:
        log.info("NGINX config already written (state checkpoint).")

    # ── Phase: Pull AWX image ────────────────────────────────────
    compose_file = str(Path(home) / "compose" / "awx" / "docker-compose.yml")
    compose_cmd = detect_compose_command()

    recovery_rerun = state.is_complete("containers_started") and not state.is_complete("awx_bootstrap")
    if recovery_rerun:
        log.warning(
            "Previous run did not complete AWX bootstrap; forcing container re-creation "
            "to recover from partial runtime state."
        )
        run(
            compose_cmd + ["-f", compose_file, "down"],
            cwd=str(Path(compose_file).parent),
            check=False,
        )

    pull_image(config, compose_cmd, compose_file, state, force=args.force_pull)

    # ── Phase: Start containers ──────────────────────────────────
    start_containers(compose_cmd, compose_file, state, home, config)

    # ── Phase: Bootstrap AWX API ─────────────────────────────────
    awx_bootstrap(
        config,
        home,
        state,
        non_interactive=args.non_interactive,
        assume_git_key_ready=args.assume_git_key_ready,
    )

    # ── Phase: Final NGINX reload ────────────────────────────────
    validate_reload_nginx()

    # ── Phase: Smoke tests ───────────────────────────────────────
    test_results = run_smoke_tests(config, home, compose_cmd, compose_file)

    # ── Print summary ─────────────────────────────────────────────
    print_summary(config, home, test_results)

    # Exit with error if any non-warning tests failed
    failures = [r for r in test_results if not r.passed and not r.warning]
    if failures:
        log.error(
            "Bootstrap completed with %d test failure(s).",
            len(failures),
        )
        sys.exit(1)

    log.info("Bootstrap completed successfully.")


if __name__ == "__main__":
    main()
