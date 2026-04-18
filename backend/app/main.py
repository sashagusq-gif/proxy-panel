import csv
import io
import json
import os
import shutil
import string
import tempfile
import threading
import time
import re
import hmac
import hashlib
import base64
import secrets
import socket
import sqlite3
import urllib.request
from urllib.parse import quote
import ipaddress
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import Boolean, DateTime, Integer, String, create_engine, delete, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.vless_singbox import build_singbox_config, parse_vless_url, singbox_config_direct_only


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:////data/panel.db")
PROXY_CONFIG_PATH = Path(os.environ.get("PROXY_CONFIG_PATH", "/opt/proxy/conf/3proxy.cfg"))
PROXY_LOG_PATH = Path(os.environ.get("PROXY_LOG_PATH", "/opt/proxy/logs/traffic.log"))
SINGBOX_CONFIG_PATH = Path(os.environ.get("SINGBOX_CONFIG_PATH", "/opt/sing-box/config.json"))
SINGBOX_SOCKS_HOST = os.environ.get("SINGBOX_SOCKS_HOST", "sing-box")
SINGBOX_SOCKS_PORT = int(os.environ.get("SINGBOX_SOCKS_PORT", "1080"))
MTPROTO_CONFIG_PATH = Path(os.environ.get("MTPROTO_CONFIG_PATH", "/opt/mtproto/config.toml"))
BACKUP_DIR = Path("/data/backups")
PANEL_SECRET_KEY = os.environ.get("PANEL_SECRET_KEY", "change-me-in-production")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
PROXY_PUBLIC_HOST = os.environ.get("PROXY_PUBLIC_HOST", "auto")
MTPROTO_PUBLIC_HOST = os.environ.get("MTPROTO_PUBLIC_HOST", "").strip()
PROXY_PUBLIC_SOCKS_PORT = int(os.environ.get("PROXY_PUBLIC_SOCKS_PORT", "11080"))
PROXY_PUBLIC_HTTP_PORT = int(os.environ.get("PROXY_PUBLIC_HTTP_PORT", "13128"))
PROXY_LOGDUMP_BYTES = int(os.environ.get("PROXY_LOGDUMP_BYTES", "65536"))
TRAFFIC_POLL_INTERVAL_SECONDS = float(os.environ.get("TRAFFIC_POLL_INTERVAL_SECONDS", "2.0"))
MTPROTO_INTERNAL_PORT = int(os.environ.get("MTPROTO_INTERNAL_PORT", "3443"))
MTPROTO_PUBLIC_PORT = int(os.environ.get("MTPROTO_PUBLIC_PORT", "2053"))
MTPROTO_FAKE_TLS_DOMAIN = os.environ.get("MTPROTO_FAKE_TLS_DOMAIN", "yandex.ru")
MTPROTO_SECRET_MODE = os.environ.get("MTPROTO_SECRET_MODE", "faketls").strip().lower()
MTPROTO_STATS_URL = os.environ.get("MTPROTO_STATS_URL", "http://mtproto:9090/stats")
TRAFFIC_SAMPLING_INTERVAL_SECONDS = int(os.environ.get("TRAFFIC_SAMPLING_INTERVAL_SECONDS", "30"))
ACCESS_RESYNC_INTERVAL_SECONDS = float(os.environ.get("ACCESS_RESYNC_INTERVAL_SECONDS", "30"))
VLESS_CHAIN_PROBE_TIMEOUT = float(os.environ.get("VLESS_CHAIN_PROBE_TIMEOUT", "4"))
VLESS_CHAIN_PROBE_HOST = os.environ.get("VLESS_CHAIN_PROBE_HOST", "1.1.1.1").strip()
VLESS_CHAIN_PROBE_PORT = int(os.environ.get("VLESS_CHAIN_PROBE_PORT", "443"))
DOCKER_SOCKET_PATH = os.environ.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
AUTO_RESTART_VLESS_SERVICES = (
    os.environ.get("AUTO_RESTART_VLESS_SERVICES", "true").strip().lower() in ("1", "true", "yes", "on")
)
VLESS_RESTART_SERVICES = tuple(
    s.strip() for s in os.environ.get("VLESS_RESTART_SERVICES", "sing-box,proxy,mtproto").split(",") if s.strip()
)
PRUNE_TRAFFIC_EVENTS_MAX_ROWS = int(os.environ.get("PRUNE_TRAFFIC_EVENTS_MAX_ROWS", "500000"))
PRUNE_TRAFFIC_EVENTS_CHUNK = int(os.environ.get("PRUNE_TRAFFIC_EVENTS_CHUNK", "100000"))
# Семплы для графиков: API смотрит максимум на 24 ч; старше — мёртвый вес. 0 = не удалять.
TRAFFIC_SAMPLES_RETENTION_HOURS = int(os.environ.get("TRAFFIC_SAMPLES_RETENTION_HOURS", "48"))
TRAFFIC_SAMPLES_PRUNE_CHUNK = int(os.environ.get("TRAFFIC_SAMPLES_PRUNE_CHUNK", "10000"))
TRAFFIC_SAMPLES_PRUNE_MAX_BATCHES = int(os.environ.get("TRAFFIC_SAMPLES_PRUNE_MAX_BATCHES", "50"))
SESSION_COOKIE_NAME = "panel_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
MAX_IMPORT_ROWS = 500

IMPORT_HEADER_ALIASES: dict[str, tuple[str, ...]] = {
    "username": ("username", "логин", "user", "login"),
    "password": ("password", "пароль", "pass"),
    "allow_http": ("allow_http", "http"),
    "allow_socks5": ("allow_socks5", "socks5", "socks"),
    "allow_mtproto": ("allow_mtproto", "mtproto"),
    "expires_at": ("expires_at", "expires", "действует_до", "действуетдо"),
    "traffic_limit_gb": ("traffic_limit_gb", "limit_gb", "лимит_gb", "лимитгб", "лимит"),
}

IMPORT_TEMPLATE_CSV = """\ufeffusername;password;allow_http;allow_socks5;allow_mtproto;expires_at;traffic_limit_gb
import_example1;;да;да;нет;2030-12-31T23:59:59+00:00;10
import_example2;;да;да;нет;;
"""

_public_ip_cache: str | None = None


class Base(DeclarativeBase):
    pass


class ProxyUser(Base):
    __tablename__ = "proxy_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(128))
    allow_http: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_socks5: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_mtproto: Mapped[bool] = mapped_column(Boolean, default=False)
    mtproto_secret: Mapped[str | None] = mapped_column(String(256), nullable=True)
    traffic_in_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_out_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_bytes: Mapped[int] = mapped_column(Integer, default=0)
    requests_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    traffic_limit_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)


class PanelSettings(Base):
    __tablename__ = "panel_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    vless_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    vless_link: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    # После смены ссылки sing-box нужно перезапустить — иначе процесс держит старый JSON (часто direct), а прога SOCKS всё равно ОК.
    vless_singbox_restart_pending: Mapped[bool] = mapped_column(Boolean, default=False)


class TrafficState(Base):
    __tablename__ = "traffic_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    file_offset: Mapped[int] = mapped_column(Integer, default=0)
    last_sample_ts: Mapped[int] = mapped_column(Integer, default=0)


class MTProtoUserState(Base):
    __tablename__ = "mtproto_user_state"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_in_bytes: Mapped[int] = mapped_column(Integer, default=0)
    last_out_bytes: Mapped[int] = mapped_column(Integer, default=0)
    last_connections: Mapped[int] = mapped_column(Integer, default=0)


class TrafficSample(Base):
    __tablename__ = "traffic_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    traffic_in_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_out_bytes: Mapped[int] = mapped_column(Integer, default=0)
    traffic_bytes: Mapped[int] = mapped_column(Integer, default=0)


class TrafficEvent(Base):
    """Сырые записи из лога 3proxy (хранятся в БД вместо опоры только на файл)."""
    __tablename__ = "traffic_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)
    logged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

templates = Jinja2Templates(directory="/app/templates")


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str | None = Field(default=None, max_length=128)
    allow_http: bool = True
    allow_socks5: bool = True
    allow_mtproto: bool = False
    expires_at: datetime | None = None
    traffic_limit_bytes: int | None = Field(default=None, ge=0)

    @field_validator("username")
    @classmethod
    def username_clean(cls, value: str) -> str:
        value = value.strip()
        if ":" in value or "|" in value or " " in value:
            raise ValueError("username must not contain spaces, ':' or '|'")
        return value

    @field_validator("password")
    @classmethod
    def password_clean(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if ":" in value or "|" in value:
            raise ValueError("password must not contain ':' or '|'")
        if len(value) < 3:
            raise ValueError("password must be at least 3 characters when set")
        return value

    @field_validator("allow_socks5", "allow_http")
    @classmethod
    def protocol_guard(cls, value: bool) -> bool:
        return value


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=3, max_length=128)
    allow_http: bool | None = None
    allow_socks5: bool | None = None
    allow_mtproto: bool | None = None
    regenerate_mtproto_secret: bool = False
    expires_at: datetime | None = None
    traffic_limit_bytes: int | None = Field(default=None, ge=0)

    @field_validator("password")
    @classmethod
    def password_clean(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if ":" in value or "|" in value:
            raise ValueError("password must not contain ':' or '|'")
        return value


class VlessSettingsOut(BaseModel):
    vless_enabled: bool
    vless_link: str | None = None
    vless_active: bool = False
    # Цепочка к клиентам: конфиг на диске = VLESS, прога OK, нет ожидания рестарта sing-box.
    vless_clients_chained: bool = False
    vless_singbox_restart_pending: bool = False


class VlessSettingsUpdate(BaseModel):
    vless_enabled: bool
    vless_link: str | None = None


class UserChartOptionOut(BaseModel):
    id: int
    username: str


class UserOut(BaseModel):
    id: int
    username: str
    password: str
    allow_http: bool
    allow_socks5: bool
    allow_mtproto: bool
    mtproto_secret: str | None
    traffic_in_bytes: int
    traffic_out_bytes: int
    traffic_bytes: int
    requests_count: int
    created_at: datetime
    expires_at: datetime | None
    traffic_limit_bytes: int | None
    access_allowed: bool


class UsersPageOut(BaseModel):
    items: list[UserOut]
    total: int
    page: int
    per_page: int


class UserCreatedOut(UserOut):
    password_generated: bool


class ImportRowError(BaseModel):
    row: int
    detail: str


class ImportUserResult(BaseModel):
    row: int
    username: str
    id: int
    password: str
    password_generated: bool


class ImportUsersOut(BaseModel):
    created: int
    errors: list[ImportRowError]
    results: list[ImportUserResult]


class LoginRequest(BaseModel):
    username: str
    password: str


class TrafficSeriesPoint(BaseModel):
    captured_at: datetime
    traffic_in_bytes: int
    traffic_out_bytes: int
    traffic_bytes: int


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        columns = [row[1] for row in conn.execute(text("PRAGMA table_info(proxy_users)")).fetchall()]
        if "traffic_in_bytes" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN traffic_in_bytes INTEGER DEFAULT 0"))
        if "traffic_out_bytes" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN traffic_out_bytes INTEGER DEFAULT 0"))
        if "allow_mtproto" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN allow_mtproto BOOLEAN DEFAULT 0"))
        if "mtproto_secret" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN mtproto_secret TEXT"))
        conn.execute(
            text(
                "UPDATE proxy_users "
                "SET traffic_out_bytes = traffic_bytes "
                "WHERE traffic_bytes > 0 AND traffic_in_bytes = 0 AND traffic_out_bytes = 0"
            )
        )
        traffic_state_columns = [row[1] for row in conn.execute(text("PRAGMA table_info(traffic_state)")).fetchall()]
        if "last_sample_ts" not in traffic_state_columns:
            conn.execute(text("ALTER TABLE traffic_state ADD COLUMN last_sample_ts INTEGER DEFAULT 0"))
        if "expires_at" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN expires_at TIMESTAMP"))
        if "traffic_limit_bytes" not in columns:
            conn.execute(text("ALTER TABLE proxy_users ADD COLUMN traffic_limit_bytes INTEGER"))
        panel_columns = [row[1] for row in conn.execute(text("PRAGMA table_info(panel_settings)")).fetchall()]
        if panel_columns and "vless_singbox_restart_pending" not in panel_columns:
            conn.execute(
                text("ALTER TABLE panel_settings ADD COLUMN vless_singbox_restart_pending BOOLEAN DEFAULT 0")
            )
            conn.execute(
                text(
                    "UPDATE panel_settings SET vless_singbox_restart_pending = 1 "
                    "WHERE vless_enabled = 1 AND TRIM(COALESCE(vless_link, '')) != ''"
                )
            )
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with SessionLocal() as session:
        state = session.get(TrafficState, 1)
        if state is None:
            session.add(TrafficState(id=1, file_offset=0))
            session.commit()
        ps = session.get(PanelSettings, 1)
        if ps is None:
            session.add(
                PanelSettings(
                    id=1,
                    vless_enabled=False,
                    vless_link=None,
                    vless_singbox_restart_pending=False,
                )
            )
            session.commit()


def _sqlite_database_path() -> Path | None:
    if not DATABASE_URL.startswith("sqlite"):
        return None
    u = make_url(DATABASE_URL)
    if not u.database:
        return None
    return Path(u.database)


def _sqlite_backup_file(dest_path: Path) -> None:
    src_path = _sqlite_database_path()
    if src_path is None:
        raise RuntimeError("SQLite URL required")
    src_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    src_conn = sqlite3.connect(str(src_path))
    try:
        dst_conn = sqlite3.connect(str(dest_path))
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()


def maybe_prune_traffic_events(session: Session) -> None:
    cnt = session.scalar(select(func.count()).select_from(TrafficEvent))
    if cnt is None or cnt <= PRUNE_TRAFFIC_EVENTS_MAX_ROWS:
        return
    session.execute(
        text(
            "DELETE FROM traffic_events WHERE id IN "
            "(SELECT id FROM traffic_events ORDER BY id ASC LIMIT :lim)"
        ),
        {"lim": PRUNE_TRAFFIC_EVENTS_CHUNK},
    )


def maybe_prune_traffic_samples(session: Session) -> None:
    """Удаляет старые строки traffic_samples (графики в API — до 24 ч)."""
    if TRAFFIC_SAMPLES_RETENTION_HOURS <= 0:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(hours=TRAFFIC_SAMPLES_RETENTION_HOURS)
    for _ in range(max(1, TRAFFIC_SAMPLES_PRUNE_MAX_BATCHES)):
        res = session.execute(
            text(
                "DELETE FROM traffic_samples WHERE id IN ("
                "SELECT id FROM traffic_samples WHERE captured_at < :cutoff "
                "ORDER BY id ASC LIMIT :lim)"
            ),
            {"cutoff": cutoff, "lim": TRAFFIC_SAMPLES_PRUNE_CHUNK},
        )
        deleted = res.rowcount or 0
        if deleted < TRAFFIC_SAMPLES_PRUNE_CHUNK:
            break


def get_db():
    with SessionLocal() as session:
        yield session


def get_panel_settings(session: Session) -> PanelSettings:
    s = session.get(PanelSettings, 1)
    if s is None:
        s = PanelSettings(
            id=1,
            vless_enabled=False,
            vless_link=None,
            vless_singbox_restart_pending=False,
        )
        session.add(s)
        session.commit()
        session.refresh(s)
    return s


def vless_upstream_active(settings: PanelSettings) -> bool:
    if not settings.vless_enabled:
        return False
    link = (settings.vless_link or "").strip()
    if not link:
        return False
    try:
        parsed = parse_vless_url(link)
        build_singbox_config(parsed, enabled=True)
        return True
    except ValueError:
        return False


def _socks5_drain_connect_reply(sock: socket.socket) -> bool:
    """Читает ответ SOCKS5 CONNECT; True если REP=0 (успех)."""
    head = sock.recv(4)
    if len(head) < 4 or head[0] != 0x05:
        return False
    rep = head[1]
    atyp = head[3]
    rest = 0
    if atyp == 0x01:
        rest = 4 + 2
    elif atyp == 0x03:
        ln_b = sock.recv(1)
        if len(ln_b) != 1:
            return False
        rest = ln_b[0] + 2
    elif atyp == 0x04:
        rest = 16 + 2
    else:
        return False
    body = sock.recv(rest) if rest else b""
    if len(body) != rest:
        return False
    return rep == 0x00


def probe_singbox_vless_path_ok() -> bool:
    """
    Проверяет: sing-box слушает SOCKS и даёт установить исходящее TCP через VLESS.
    Если VLESS до апстрима мёртв, REP будет не 0 — не включаем parent в 3proxy.
    """
    if VLESS_CHAIN_PROBE_TIMEOUT <= 0:
        return False
    host = VLESS_CHAIN_PROBE_HOST
    port = VLESS_CHAIN_PROBE_PORT
    probe_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        probe_ip = ipaddress.ip_address(host)
    except ValueError:
        probe_ip = None
        raw = host.encode("utf-8")
        if len(raw) < 1 or len(raw) > 255:
            return False
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection(
            (SINGBOX_SOCKS_HOST, SINGBOX_SOCKS_PORT),
            timeout=VLESS_CHAIN_PROBE_TIMEOUT,
        )
        sock.settimeout(VLESS_CHAIN_PROBE_TIMEOUT)
        sock.sendall(b"\x05\x01\x00")
        meth = sock.recv(2)
        if meth != b"\x05\x00":
            return False
        if probe_ip is not None:
            if probe_ip.version == 4:
                req = b"\x05\x01\x00\x01" + probe_ip.packed + port.to_bytes(2, "big")
            else:
                req = b"\x05\x01\x00\x04" + probe_ip.packed + port.to_bytes(2, "big")
        else:
            req = b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + port.to_bytes(2, "big")
        sock.sendall(req)
        return _socks5_drain_connect_reply(sock)
    except OSError:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def singbox_disk_has_vless_outbound() -> bool:
    """На общем томе должен лежать JSON с outbound vless-out (не только direct в памяти процесса)."""
    try:
        raw = SINGBOX_CONFIG_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return False
    for ob in data.get("outbounds") or []:
        if isinstance(ob, dict) and ob.get("tag") == "vless-out" and ob.get("type") == "vless":
            return True
    return False


def vless_proxy_chain_active(settings: PanelSettings) -> bool:
    """Технически включаем parent в 3proxy/mtg: ссылка OK, JSON с vless-out на диске, прога через sing-box."""
    if not vless_upstream_active(settings):
        return False
    if not singbox_disk_has_vless_outbound():
        return False
    return probe_singbox_vless_path_ok()


def vless_clients_chained(settings: PanelSettings) -> bool:
    """Для UI «всё зелёное»: то же + подтверждён рестарт sing-box после смены ссылки."""
    if not vless_proxy_chain_active(settings):
        return False
    return not settings.vless_singbox_restart_pending


def _docker_http_request(method: str, path: str, body: bytes = b"", timeout: float = 10.0) -> tuple[int, bytes]:
    """
    Минимальный HTTP-клиент к Docker Engine API через unix-socket.
    Нужен для авто-рестарта сервисов после обновления VLESS.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(DOCKER_SOCKET_PATH)
        headers = [
            f"{method} {path} HTTP/1.1",
            "Host: docker",
            "Connection: close",
            f"Content-Length: {len(body)}",
            "",
            "",
        ]
        req = "\r\n".join(headers).encode("utf-8") + body
        sock.sendall(req)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        raw = b"".join(chunks)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if not raw:
        return 0, b""
    head, _, payload = raw.partition(b"\r\n\r\n")
    head_lines = head.split(b"\r\n")
    first_line = head_lines[0].decode("utf-8", errors="replace") if head_lines else ""
    parts = first_line.split(" ")
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    # Docker API часто отвечает chunked transfer.
    is_chunked = False
    for ln in head_lines[1:]:
        if b":" not in ln:
            continue
        k, v = ln.split(b":", 1)
        if k.strip().lower() == b"transfer-encoding" and b"chunked" in v.strip().lower():
            is_chunked = True
            break
    if is_chunked:
        decoded = bytearray()
        rest = payload
        while rest:
            line, sep, tail = rest.partition(b"\r\n")
            if not sep:
                break
            try:
                size = int(line.strip().split(b";", 1)[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            if len(tail) < size + 2:
                break
            decoded.extend(tail[:size])
            rest = tail[size + 2 :]
        payload = bytes(decoded)
    return status, payload


def _docker_container_ids_by_service(service_name: str) -> list[str]:
    filters = json.dumps({"label": [f"com.docker.compose.service={service_name}"]}, separators=(",", ":"))
    status, payload = _docker_http_request(
        "GET",
        f"/containers/json?all=1&filters={quote(filters, safe='')}",
    )
    if status != 200:
        return []
    try:
        items = json.loads(payload.decode("utf-8") or "[]")
    except json.JSONDecodeError:
        return []
    out: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cid = item.get("Id")
        if isinstance(cid, str) and cid:
            out.append(cid)
    return out


def restart_vless_runtime_services() -> tuple[bool, str]:
    """
    Перезапускает sing-box/proxy/mtproto после изменения VLESS-ссылки.
    Возвращает (ok, message), чтобы UI показывал понятный статус.
    """
    if not AUTO_RESTART_VLESS_SERVICES:
        return True, "auto-restart disabled"
    if not Path(DOCKER_SOCKET_PATH).exists():
        return False, f"Docker socket not found: {DOCKER_SOCKET_PATH}"

    restarted = 0
    for service in VLESS_RESTART_SERVICES:
        ids = _docker_container_ids_by_service(service)
        if not ids:
            # Не считаем это фатальной ошибкой: состав стека может отличаться.
            continue
        for cid in ids:
            status, _ = _docker_http_request("POST", f"/containers/{cid}/restart?t=12", timeout=20.0)
            if status not in (204, 304):
                return False, f"restart failed for service={service}, status={status}"
            restarted += 1

    if restarted == 0:
        return False, "no compose service containers found for restart"

    # Небольшая пауза: после restart сразу идёт синхронизация конфигов/проба.
    time.sleep(1.5)
    return True, "ok"


def user_has_proxy_access(user: ProxyUser, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if user.expires_at is not None:
        exp = user.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now:
            return False
    if user.traffic_limit_bytes is not None:
        if user.traffic_limit_bytes <= 0:
            return False
        if user.traffic_bytes >= user.traffic_limit_bytes:
            return False
    return True


def user_to_out(user: ProxyUser) -> UserOut:
    now = datetime.now(timezone.utc)
    return UserOut(
        id=user.id,
        username=user.username,
        password=user.password,
        allow_http=user.allow_http,
        allow_socks5=user.allow_socks5,
        allow_mtproto=user.allow_mtproto,
        mtproto_secret=user.mtproto_secret,
        traffic_in_bytes=user.traffic_in_bytes,
        traffic_out_bytes=user.traffic_out_bytes,
        traffic_bytes=user.traffic_bytes,
        requests_count=user.requests_count,
        created_at=user.created_at,
        expires_at=user.expires_at,
        traffic_limit_bytes=user.traffic_limit_bytes,
        access_allowed=user_has_proxy_access(user, now),
    )


def render_proxy_config(
    users: list[ProxyUser], settings: PanelSettings, *, apply_upstream_chain: bool
) -> str:
    users_line = []
    http_users = []
    socks_users = []
    now = datetime.now(timezone.utc)

    for user in users:
        users_line.append(f"{user.username}:CL:{user.password}")
        if user.allow_http and user_has_proxy_access(user, now):
            http_users.append(user.username)
        if user.allow_socks5 and user_has_proxy_access(user, now):
            socks_users.append(user.username)

    if not users_line:
        users_line.append("disabled_user:CL:disabled_password")

    http_acl = ",".join(http_users) if http_users else "__none__"
    socks_acl = ",".join(socks_users) if socks_users else "__none__"

    # В 3proxy «parent» обязан идти сразу после «allow» (иначе Chaining error / цепочка не работает).
    if apply_upstream_chain:
        http_block = f"""flush
allow {http_acl}
parent 1000 socks5+ {SINGBOX_SOCKS_HOST} {SINGBOX_SOCKS_PORT}
proxy -p3128 -a
"""
        socks_block = f"""flush
allow {socks_acl}
parent 1000 socks5+ {SINGBOX_SOCKS_HOST} {SINGBOX_SOCKS_PORT}
socks -p1080
"""
    else:
        http_block = f"""flush
allow {http_acl}
proxy -p3128 -a
"""
        socks_block = f"""flush
allow {socks_acl}
socks -p1080
"""

    # Log format: epoch|username|bytes_in|bytes_out|service
    return f"""monitor /etc/3proxy/3proxy.cfg
log /var/log/3proxy/traffic.log
logformat "%t|%U|%I|%O"
# Emit intermediate records for long-lived connections,
# so panel counters update before the connection is closed.
logdump {PROXY_LOGDUMP_BYTES} {PROXY_LOGDUMP_BYTES}
rotate 7
nserver 1.1.1.1
nserver 8.8.8.8
nscache 65536
auth strong
users {" ".join(users_line)}
{http_block}
{socks_block}
flush
deny *
"""


def generate_proxy_user_password() -> str:
    # 3proxy log format: username|... must not contain ':' or '|' in password
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(20))


def generate_mtproto_secret() -> str:
    # mtg-multi accepts Telegram transport secrets:
    # - classic secure mode: dd + 16 random bytes (34 hex chars total)
    # - faketls mode: ee + 16 random bytes + domain bytes (hex)
    if MTPROTO_SECRET_MODE == "faketls":
        random_part = secrets.token_hex(16)
        fake_tls_hex = MTPROTO_FAKE_TLS_DOMAIN.encode("utf-8").hex()
        return f"ee{random_part}{fake_tls_hex}"
    return f"dd{secrets.token_hex(16)}"


def sanitize_mtproto_secret(raw_secret: str | None) -> str:
    secret = (raw_secret or "").strip().lower()
    if not secret:
        return generate_mtproto_secret()
    is_hex = all(ch in "0123456789abcdef" for ch in secret)
    if MTPROTO_SECRET_MODE == "classic":
        # Backward-compat: upgrade old 32-hex secret to secure dd-prefixed format.
        if len(secret) == 32 and is_hex:
            return f"dd{secret}"
        if len(secret) == 34 and secret.startswith("dd") and is_hex:
            return secret
        return generate_mtproto_secret()
    if MTPROTO_SECRET_MODE == "faketls":
        fake_tls_hex = MTPROTO_FAKE_TLS_DOMAIN.encode("utf-8").hex()
        if secret.startswith("ee") and secret.endswith(fake_tls_hex) and is_hex and len(secret) > 34:
            return secret
        return generate_mtproto_secret()
    return generate_mtproto_secret()


def render_mtproto_config(
    users: list[ProxyUser], settings: PanelSettings, *, apply_upstream_chain: bool
) -> str:
    now = datetime.now(timezone.utc)
    enabled_users = [
        (u.username, str(u.mtproto_secret))
        for u in users
        if u.allow_mtproto and u.mtproto_secret and user_has_proxy_access(u, now)
    ]
    if not enabled_users:
        # Keep proxy up with one synthetic secret to avoid service crash.
        enabled_users = [("disabled_user", generate_mtproto_secret())]
    vless_chain = apply_upstream_chain
    lines = [
        f'bind-to = "0.0.0.0:{MTPROTO_INTERNAL_PORT}"',
        'api-bind-to = "0.0.0.0:9090"',
        "",
    ]
    # В TOML ключи после [throttle] попали бы в throttle — prefer-ip только до секций.
    if vless_chain:
        lines.extend(['prefer-ip = "prefer-ipv4"', ""])
    lines.extend(
        [
            "[throttle]",
            "max-connections = 5000",
            "",
        ]
    )
    if vless_chain:
        # mtg ignores OS resolver; explicit DNS avoids failures when only the proxy path works.
        lines.extend(
            [
                "[network]",
                'dns = "udp://8.8.8.8"',
                f'proxies = ["socks5://{SINGBOX_SOCKS_HOST}:{SINGBOX_SOCKS_PORT}"]',
                "",
            ]
        )
    lines.append("[secrets]")
    for username, secret in enabled_users:
        lines.append(f'"{username}" = "{secret}"')
    return "\n".join(lines) + "\n"


def sync_mtproto_config(session: Session, *, apply_upstream_chain: bool) -> None:
    users = session.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    settings = get_panel_settings(session)
    content = render_mtproto_config(users, settings, apply_upstream_chain=apply_upstream_chain)
    MTPROTO_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = MTPROTO_CONFIG_PATH.with_suffix(".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(MTPROTO_CONFIG_PATH)


def normalize_mtproto_secrets(session: Session) -> None:
    users = session.scalars(select(ProxyUser).where(ProxyUser.allow_mtproto == True)).all()
    changed = False
    for user in users:
        normalized = sanitize_mtproto_secret(user.mtproto_secret)
        if user.mtproto_secret != normalized:
            user.mtproto_secret = normalized
            changed = True
    if changed:
        session.commit()


def sync_singbox_config(session: Session, settings: PanelSettings | None = None) -> None:
    settings = settings or get_panel_settings(session)
    content = singbox_config_direct_only()
    link = (settings.vless_link or "").strip()
    if settings.vless_enabled and link:
        try:
            parsed = parse_vless_url(link)
            content = build_singbox_config(parsed, enabled=True)
        except ValueError:
            content = singbox_config_direct_only()
    SINGBOX_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SINGBOX_CONFIG_PATH.with_suffix(".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(SINGBOX_CONFIG_PATH)


def sync_proxy_config(session: Session) -> None:
    users = session.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    settings = get_panel_settings(session)
    # Сначала JSON на диск — иначе проба может пойти против старого режима sing-box.
    sync_singbox_config(session, settings)
    apply_chain = vless_proxy_chain_active(settings)
    content = render_proxy_config(users, settings, apply_upstream_chain=apply_chain)
    PROXY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = PROXY_CONFIG_PATH.with_suffix(".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(PROXY_CONFIG_PATH)
    sync_mtproto_config(session, apply_upstream_chain=apply_chain)


def poll_mtproto_stats(session: Session) -> None:
    try:
        with urllib.request.urlopen(MTPROTO_STATS_URL, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return
    users_payload = payload.get("users")
    if not isinstance(users_payload, dict):
        return

    db_users = session.scalars(select(ProxyUser).where(ProxyUser.username.in_(list(users_payload.keys())))).all()
    by_username = {u.username: u for u in db_users}
    for username, stat in users_payload.items():
        if username not in by_username or not isinstance(stat, dict):
            continue
        user = by_username[username]
        if not user.allow_mtproto:
            continue
        in_total = int(stat.get("bytes_in", 0))
        out_total = int(stat.get("bytes_out", 0))
        connections_total = int(stat.get("connections", 0))

        state = session.get(MTProtoUserState, username)
        if state is None:
            state = MTProtoUserState(
                username=username,
                last_in_bytes=in_total,
                last_out_bytes=out_total,
                last_connections=connections_total,
            )
            session.add(state)
            continue

        delta_in = max(0, in_total - state.last_in_bytes)
        delta_out = max(0, out_total - state.last_out_bytes)
        delta_conn = max(0, connections_total - state.last_connections)
        if delta_in or delta_out or delta_conn:
            if user_has_proxy_access(user):
                user.traffic_in_bytes += delta_in
                user.traffic_out_bytes += delta_out
                user.traffic_bytes += delta_in + delta_out
                user.requests_count += delta_conn

        state.last_in_bytes = in_total
        state.last_out_bytes = out_total
        state.last_connections = connections_total


def sample_traffic(session: Session, now: datetime) -> None:
    users = session.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    total_in = 0
    total_out = 0
    total_all = 0
    for user in users:
        total_in += user.traffic_in_bytes
        total_out += user.traffic_out_bytes
        total_all += user.traffic_bytes
        session.add(
            TrafficSample(
                user_id=user.id,
                captured_at=now,
                traffic_in_bytes=user.traffic_in_bytes,
                traffic_out_bytes=user.traffic_out_bytes,
                traffic_bytes=user.traffic_bytes,
            )
        )
    session.add(
        TrafficSample(
            user_id=None,
            captured_at=now,
            traffic_in_bytes=total_in,
            traffic_out_bytes=total_out,
            traffic_bytes=total_all,
        )
    )


def parse_traffic_line(line: str) -> tuple[str, int, int, datetime | None] | None:
    parts = line.strip().split("|")
    if len(parts) != 4:
        return None
    ts_str, username, incoming, outgoing = parts
    if not username or username == "-":
        return None
    try:
        in_bytes = int(incoming)
        out_bytes = int(outgoing)
    except ValueError:
        return None
    logged_at: datetime | None = None
    try:
        ts_epoch = float(ts_str)
        logged_at = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        logged_at = None
    return username, in_bytes, out_bytes, logged_at


def traffic_worker(stop_event: threading.Event) -> None:
    last_access_sync = 0.0
    prune_tick = 0
    while not stop_event.is_set():
        try:
            PROXY_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            if not PROXY_LOG_PATH.exists():
                PROXY_LOG_PATH.touch()

            with SessionLocal() as session:
                state = session.get(TrafficState, 1)
                if state is None:
                    state = TrafficState(id=1, file_offset=0)
                    session.add(state)
                    session.commit()

                with PROXY_LOG_PATH.open("r", encoding="utf-8", errors="ignore") as log_file:
                    file_size = PROXY_LOG_PATH.stat().st_size
                    if state.file_offset > file_size:
                        state.file_offset = 0
                    log_file.seek(state.file_offset)

                    pending: dict[str, tuple[int, int, int]] = {}
                    log_events: list[TrafficEvent] = []
                    while True:
                        line = log_file.readline()
                        if not line:
                            break
                        parsed = parse_traffic_line(line)
                        if parsed is None:
                            continue
                        username, in_bytes, out_bytes, logged_at = parsed
                        log_events.append(
                            TrafficEvent(
                                username=username,
                                bytes_in=in_bytes,
                                bytes_out=out_bytes,
                                logged_at=logged_at,
                            )
                        )
                        req_count, traffic_in, traffic_out = pending.get(username, (0, 0, 0))
                        pending[username] = (req_count + 1, traffic_in + in_bytes, traffic_out + out_bytes)

                    state.file_offset = log_file.tell()

                    if log_events:
                        session.add_all(log_events)

                    if pending:
                        users = session.scalars(select(ProxyUser).where(ProxyUser.username.in_(list(pending.keys())))).all()
                        for user in users:
                            req_count, traffic_in, traffic_out = pending[user.username]
                            user.requests_count += req_count
                            user.traffic_in_bytes += traffic_in
                            user.traffic_out_bytes += traffic_out
                            user.traffic_bytes += traffic_in + traffic_out

                    poll_mtproto_stats(session)

                    now_ts = int(datetime.now(timezone.utc).timestamp())
                    if state.last_sample_ts == 0 or now_ts - state.last_sample_ts >= TRAFFIC_SAMPLING_INTERVAL_SECONDS:
                        sample_traffic(session, datetime.now(timezone.utc))
                        state.last_sample_ts = now_ts

                    prune_tick += 1
                    if prune_tick >= 200:
                        prune_tick = 0
                        maybe_prune_traffic_events(session)
                        maybe_prune_traffic_samples(session)

                    session.commit()

                    should_resync = bool(pending) or (
                        time.monotonic() - last_access_sync >= ACCESS_RESYNC_INTERVAL_SECONDS
                    )
                    if should_resync:
                        last_access_sync = time.monotonic()
                        with SessionLocal() as sync_session:
                            sync_proxy_config(sync_session)
        except Exception:
            # Worker must survive temporary file/db errors.
            pass
        stop_event.wait(TRAFFIC_POLL_INTERVAL_SECONDS)


def validate_protocol_selection(allow_http: bool, allow_socks5: bool) -> None:
    if not allow_http and not allow_socks5:
        raise HTTPException(status_code=400, detail="At least one protocol must be enabled")


def _protocol_ok_extended(allow_http: bool, allow_socks5: bool, allow_mtproto: bool) -> None:
    if not allow_http and not allow_socks5 and not allow_mtproto:
        raise ValueError("At least one protocol must be enabled")


def validate_protocol_selection_extended(allow_http: bool, allow_socks5: bool, allow_mtproto: bool) -> None:
    try:
        _protocol_ok_extended(allow_http, allow_socks5, allow_mtproto)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


def _prepare_user_row_for_create(payload: UserCreate, db: Session) -> tuple[ProxyUser, bool]:
    _protocol_ok_extended(payload.allow_http, payload.allow_socks5, payload.allow_mtproto)
    if payload.expires_at is not None:
        exp = payload.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
    existing = db.scalar(select(ProxyUser).where(ProxyUser.username == payload.username))
    if existing:
        raise ValueError("Username already exists")
    password_generated = payload.password is None
    final_password = generate_proxy_user_password() if password_generated else payload.password
    assert final_password is not None
    user = ProxyUser(
        username=payload.username,
        password=final_password,
        allow_http=payload.allow_http,
        allow_socks5=payload.allow_socks5,
        allow_mtproto=payload.allow_mtproto,
        mtproto_secret=generate_mtproto_secret() if payload.allow_mtproto else None,
        expires_at=payload.expires_at,
        traffic_limit_bytes=payload.traffic_limit_bytes,
    )
    return user, password_generated


def _normalize_import_header(cell: str) -> str:
    return cell.strip().lower().replace(" ", "_").replace("\ufeff", "")


def _map_import_columns(headers: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for i, raw in enumerate(headers):
        norm = _normalize_import_header(raw)
        for canon, aliases in IMPORT_HEADER_ALIASES.items():
            if canon in result:
                continue
            if norm == canon or norm in aliases:
                result[canon] = i
                break
    return result


def _parse_import_bool_cell(raw: str, default: bool) -> bool:
    v = (raw or "").strip().lower()
    if not v:
        return default
    if v in ("да", "yes", "1", "true", "y", "on"):
        return True
    if v in ("нет", "no", "0", "false", "n", "off"):
        return False
    raise ValueError(f"invalid boolean value: {raw!r}")


def _parse_import_expires_at(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as exc:
        raise ValueError("invalid expires_at (use ISO-8601, e.g. 2030-12-31T23:59:59Z)") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_import_limit_gb(s: str) -> int | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        gb = float(s.replace(",", "."))
    except ValueError as exc:
        raise ValueError("invalid traffic_limit_gb") from exc
    if gb < 0:
        raise ValueError("traffic_limit_gb must be >= 0")
    return int(round(gb * (1024**3)))


def _csv_rows_from_text(content: str) -> list[list[str]]:
    text = content.lstrip("\ufeff")
    if not text.strip():
        return []
    first_line = text.splitlines()[0]
    delim = ";" if first_line.count(";") >= first_line.count(",") else ","
    return list(csv.reader(io.StringIO(text), delimiter=delim))


def _row_to_user_create(cols: dict[str, int], row: list[str]) -> UserCreate:
    def cell(col: str) -> str:
        if col not in cols:
            return ""
        j = cols[col]
        if j >= len(row):
            return ""
        return row[j].strip()

    username = _normalize_import_username(cell("username"))

    pw_raw = cell("password")
    password: str | None = pw_raw if pw_raw else None

    allow_http = _parse_import_bool_cell(cell("allow_http"), True) if "allow_http" in cols else True
    allow_socks5 = _parse_import_bool_cell(cell("allow_socks5"), True) if "allow_socks5" in cols else True
    allow_mtproto = _parse_import_bool_cell(cell("allow_mtproto"), False) if "allow_mtproto" in cols else False

    expires_at: datetime | None = None
    if "expires_at" in cols:
        expires_at = _parse_import_expires_at(cell("expires_at"))

    traffic_limit_bytes: int | None = None
    if "traffic_limit_gb" in cols:
        traffic_limit_bytes = _parse_import_limit_gb(cell("traffic_limit_gb"))

    return UserCreate(
        username=username,
        password=password,
        allow_http=allow_http,
        allow_socks5=allow_socks5,
        allow_mtproto=allow_mtproto,
        expires_at=expires_at,
        traffic_limit_bytes=traffic_limit_bytes,
    )


def _normalize_import_username(raw: str) -> str:
    """
    Нормализация логина только для CSV-импорта:
    - пробелы -> "_"
    - запрещённые в 3proxy/валидации символы ":" и "|" -> "_"
    - повторные "_" схлопываются
    """
    s = (raw or "").strip()
    if not s:
        raise ValueError("username is required")
    s = re.sub(r"\s+", "_", s)
    s = s.replace(":", "_").replace("|", "_")
    s = re.sub(r"_+", "_", s)
    if len(s) > 64:
        s = s[:64]
    if len(s) < 3:
        raise ValueError("username is too short after normalization")
    return s


def _make_unique_import_username(base: str, taken: set[str]) -> str:
    """
    Делает username уникальным относительно уже занятых (БД + текущий импорт).
    Формат: base, base_2, base_3, ...
    """
    candidate = base
    if candidate not in taken:
        taken.add(candidate)
        return candidate
    i = 2
    while True:
        suffix = f"_{i}"
        root = base[: max(1, 64 - len(suffix))]
        candidate = f"{root}{suffix}"
        if candidate not in taken:
            taken.add(candidate)
            return candidate
        i += 1


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _sign_value(value: str) -> str:
    return hmac.new(PANEL_SECRET_KEY.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session_cookie(username: str) -> str:
    payload = {"u": username, "exp": _now_ts() + SESSION_TTL_SECONDS}
    payload_raw = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_raw.encode("utf-8")).decode("utf-8").rstrip("=")
    signature = _sign_value(payload_b64)
    return f"{payload_b64}.{signature}"


def decode_session_cookie(cookie_value: str | None) -> str | None:
    if not cookie_value or "." not in cookie_value:
        return None
    payload_b64, signature = cookie_value.split(".", 1)
    expected_signature = _sign_value(payload_b64)
    if not hmac.compare_digest(expected_signature, signature):
        return None
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        payload_raw = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_raw)
    except Exception:
        return None
    if payload.get("exp", 0) < _now_ts():
        return None
    return str(payload.get("u", ""))


def require_auth(request: Request) -> str:
    username = decode_session_cookie(request.cookies.get(SESSION_COOKIE_NAME))
    if username != ADMIN_USERNAME:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return username


def detect_public_ip() -> str | None:
    global _public_ip_cache
    if _public_ip_cache:
        return _public_ip_cache
    urls = ("https://api.ipify.org", "https://ifconfig.me/ip")
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                value = response.read().decode("utf-8").strip()
            ipaddress.ip_address(value)
            _public_ip_cache = value
            return value
        except Exception:
            continue
    return None


stop_event = threading.Event()
worker_thread: threading.Thread | None = None


def proxy_chain_delayed_resync_worker(delays_sec: tuple[float, ...] = (25.0, 55.0, 120.0)) -> None:
    """
    sing-box поднимается после healthy backend — первая sync_proxy_config часто идёт без SOCKS,
    и 3proxy остаётся без parent до ручного сохранения настроек. Повторяем синк с задержками.
    """
    elapsed = 0.0
    for target in delays_sec:
        wait = max(0.0, target - elapsed)
        if stop_event.wait(timeout=wait):
            return
        elapsed = target
        try:
            with SessionLocal() as session:
                sync_proxy_config(session)
        except Exception:
            pass


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global worker_thread
    init_db()
    with SessionLocal() as session:
        normalize_mtproto_secrets(session)
        sync_proxy_config(session)
    stop_event.clear()
    worker_thread = threading.Thread(target=traffic_worker, args=(stop_event,), daemon=True)
    worker_thread.start()
    threading.Thread(target=proxy_chain_delayed_resync_worker, daemon=True).start()
    yield
    stop_event.set()
    if worker_thread and worker_thread.is_alive():
        worker_thread.join(timeout=2)


app = FastAPI(title="Proxy Admin Panel", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="/app/static"), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def _read_panel_git_revision() -> str:
    try:
        return Path("/app/.git-revision").read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


@app.get("/health")
def health():
    return {"status": "ok", "revision": _read_panel_git_revision()}


@app.post("/api/auth/login")
def login(payload: LoginRequest, response: Response):
    if payload.username != ADMIN_USERNAME or not hmac.compare_digest(payload.password, ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    cookie_value = make_session_cookie(payload.username)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=cookie_value,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )
    return {"status": "ok"}


@app.post("/api/auth/logout")
def logout(response: Response, _auth: str = Depends(require_auth)):
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"status": "ok"}


@app.get("/api/auth/me")
def auth_me(_auth: str = Depends(require_auth)):
    return {"authenticated": True, "username": ADMIN_USERNAME}


@app.get("/api/meta")
def meta(request: Request, _auth: str = Depends(require_auth)):
    host_value = PROXY_PUBLIC_HOST
    if host_value == "auto":
        forwarded_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
        host_value = forwarded_host or request.url.hostname or "127.0.0.1"
        host_value = host_value.split(":")[0]
    mtproto_host = MTPROTO_PUBLIC_HOST or detect_public_ip() or host_value
    with SessionLocal() as session:
        ps = get_panel_settings(session)
        vless_active = vless_upstream_active(ps)
        vless_clients_chained_flag = vless_clients_chained(ps)
        vless_pending = bool(ps.vless_singbox_restart_pending)
    return {
        "proxy_public_host": host_value,
        "proxy_public_mtproto_host": mtproto_host,
        "proxy_public_http_port": PROXY_PUBLIC_HTTP_PORT,
        "proxy_public_socks_port": PROXY_PUBLIC_SOCKS_PORT,
        "proxy_public_mtproto_port": MTPROTO_PUBLIC_PORT,
        "vless_active": vless_active,
        "vless_clients_chained": vless_clients_chained_flag,
        "vless_singbox_restart_pending": vless_pending,
    }


@app.get("/api/settings/vless", response_model=VlessSettingsOut)
def get_vless_settings(_auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    s = get_panel_settings(db)
    return VlessSettingsOut(
        vless_enabled=s.vless_enabled,
        vless_link=s.vless_link,
        vless_active=vless_upstream_active(s),
        vless_clients_chained=vless_clients_chained(s),
        vless_singbox_restart_pending=bool(s.vless_singbox_restart_pending),
    )


@app.put("/api/settings/vless", response_model=VlessSettingsOut)
def put_vless_settings(
    payload: VlessSettingsUpdate,
    _auth: str = Depends(require_auth),
    db: Session = Depends(get_db),
):
    s = get_panel_settings(db)
    old_enabled = s.vless_enabled
    old_link = (s.vless_link or "").strip()
    link = (payload.vless_link or "").strip() or None
    if payload.vless_enabled:
        if not link:
            raise HTTPException(status_code=400, detail="Укажите ссылку vless:// при включении цепочки")
        try:
            parsed = parse_vless_url(link)
            build_singbox_config(parsed, enabled=True)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    changed = old_enabled != payload.vless_enabled or old_link != (link or "")
    s.vless_enabled = payload.vless_enabled
    s.vless_link = link
    if not payload.vless_enabled:
        s.vless_singbox_restart_pending = False
    elif changed and link:
        s.vless_singbox_restart_pending = True
    db.commit()
    db.refresh(s)
    sync_proxy_config(db)
    if changed:
        restart_ok, _restart_msg = restart_vless_runtime_services()
        if payload.vless_enabled:
            s.vless_singbox_restart_pending = not restart_ok
            db.commit()
            db.refresh(s)
        # После перезапуска обязательно пересобираем цепочки и gate-логику.
        sync_proxy_config(db)
    return VlessSettingsOut(
        vless_enabled=s.vless_enabled,
        vless_link=s.vless_link,
        vless_active=vless_upstream_active(s),
        vless_clients_chained=vless_clients_chained(s),
        vless_singbox_restart_pending=bool(s.vless_singbox_restart_pending),
    )


@app.post("/api/settings/vless/restart-done", response_model=VlessSettingsOut)
def vless_singbox_restart_done(_auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    """Fallback-кнопка: вручную триггернуть авто-рестарт сервисов VLESS и пересборку цепочки."""
    s = get_panel_settings(db)
    if not s.vless_enabled:
        raise HTTPException(status_code=400, detail="Цепочка VLESS выключена")
    ok, msg = restart_vless_runtime_services()
    if not ok:
        raise HTTPException(status_code=500, detail=f"Авто-рестарт сервисов не выполнен: {msg}")
    s.vless_singbox_restart_pending = False
    db.commit()
    db.refresh(s)
    sync_proxy_config(db)
    return VlessSettingsOut(
        vless_enabled=s.vless_enabled,
        vless_link=s.vless_link,
        vless_active=vless_upstream_active(s),
        vless_clients_chained=vless_clients_chained(s),
        vless_singbox_restart_pending=bool(s.vless_singbox_restart_pending),
    )


@app.get("/api/users", response_model=UsersPageOut)
def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=20),
    q: str = Query("", max_length=200),
    _auth: str = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Список пользователей с пагинацией (не более `per_page` записей, по умолчанию 20)."""
    if per_page > 20:
        per_page = 20
    q_clean = q.strip()
    stmt = select(ProxyUser).order_by(ProxyUser.id.asc())
    count_stmt = select(func.count()).select_from(ProxyUser)
    if q_clean:
        esc = q_clean.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{esc}%"
        filt = ProxyUser.username.like(pattern, escape="\\")
        stmt = stmt.where(filt)
        count_stmt = count_stmt.where(filt)
    total = int(db.scalar(count_stmt) or 0)
    total_pages = max(1, (total + per_page - 1) // per_page) if total else 1
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page
    users = db.scalars(stmt.offset(offset).limit(per_page)).all()
    return UsersPageOut(
        items=[user_to_out(u) for u in users],
        total=total,
        page=page,
        per_page=per_page,
    )


@app.get("/api/users/chart-options", response_model=list[UserChartOptionOut])
def list_users_chart_options(_auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    rows = db.execute(select(ProxyUser.id, ProxyUser.username).order_by(ProxyUser.id.asc())).all()
    return [UserChartOptionOut(id=i, username=username) for i, username in rows]


def _bytes_to_gib_str(n: int | None) -> str:
    """ГиБ (1024³ байт) в виде строки для CSV. Пусто только если лимит не задан (None)."""
    if n is None:
        return ""
    gib = n / (1024**3)
    s = f"{gib:.6f}".rstrip("0").rstrip(".")
    return s or "0"


def _client_public_hosts(request: Request) -> tuple[str, str]:
    host_value = PROXY_PUBLIC_HOST
    if host_value == "auto":
        forwarded_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
        host_value = forwarded_host or request.url.hostname or "127.0.0.1"
        host_value = host_value.split(":")[0]
    mtproto_host = MTPROTO_PUBLIC_HOST or detect_public_ip() or host_value
    return host_value, mtproto_host


def _user_http_proxy_url(host: str, username: str, password: str) -> str:
    return f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{PROXY_PUBLIC_HTTP_PORT}"


def _user_tg_socks_link(host: str, username: str, password: str) -> str:
    return (
        f"tg://socks?server={quote(host)}&port={quote(str(PROXY_PUBLIC_SOCKS_PORT))}"
        f"&user={quote(username)}&pass={quote(password)}"
    )


def _user_tg_mtproto_link(mtproto_host: str, secret: str) -> str:
    return (
        f"tg://proxy?server={quote(mtproto_host)}&port={quote(str(MTPROTO_PUBLIC_PORT))}"
        f"&secret={quote(secret)}"
    )


@app.get("/api/users/report")
def export_users_report(_auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    users = db.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(
        [
            "ID",
            "Логин",
            "Пароль",
            "HTTP",
            "SOCKS5",
            "MTProto",
            "Входящий_ГБ",
            "Исходящий_ГБ",
            "Всего_ГБ",
            "Запросов",
            "Создан_UTC",
            "Действует_до_UTC",
            "Лимит_ГБ",
            "Доступ",
        ]
    )
    for u in users:
        row = user_to_out(u)
        writer.writerow(
            [
                row.id,
                row.username,
                row.password,
                "да" if row.allow_http else "нет",
                "да" if row.allow_socks5 else "нет",
                "да" if row.allow_mtproto else "нет",
                _bytes_to_gib_str(row.traffic_in_bytes),
                _bytes_to_gib_str(row.traffic_out_bytes),
                _bytes_to_gib_str(row.traffic_bytes),
                row.requests_count,
                row.created_at.isoformat() if row.created_at else "",
                row.expires_at.isoformat() if row.expires_at else "",
                _bytes_to_gib_str(row.traffic_limit_bytes),
                "да" if row.access_allowed else "нет",
            ]
        )
    body = "\ufeff" + buffer.getvalue()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"proxy-users-report-{ts}.csv"
    return Response(
        content=body.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/users/report-links")
def export_users_report_with_links(
    request: Request,
    _auth: str = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Тот же отчёт, что /api/users/report, плюс колонки с готовыми ссылками (как в панели)."""
    host_value, mtproto_host = _client_public_hosts(request)
    users = db.scalars(select(ProxyUser).order_by(ProxyUser.id.asc())).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(
        [
            "ID",
            "Логин",
            "Пароль",
            "HTTP",
            "SOCKS5",
            "MTProto",
            "Входящий_ГБ",
            "Исходящий_ГБ",
            "Всего_ГБ",
            "Запросов",
            "Создан_UTC",
            "Действует_до_UTC",
            "Лимит_ГБ",
            "Доступ",
            "HTTP_ссылка",
            "TG_SOCKS5_ссылка",
            "TG_MTProto_ссылка",
        ]
    )
    for u in users:
        row = user_to_out(u)
        http_link = ""
        tg_socks = ""
        tg_mt = ""
        if row.access_allowed:
            if u.allow_http:
                http_link = _user_http_proxy_url(host_value, u.username, u.password)
            if u.allow_socks5:
                tg_socks = _user_tg_socks_link(host_value, u.username, u.password)
            if u.allow_mtproto and u.mtproto_secret:
                tg_mt = _user_tg_mtproto_link(mtproto_host, u.mtproto_secret)
        writer.writerow(
            [
                row.id,
                row.username,
                row.password,
                "да" if row.allow_http else "нет",
                "да" if row.allow_socks5 else "нет",
                "да" if row.allow_mtproto else "нет",
                _bytes_to_gib_str(row.traffic_in_bytes),
                _bytes_to_gib_str(row.traffic_out_bytes),
                _bytes_to_gib_str(row.traffic_bytes),
                row.requests_count,
                row.created_at.isoformat() if row.created_at else "",
                row.expires_at.isoformat() if row.expires_at else "",
                _bytes_to_gib_str(row.traffic_limit_bytes),
                "да" if row.access_allowed else "нет",
                http_link,
                tg_socks,
                tg_mt,
            ]
        )
    body = "\ufeff" + buffer.getvalue()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"proxy-users-report-links-{ts}.csv"
    return Response(
        content=body.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/users", response_model=UserCreatedOut)
def create_user(payload: UserCreate, _auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    try:
        user, password_generated = _prepare_user_row_for_create(payload, db)
    except ValueError as e:
        msg = str(e)
        if msg == "Username already exists":
            raise HTTPException(status_code=409, detail=msg) from e
        raise HTTPException(status_code=400, detail=msg) from e
    db.add(user)
    db.commit()
    db.refresh(user)
    sync_proxy_config(db)
    base = user_to_out(user)
    return UserCreatedOut(**base.model_dump(), password_generated=password_generated)


@app.get("/api/users/import-template")
def download_import_template(_auth: str = Depends(require_auth)):
    return Response(
        content=IMPORT_TEMPLATE_CSV.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="proxy-users-import-template.csv"'},
    )


@app.post("/api/users/import", response_model=ImportUsersOut)
async def import_users_csv(
    file: UploadFile = File(...),
    _auth: str = Depends(require_auth),
    db: Session = Depends(get_db),
):
    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="File must be UTF-8") from exc

    rows = _csv_rows_from_text(text)
    if not rows:
        raise HTTPException(status_code=400, detail="CSV is empty")

    headers = rows[0]
    col_map = _map_import_columns(headers)
    if "username" not in col_map:
        raise HTTPException(
            status_code=400,
            detail="CSV must contain a username column (username / логин)",
        )

    data_rows = rows[1:]
    if len(data_rows) > MAX_IMPORT_ROWS:
        raise HTTPException(
            status_code=400,
            detail=f"Too many rows (max {MAX_IMPORT_ROWS})",
        )

    results: list[ImportUserResult] = []
    errors: list[ImportRowError] = []
    taken_usernames = {
        u for u in db.scalars(select(ProxyUser.username)).all() if isinstance(u, str) and u
    }

    for i, row in enumerate(data_rows, start=2):
        if not row or not any((c or "").strip() for c in row):
            continue
        try:
            payload = _row_to_user_create(col_map, row)
            normalized_username = _normalize_import_username(payload.username)
            unique_username = _make_unique_import_username(normalized_username, taken_usernames)
            payload = payload.model_copy(update={"username": unique_username})
            user, password_generated = _prepare_user_row_for_create(payload, db)
        except ValueError as e:
            errors.append(ImportRowError(row=i, detail=str(e)))
            continue
        except ValidationError as e:
            err0 = e.errors()[0] if e.errors() else {}
            msg = str(err0.get("msg", e))
            errors.append(ImportRowError(row=i, detail=msg))
            continue
        db.add(user)
        db.flush()
        results.append(
            ImportUserResult(
                row=i,
                username=user.username,
                id=user.id,
                password=user.password,
                password_generated=password_generated,
            )
        )

    db.commit()
    sync_proxy_config(db)

    return ImportUsersOut(created=len(results), errors=errors, results=results)


@app.put("/api/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, payload: UserUpdate, _auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    user = db.get(ProxyUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    new_http = payload.allow_http if payload.allow_http is not None else user.allow_http
    new_socks = payload.allow_socks5 if payload.allow_socks5 is not None else user.allow_socks5
    new_mtproto = payload.allow_mtproto if payload.allow_mtproto is not None else user.allow_mtproto
    validate_protocol_selection_extended(new_http, new_socks, new_mtproto)

    if payload.password is not None:
        user.password = payload.password
    if payload.allow_http is not None:
        user.allow_http = payload.allow_http
    if payload.allow_socks5 is not None:
        user.allow_socks5 = payload.allow_socks5
    if payload.allow_mtproto is not None:
        user.allow_mtproto = payload.allow_mtproto
        if user.allow_mtproto:
            user.mtproto_secret = sanitize_mtproto_secret(user.mtproto_secret)
    if payload.regenerate_mtproto_secret:
        user.mtproto_secret = generate_mtproto_secret()

    patch = payload.model_dump(exclude_unset=True)
    if "expires_at" in patch:
        if patch["expires_at"] is not None:
            exp = patch["expires_at"]
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= datetime.now(timezone.utc):
                raise HTTPException(status_code=400, detail="expires_at must be in the future")
        user.expires_at = patch["expires_at"]
    if "traffic_limit_bytes" in patch:
        user.traffic_limit_bytes = patch["traffic_limit_bytes"]

    db.commit()
    db.refresh(user)
    sync_proxy_config(db)
    return user_to_out(user)


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, _auth: str = Depends(require_auth), db: Session = Depends(get_db)):
    user = db.get(ProxyUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    sync_proxy_config(db)
    return {"status": "deleted"}


@app.post("/api/backup")
def backup_users(_auth: str = Depends(require_auth)):
    if _sqlite_database_path() is None:
        raise HTTPException(
            status_code=501,
            detail="Резервная копия файла БД поддерживается только для SQLite (DATABASE_URL=sqlite:...)",
        )
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    file_path = BACKUP_DIR / f"panel-backup-{ts}.db"
    try:
        _sqlite_backup_file(file_path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return FileResponse(
        path=str(file_path),
        media_type="application/x-sqlite3",
        filename=file_path.name,
    )


@app.post("/api/restore")
async def restore_users(file: UploadFile = File(...), _auth: str = Depends(require_auth)):
    data = await file.read()
    if len(data) >= 15 and data.startswith(b"SQLite format 3"):
        dest = _sqlite_database_path()
        if dest is None:
            raise HTTPException(
                status_code=501,
                detail="Восстановление из файла БД доступно только при SQLite (DATABASE_URL=sqlite:...)",
            )
        fd, tmp_path = tempfile.mkstemp(suffix=".db")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            probe = sqlite3.connect(tmp_path)
            try:
                probe.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='proxy_users'"
                )
            finally:
                probe.close()
        except sqlite3.Error as exc:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise HTTPException(status_code=400, detail=f"Некорректный SQLite: {exc}") from exc
        try:
            engine.dispose()
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(tmp_path, dest)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        init_db()
        with SessionLocal() as session:
            normalize_mtproto_secrets(session)
            sync_proxy_config(session)
        return {"status": "restored", "format": "sqlite"}

    try:
        text = data.decode("utf-8")
        payload = json.loads(text)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Неверный JSON: {exc}") from exc

    if not isinstance(payload, dict) or "users" not in payload or not isinstance(payload["users"], list):
        raise HTTPException(status_code=400, detail="Неверный формат legacy JSON backup")

    with SessionLocal() as db:
        db.execute(delete(ProxyUser))
        for item in payload["users"]:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username", "")).strip()
            password = str(item.get("password", ""))
            allow_http = bool(item.get("allow_http", False))
            allow_socks5 = bool(item.get("allow_socks5", False))
            allow_mtproto = bool(item.get("allow_mtproto", False))
            if not username or ":" in username or "|" in username or " " in username:
                continue
            if ":" in password or "|" in password:
                continue
            if not allow_http and not allow_socks5 and not allow_mtproto:
                continue
            expires_raw = item.get("expires_at")
            expires_at = datetime.fromisoformat(str(expires_raw)) if expires_raw else None
            tlim = item.get("traffic_limit_bytes")
            traffic_limit_bytes = int(tlim) if tlim is not None else None

            user = ProxyUser(
                username=username,
                password=password,
                allow_http=allow_http,
                allow_socks5=allow_socks5,
                allow_mtproto=allow_mtproto,
                mtproto_secret=sanitize_mtproto_secret(str(item.get("mtproto_secret") or "")) if allow_mtproto else None,
                traffic_in_bytes=int(item.get("traffic_in_bytes", 0)),
                traffic_out_bytes=int(item.get("traffic_out_bytes", 0)),
                traffic_bytes=int(item.get("traffic_bytes", 0)),
                requests_count=int(item.get("requests_count", 0)),
                created_at=datetime.fromisoformat(item.get("created_at")) if item.get("created_at") else datetime.now(timezone.utc),
                expires_at=expires_at,
                traffic_limit_bytes=traffic_limit_bytes,
            )
            db.add(user)
        db.commit()
    with SessionLocal() as session:
        sync_proxy_config(session)
    return {"status": "restored", "format": "json"}


@app.get("/api/traffic/samples", response_model=list[TrafficSeriesPoint])
def traffic_samples(
    user_id: int | None = None,
    minutes: int = 180,
    _auth: str = Depends(require_auth),
    db: Session = Depends(get_db),
):
    minutes = max(10, min(minutes, 24 * 60))
    threshold = datetime.now(timezone.utc).timestamp() - minutes * 60
    threshold_dt = datetime.fromtimestamp(threshold, timezone.utc)
    if user_id is None:
        rows = db.scalars(
            select(TrafficSample)
            .where(TrafficSample.user_id.is_(None), TrafficSample.captured_at >= threshold_dt)
            .order_by(TrafficSample.captured_at.asc())
        ).all()
    else:
        rows = db.scalars(
            select(TrafficSample)
            .where(TrafficSample.user_id == user_id, TrafficSample.captured_at >= threshold_dt)
            .order_by(TrafficSample.captured_at.asc())
        ).all()
    return [
        TrafficSeriesPoint(
            captured_at=row.captured_at,
            traffic_in_bytes=row.traffic_in_bytes,
            traffic_out_bytes=row.traffic_out_bytes,
            traffic_bytes=row.traffic_bytes,
        )
        for row in rows
    ]
