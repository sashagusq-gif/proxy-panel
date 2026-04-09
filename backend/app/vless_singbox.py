"""Парсинг vless:// ссылок и генерация конфигурации sing-box (SOCKS in → VLESS out)."""

from __future__ import annotations

import ipaddress
import json
import os
import uuid as uuid_lib
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


def _flatten_params(qs: dict[str, list[str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, vals in qs.items():
        if vals:
            out[k.lower()] = unquote(vals[0]).strip()
    return out


def _normalize_uuid(raw: str) -> str:
    s = (raw or "").strip()
    try:
        return str(uuid_lib.UUID(s))
    except ValueError as e:
        raise ValueError("Неверный UUID в ссылке") from e


def parse_vless_url(raw: str) -> dict[str, Any]:
    raw = (raw or "").strip()
    if not raw.startswith("vless://"):
        raise ValueError("Ссылка должна начинаться с vless://")
    u = urlparse(raw)
    if u.scheme != "vless":
        raise ValueError("Неверная схема URL")
    if not u.hostname:
        raise ValueError("Не указан хост")
    uuid = _normalize_uuid(unquote(u.username or ""))
    try:
        port = u.port or 443
    except ValueError as e:
        raise ValueError("Неверный порт в ссылке VLESS") from e
    if port < 1 or port > 65535:
        raise ValueError("Порт должен быть в диапазоне 1..65535")
    server = u.hostname.strip("[]")
    if not server:
        raise ValueError("Не указан хост")
    params = _flatten_params(parse_qs(u.query))
    fragment = unquote(u.fragment) if u.fragment else ""
    return {
        "uuid": uuid,
        "server": server,
        "port": port,
        "params": params,
        "remark": fragment,
    }


def _bool_param(p: dict[str, str], key: str) -> bool:
    v = (p.get(key) or "").lower()
    return v in ("1", "true", "yes", "on")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _singbox_log_level() -> str:
    return (os.environ.get("SINGBOX_LOG_LEVEL") or "warn").strip().lower()


def _normalize_network(raw: str) -> str:
    s = (raw or "tcp").strip().lower()
    aliases = {
        "h2": "http",
        "http2": "http",
        "gun": "grpc",
    }
    s = aliases.get(s, s)
    if s in ("tcp", "ws", "grpc", "httpupgrade", "http"):
        return s
    raise ValueError(f"Неподдерживаемый transport type: {raw}")


def _normalize_security(raw: str) -> str:
    s = (raw or "none").strip().lower()
    if s in ("none", "tls", "reality"):
        return s
    if s in ("xtls",):
        # Для sing-box в клиентском VLESS это обычный TLS-контур.
        return "tls"
    raise ValueError(f"Неподдерживаемый security: {raw}")


def _normalize_vless_flow(raw: str) -> str:
    """Xray в ссылках иногда даёт xtls-rprx-vision-udp443 — sing-box это не понимает."""
    s = (raw or "").strip()
    if not s:
        return ""
    low = s.lower()
    if low in ("none", "null", "-", "off", "plain"):
        return ""
    if low.startswith("xtls-rprx-vision"):
        return "xtls-rprx-vision"
    return s


def _dns_block_for_remote() -> dict[str, Any]:
    """Явный DNS для исходящего VLESS: в Docker часто ломается резолв домена узла (IPv6/резолвер)."""
    return {
        "servers": [
            {
                "type": "udp",
                "tag": "dns-remote",
                "server": "8.8.8.8",
                "server_port": 53,
            }
        ],
        "strategy": "prefer_ipv4",
        "final": "dns-remote",
    }


def build_singbox_config(parsed: dict[str, Any] | None, *, enabled: bool) -> str:
    """Генерирует JSON sing-box: SOCKS 0.0.0.0:1080 → VLESS или direct."""
    inbound = {
        "type": "socks",
        "tag": "socks-in",
        "listen": "0.0.0.0",
        "listen_port": 1080,
    }
    if not enabled or not parsed:
        outbounds: list[dict[str, Any]] = [
            {"type": "direct", "tag": "direct"},
        ]
        route: dict[str, Any] = {"final": "direct"}
    else:
        p = parsed["params"]
        server = parsed["server"]
        port = parsed["port"]
        uuid = parsed["uuid"]
        net = _normalize_network(p.get("type") or "tcp")
        security = _normalize_security(p.get("security") or "none")

        # flow из ссылки; без параметра — plain VLESS (REALITY). Vision: flow=xtls-rprx-vision
        flow = _normalize_vless_flow(p.get("flow") or "")
        if flow and security == "none":
            raise ValueError("Параметр flow требует security=tls или security=reality")

        outbound: dict[str, Any] = {
            "type": "vless",
            "tag": "vless-out",
            "server": server,
            "server_port": port,
            "uuid": uuid,
        }
        if flow:
            outbound["flow"] = flow
        # Явный резолвинг адреса сервера (домен в vless), иначе в Docker часто берётся AAAA/неверный путь.
        if not _is_ip(server):
            outbound["domain_resolver"] = {
                "server": "dns-remote",
                "strategy": "prefer_ipv4",
            }
        if security in ("tls", "reality"):
            tls: dict[str, Any] = {"enabled": True}
            sni = (p.get("sni") or p.get("peer") or "").strip()
            if not sni and not _is_ip(server):
                sni = server
            if sni:
                tls["server_name"] = sni
            alpn_raw = (p.get("alpn") or "").strip()
            if alpn_raw:
                tls["alpn"] = [x.strip() for x in unquote(alpn_raw).split(",") if x.strip()]
            if _bool_param(p, "allowinsecure") or _bool_param(p, "insecure"):
                tls["insecure"] = True
            if security == "reality":
                # sing-box: uTLS обязателен для REALITY (см. NewRealityClient).
                fp = (p.get("fp") or p.get("fingerprint") or "chrome").strip()
                tls["utls"] = {"enabled": True, "fingerprint": fp}
                tls["reality"] = {"enabled": True}
                pbk = p.get("pbk") or p.get("publickey")
                if not pbk:
                    raise ValueError("Для REALITY в ссылке нужен параметр pbk (public key)")
                tls["reality"]["public_key"] = pbk
                sid = (p.get("sid") or p.get("shortid") or "").strip()
                if sid:
                    tls["reality"]["short_id"] = sid
                if not tls.get("server_name"):
                    raise ValueError("Для REALITY нужен sni/peer (или доменное имя в host)")
            else:
                fp = p.get("fp") or p.get("fingerprint")
                if fp:
                    tls["utls"] = {"enabled": True, "fingerprint": fp}
            outbound["tls"] = tls
        # Только TCP для type=tcp: иначе sing-box по умолчанию включает и udp — ломает часть REALITY/VLESS к Xray.
        if net == "tcp":
            outbound["network"] = "tcp"
        # Без XTLS Vision sing-box по умолчанию ставит packet_encoding=xudp; многие Xray-узлы ждут обычный VLESS без XUDP.
        if not flow:
            outbound["packet_encoding"] = ""
        if security == "reality" and net == "tcp":
            outbound["connect_timeout"] = "20s"
        if net == "ws":
            path = (p.get("path") or "/").strip() or "/"
            if not path.startswith("/"):
                path = "/" + path
            host_hdr = p.get("host") or server
            outbound["transport"] = {
                "type": "ws",
                "path": path,
                "headers": {"Host": host_hdr},
            }
        elif net == "grpc":
            svc = p.get("servicename") or p.get("serviceName") or "GunService"
            outbound["transport"] = {"type": "grpc", "service_name": svc}
        elif net == "httpupgrade":
            path = (p.get("path") or "/").strip() or "/"
            if not path.startswith("/"):
                path = "/" + path
            host_hdr = p.get("host") or server
            outbound["transport"] = {
                "type": "httpupgrade",
                "host": host_hdr,
                "path": path,
                "headers": {},
            }
        elif net == "http":
            path = (p.get("path") or "/").strip() or "/"
            if not path.startswith("/"):
                path = "/" + path
            host_hdr = p.get("host") or server
            outbound["transport"] = {
                "type": "http",
                "path": path,
                "host": [host_hdr] if host_hdr else [],
                "headers": {},
            }
        outbounds = [
            outbound,
            {"type": "direct", "tag": "direct"},
        ]
        route: dict[str, Any] = {
            "final": "vless-out",
            "auto_detect_interface": True,
        }
        if not _is_ip(server):
            route["default_domain_resolver"] = {
                "server": "dns-remote",
                "strategy": "prefer_ipv4",
            }
    cfg: dict[str, Any] = {
        "log": {"level": _singbox_log_level()},
        "inbounds": [inbound],
        "outbounds": outbounds,
        "route": route,
    }
    if enabled and parsed and not _is_ip(parsed["server"]):
        cfg["dns"] = _dns_block_for_remote()
    return json.dumps(cfg, indent=2, ensure_ascii=False)


def singbox_config_direct_only() -> str:
    return build_singbox_config(None, enabled=False)
