"""按账号代理（一号一代理）。

设计原则：
- 默认不改变任何现有行为：账号没配代理时，上游客户端的创建方式与原来完全一致
  （billing/claim 保持 trust_env=False 直连，网关保持原来的 env 行为）。
- 账号配了代理后，该账号的所有上游请求（模型调用、领取、额度）都走这条代理。
"""
from __future__ import annotations

import re
import time

import httpx

# http://user:pass@host:port 或 http://host:port（https 同理）
_PROXY_RE = re.compile(r"^https?://([^@\s/]+@)?[A-Za-z0-9.\-_]+:\d{1,5}$")
_MASK_RE = re.compile(r"^(https?://)(?:[^@\s/]+@)?([^/\s]+)$")


def normalize_proxy(value: str | None) -> str | None:
    """校验并归一化代理 URL；非法返回 None。"""
    v = (value or "").strip()
    if not v:
        return None
    if _PROXY_RE.match(v):
        return v
    return None


def mask_proxy(value: str) -> str:
    """脱敏：只保留 host:port，绝不暴露密码。非法格式返回 '***'。"""
    v = (value or "").strip()
    m = _MASK_RE.match(v)
    if not m:
        return "***"
    return m.group(2)


def proxy_for(account) -> str | None:
    """取账号配置的代理（已校验格式），未配置返回 None。"""
    if account is None:
        return None
    return normalize_proxy(getattr(account, "proxy", None))


def upstream_client(account=None, **kwargs) -> httpx.AsyncClient:
    """创建上游 httpx 客户端。

    账号配了代理则注入 proxy= 参数；没配时代理相关参数一个不动，
    与调用方原来的写法行为一致。
    """
    kw = dict(kwargs)
    proxy = proxy_for(account)
    if proxy and "proxy" not in kw:
        kw["proxy"] = proxy
    return httpx.AsyncClient(**kw)


async def test_proxy(proxy_url: str, timeout: float = 15.0) -> dict:
    """测试代理连通性：走 HTTPS（CONNECT 隧道，贴近 Z.AI 实际调用方式）。

    返回 {"ok", "egress_ip", "ms", "error"}。
    """
    proxy = normalize_proxy(proxy_url)
    if not proxy:
        return {"ok": False, "egress_ip": None, "ms": 0,
                "error": "代理格式非法，应为 http(s)://[user:pass@]host:port"}
    t0 = time.time()
    try:
        async with httpx.AsyncClient(proxy=proxy, timeout=timeout,
                                     trust_env=False) as client:
            r = await client.get("https://api.ipify.org?format=text")
            r.raise_for_status()
            ip = r.text.strip()
            if not re.match(r"^[0-9a-fA-F.:]+$", ip):
                raise ValueError(f"出口 IP 解析异常: {ip[:40]}")
            ms = int((time.time() - t0) * 1000)
            return {"ok": True, "egress_ip": ip, "ms": ms, "error": None}
    except Exception as e:  # noqa: BLE001
        ms = int((time.time() - t0) * 1000)
        return {"ok": False, "egress_ip": None, "ms": ms,
                "error": f"{type(e).__name__}: {str(e)[:120]}"}
