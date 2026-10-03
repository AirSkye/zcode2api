"""按账号代理（一号一代理）。

设计原则：
- 账号没配代理时，上游客户端的创建方式与原来完全一致。
- 账号配了代理后，是否真正走代理由两级开关决定：
  全局开关（settings.proxy_global_enabled，默认开）× 账号开关（account.proxy_enabled，默认开）。
  任一关闭则该账号全部上游请求直连。
- 账号开关开时，该账号的所有上游请求（模型调用、领取、额度）都走这条代理。
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


def proxy_enabled_for(account) -> bool:
    """该账号是否允许走代理：全局开关 × 账号开关（默认都开）。"""
    if account is None:
        return False
    if not getattr(account, "proxy_enabled", True):
        return False
    try:
        from .store import store

        if str(store.get_setting("proxy_global_enabled", "1")) != "1":
            return False
    except Exception:  # noqa: BLE001
        pass
    return True


def proxy_for(account) -> str | None:
    """取账号实际生效的代理（已校验格式）；任一开关关闭或未配置返回 None。"""
    if not proxy_enabled_for(account):
        return None
    return normalize_proxy(getattr(account, "proxy", None))


def egress_ip_for(account) -> str | None:
    """该账号当前请求的出口 IP（用于日志/展示）：

    - 走代理：优先用最近一次探测到的出口 IP（proxy_egress），没有则退化为代理 host
    - 直连：返回 None（调用方展示为"直连"）
    """
    if not proxy_enabled_for(account):
        return None
    proxy = normalize_proxy(getattr(account, "proxy", None))
    if not proxy:
        return None
    eg = getattr(account, "proxy_egress", None) or {}
    if eg.get("ok") and eg.get("ip"):
        return str(eg["ip"])
    m = _MASK_RE.match(proxy)
    return m.group(2) if m else None


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
    """测试代理连通性：自动检测支持类型。

    先测 HTTPS（CONNECT 隧道，贴近 Z.AI 实际调用方式），
    再测 HTTP。返回 {"ok", "egress_ip", "ms", "error",
    "supports": {"http": bool, "https": bool}}。
    ok 为 True 当且仅当 HTTPS 可用（zcode2api 只走 HTTPS）。
    """
    proxy = normalize_proxy(proxy_url)
    if not proxy:
        return {"ok": False, "egress_ip": None, "ms": 0,
                "error": "代理格式非法，应为 http(s)://[user:pass@]host:port",
                "supports": {"http": False, "https": False}}
    supports = {"http": False, "https": False}
    egress_ip, ms, err = None, 0, None
    t0 = time.time()
    try:
        async with httpx.AsyncClient(proxy=proxy, timeout=timeout,
                                     trust_env=False) as client:
            # 1. HTTPS（决定 ok）
            try:
                r = await client.get("https://api.ipify.org?format=text")
                r.raise_for_status()
                ip = r.text.strip()
                if re.match(r"^[0-9a-fA-F.:]+$", ip):
                    supports["https"] = True
                    egress_ip = ip
            except Exception as e:  # noqa: BLE001
                err = f"HTTPS: {type(e).__name__}: {str(e)[:80]}"
            # 2. HTTP（仅探测支持类型）
            try:
                r = await client.get("http://api.ipify.org?format=text")
                r.raise_for_status()
                ip = r.text.strip()
                if re.match(r"^[0-9a-fA-F.:]+$", ip):
                    supports["http"] = True
                    if not egress_ip:
                        egress_ip = ip
            except Exception:  # noqa: BLE001
                pass
            ms = int((time.time() - t0) * 1000)
            if supports["https"]:
                return {"ok": True, "egress_ip": egress_ip, "ms": ms,
                        "error": None, "supports": supports}
            # HTTPS 不可用：说明是哪种情况
            if supports["http"]:
                error = "仅支持 HTTP，不支持 HTTPS（zcode2api 需要 HTTPS）"
            else:
                error = err or "HTTP/HTTPS 均不可用"
            return {"ok": False, "egress_ip": egress_ip, "ms": ms,
                    "error": error, "supports": supports}
    except Exception as e:  # noqa: BLE001
        ms = int((time.time() - t0) * 1000)
        return {"ok": False, "egress_ip": None, "ms": ms,
                "error": f"{type(e).__name__}: {str(e)[:120]}",
                "supports": supports}
