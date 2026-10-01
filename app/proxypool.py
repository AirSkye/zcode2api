"""代理池：导入账号时自动一号一代理分配。

- 代理清单文件：{DATA_DIR}/proxies.txt，每行一个 http://user:pass@host:port
- 分配状态持久化：已分配的代理从账号表反查（account.proxy），游标存 settings
- 账号删除后其代理自动回到池中；池耗尽时返回 None（账号保持直连）
"""
from __future__ import annotations

import threading

from . import settings
from .proxyutil import normalize_proxy

_LOCK = threading.Lock()
_POOL: list[str] | None = None

POOL_FILE = "proxies.txt"
CURSOR_KEY = "proxy_pool_cursor"


def pool_file():
    return settings.DATA_DIR / POOL_FILE


def load_pool(force: bool = False) -> list[str]:
    """加载代理池（缓存）。文件不存在返回空列表。"""
    global _POOL
    with _LOCK:
        if _POOL is None or force:
            f = pool_file()
            pool: list[str] = []
            if f.exists():
                seen: set[str] = set()
                for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                    url = normalize_proxy(line)
                    if url and url not in seen:
                        seen.add(url)
                        pool.append(url)
            _POOL = pool
        return list(_POOL)


def _hostport(url: str) -> str:
    # http://user:pass@host:port -> host:port
    rest = url.split("://", 1)[1]
    return rest.rsplit("@", 1)[-1]


def assigned_hostports() -> set[str]:
    """所有账号已占用的代理 host:port。"""
    from .store import store

    used: set[str] = set()
    for acc in store.list_accounts():
        p = normalize_proxy(getattr(acc, "proxy", None))
        if p:
            used.add(_hostport(p))
    return used


def pool_stats() -> dict:
    pool = load_pool()
    used = assigned_hostports()
    return {"total": len(pool), "assigned": len(used), "free": len(pool) - len(used)}


def assign_proxy(account) -> str | None:
    """为账号分配一个空闲代理并写回 DB。返回代理 URL，池空返回 None。"""
    from .store import store

    pool = load_pool()
    if not pool:
        return None
    used = assigned_hostports()
    # 游标轮转，避免每次都从头取
    try:
        cursor = int(store.get_setting(CURSOR_KEY, "0") or 0)
    except (TypeError, ValueError):
        cursor = 0
    n = len(pool)
    chosen: str | None = None
    for i in range(n):
        cand = pool[(cursor + i) % n]
        if _hostport(cand) not in used:
            chosen = cand
            cursor = (cursor + i + 1) % n
            break
    if chosen is None:
        return None
    with _LOCK:
        account.proxy = chosen
        store.update_account(account)
        store.set_setting(CURSOR_KEY, str(cursor))
    return chosen


def auto_assign_new_accounts(accounts) -> int:
    """给一批新导入且未配代理的账号自动分配。返回分配成功数。"""
    ok = 0
    for acc in accounts:
        if normalize_proxy(getattr(acc, "proxy", None)):
            continue
        if assign_proxy(acc):
            ok += 1
        else:
            break  # 池耗尽
    return ok
