"""代理健康实时监控：每 10s 检测候选 HTTPS 代理的延迟，优选前 N 个分配给账号。

- 候选池：data/proxy_candidates.txt（每行 http://ip:port）
- 每个代理保留最近 10 次延迟，取平均排名
- N = 当前账号数量；始终用平均延迟最低的 N 个
- 已分配代理若连续 3 次检测失败或平均延迟明显劣化，自动替换为更优的未分配代理
- 无更优可用时不替换
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field

from . import logs
from . import proxyutil
from .store import store


CHECK_INTERVAL = 10.0          # 检测间隔（秒）
HISTORY_LEN = 10               # 保留最近 N 次延迟
FAIL_THRESHOLD = 3             # 连续失败 N 次视为不可用
REPLACE_RATIO = 1.5            # 已分配代理平均延迟超过最优未分配 1.5 倍时替换


@dataclass
class ProxyStat:
    proxy: str
    latencies: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LEN))
    fails: int = 0
    last_check: float = 0
    last_ms: int | None = None
    ok: bool = False
    mitm_checked: bool = False  # 是否已通过 MITM 检测
    mitm_bad: bool = False      # 是否检测出 MITM

    @property
    def avg_ms(self) -> float | None:
        if not self.latencies:
            return None
        return sum(self.latencies) / len(self.latencies)

    def record(self, ok: bool, ms: int | None):
        self.last_check = time.time()
        self.last_ms = ms
        self.ok = ok
        if ok and ms is not None:
            self.latencies.append(ms)
            self.fails = 0
        else:
            self.fails += 1


class ProxyHealthMonitor:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.stats: dict[str, ProxyStat] = {}
        self.enabled = True
        self.last_round: float = 0
        self.rounds = 0

    # ---------- 候选池 ----------
    def _candidates_file(self):
        from . import settings
        return settings.DATA_DIR / "proxy_candidates.txt"

    def load_candidates(self) -> list[str]:
        f = self._candidates_file()
        if not f.exists():
            return []
        out = []
        for line in f.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                p = proxyutil.normalize_proxy(line)
                if p and p not in out:
                    out.append(p)
        return out

    def save_candidates(self, proxies: list[str]) -> None:
        f = self._candidates_file()
        f.write_text("\n".join(proxies) + ("\n" if proxies else ""))

    def add_candidates(self, proxies: list[str]) -> int:
        cur = self.load_candidates()
        added = 0
        for raw in proxies:
            p = proxyutil.normalize_proxy(raw)
            if p and p not in cur:
                cur.append(p)
                added += 1
        self.save_candidates(cur)
        return added

    # ---------- 检测 ----------
    async def _check_one(self, proxy: str) -> tuple[str, bool, int | None]:
        try:
            r = await proxyutil.test_proxy(proxy, timeout=10.0)
            if not r.get("ok"):
                return (proxy, False, None)
            # MITM 检测暂时禁用（会导致轮次卡死，待改为独立低频任务）
            # st = self.stats.get(proxy)
            # if st and not st.mitm_checked:
            #     mitm = await self._check_mitm(proxy)
            #     st.mitm_checked = True
            #     st.mitm_bad = mitm
            #     if mitm:
            #         logs.err("proxyhealth", f"代理 {proxy} 检出 MITM，已拉黑")
            #         return (proxy, False, None)
            # elif st and st.mitm_bad:
            #     return (proxy, False, None)
            return (proxy, True, r.get("ms"))
        except Exception:  # noqa: BLE001
            return (proxy, False, None)

    async def _check_mitm(self, proxy: str) -> bool:
        """检测代理是否对 Z.AI 域名做 MITM。返回 True 表示有劫持。"""
        import httpx
        try:
            async with httpx.AsyncClient(proxy=proxy, timeout=10.0,
                                         trust_env=False) as client:
                # 只建连握手，不发业务请求
                r = await client.get("https://chat.z.ai/",
                                     follow_redirects=False)
                # 能拿到正常响应（2xx/3xx/4xx）说明证书链没问题
                return False
        except Exception as e:  # noqa: BLE001
            msg = str(e)
            # 自签证书 = MITM
            if "CERTIFICATE_VERIFY_FAILED" in msg or "self-signed" in msg:
                return True
            # 其他错误（超时、连接拒绝等）不算 MITM，交给普通失败计数
            return False

    # 每轮最多测多少个（轮询，避免候选太多时单轮超时）
    BATCH_SIZE = 60

    async def _round(self) -> None:
        candidates = self.load_candidates()
        if not candidates:
            return
        # 确保每个候选都有 stat
        for p in candidates:
            if p not in self.stats:
                self.stats[p] = ProxyStat(proxy=p)
        # 轮询：优先测最久没测过的
        ordered = sorted(candidates, key=lambda p: self.stats[p].last_check)
        batch = ordered[: self.BATCH_SIZE]
        # 并发检测；整轮限时 60s
        sem = asyncio.Semaphore(25)

        async def _guarded(proxy: str):
            async with sem:
                return await self._check_one(proxy)

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*[_guarded(p) for p in batch]),
                timeout=60.0,
            )
        except TimeoutError:
            logs.err("proxyhealth", "检测轮次超时（60s），跳过本轮")
            return
        for proxy, ok, ms in results:
            self.stats[proxy].record(ok, ms)
        self.last_round = time.time()
        self.rounds += 1
        # 检测完尝试优选替换
        self._rebalance()

    def _ranked(self) -> list[ProxyStat]:
        """按平均延迟排序（有数据的优先，无数据的排最后）。"""
        def key(s: ProxyStat):
            avg = s.avg_ms
            return (avg is None, avg if avg is not None else 0, s.fails)
        return sorted(self.stats.values(), key=key)

    def _rebalance(self) -> None:
        """优选逻辑：始终用平均延迟最低的 N 个（N=账号数）。"""
        try:
            accounts = store.list_accounts()
        except Exception:  # noqa: BLE001
            return
        if not accounts:
            return
        n = len(accounts)
        ranked = [s for s in self._ranked() if s.avg_ms is not None and s.fails < FAIL_THRESHOLD and not s.mitm_bad]
        if not ranked:
            return
        top = ranked[:n]
        top_set = {s.proxy for s in top}

        # 当前各账号的代理
        for acc in accounts:
            cur = (acc.proxy or "").strip()
            if not cur:
                # 没代理的账号：直接分配最优的未分配代理
                used = { (a.proxy or "").strip() for a in accounts if (a.proxy or "").strip() }
                for s in top:
                    if s.proxy not in used:
                        acc.proxy = s.proxy
                        acc.proxy_egress = None
                        store.update_account(acc)
                        logs.ok("proxyhealth", f"账号 {acc.id[:20]} 分配最优代理 {s.proxy}（{s.avg_ms:.0f}ms）")
                        break
                continue
            st = self.stats.get(cur)
            # 已分配代理失效或劣化：替换
            need_replace = False
            if st is None or st.fails >= FAIL_THRESHOLD:
                need_replace = True
            elif cur not in top_set and top:
                # 不在前 N：看最优未分配的是否明显更好
                used = { (a.proxy or "").strip() for a in accounts if (a.proxy or "").strip() }
                best_spare = next((s for s in top if s.proxy not in used), None)
                if best_spare and st.avg_ms and best_spare.avg_ms:
                    if st.avg_ms > best_spare.avg_ms * REPLACE_RATIO:
                        need_replace = True
            if need_replace:
                used = { (a.proxy or "").strip() for a in accounts if (a.proxy or "").strip() }
                used.discard(cur)
                nxt = next((s for s in top if s.proxy not in used), None)
                if nxt:
                    acc.proxy = nxt.proxy
                    acc.proxy_egress = None
                    store.update_account(acc)
                    logs.ok("proxyhealth", f"账号 {acc.id[:20]} 代理劣化替换 {cur} -> {nxt.proxy}（{nxt.avg_ms:.0f}ms）")
                # 无更优可用：不替换，保持原样

    # ---------- 生命周期 ----------
    async def _loop(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=5)
            return
        except TimeoutError:
            pass
        while not self._stop.is_set():
            if self.enabled:
                try:
                    await self._round()
                except Exception as err:  # noqa: BLE001
                    logs.err("proxyhealth", f"检测轮次出错: {err}")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=CHECK_INTERVAL)
            except TimeoutError:
                continue

    def start(self) -> None:
        if self._task is None:
            self._stop.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    # ---------- 状态查询 ----------
    def status(self) -> dict:
        ranked = self._ranked()
        try:
            n_accounts = len(store.list_accounts())
        except Exception:  # noqa: BLE001
            n_accounts = 0
        rows = []
        for i, s in enumerate(ranked):
            rows.append({
                "rank": i + 1,
                "proxy": s.proxy,
                "proxy_masked": proxyutil.mask_proxy(s.proxy),
                "avg_ms": round(s.avg_ms, 1) if s.avg_ms is not None else None,
                "last_ms": s.last_ms,
                "fails": s.fails,
                "ok": s.ok,
                "samples": len(s.latencies),
                "last_check": s.last_check,
                "in_top": (i + 1) <= n_accounts and s.avg_ms is not None,
            })
        return {
            "enabled": self.enabled,
            "interval": CHECK_INTERVAL,
            "rounds": self.rounds,
            "last_round": self.last_round,
            "n_accounts": n_accounts,
            "n_candidates": len(ranked),
            "rows": rows,
        }


monitor = ProxyHealthMonitor()
