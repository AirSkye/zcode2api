"""ClaimRoundManager 单测：门控过滤、1005 退避、停服截止。

不跑真实 loop（睡眠周期），直接驱动 _round() / stop() 验证：
- 仅 allows_billing() 的 JWT 账号进入轮次（冷却/停用/风控禁用跳过）
- 有新套餐入账才触发额度刷新
- 1005+next_at 的套餐在等待期跳过领取（preview 照常、不耗 captcha），
  next_at 过后恢复重试，成功/其余失败清除退避
- stop() 对轮内长尾有截止并 cancel，停服不被卡住
"""

from __future__ import annotations

import asyncio
import time

import pytest

from app.claim import ClaimRoundManager


class _FakeAccount:
    def __init__(self, aid: str, *, billing: bool):
        self.id = aid
        self.name = f"acct-{aid}"
        self.mode = "jwt"
        self._billing = billing

    def allows_billing(self) -> bool:
        return self._billing


def _fake_store(accounts):
    class _FakeStore:
        @staticmethod
        def list_accounts(_provider):
            return accounts

        @staticmethod
        def find(_provider, aid):
            return next(a for a in accounts if a.id == aid)

    return _FakeStore()


@pytest.mark.asyncio
async def test_round_only_visits_billing_allowed_accounts(monkeypatch):
    visited: list[str] = []
    refreshed: list[str] = []
    accounts = [
        _FakeAccount("ok-1", billing=True),
        _FakeAccount("cooling", billing=False),
        _FakeAccount("banned", billing=False),
        _FakeAccount("ok-2", billing=True),
    ]

    async def fake_auto_claim(acc, *, skip_plan_ids=None):
        visited.append(acc.id)
        return [{"account_id": acc.id, "ok": acc.id == "ok-1"}] if acc.id == "ok-1" else []

    async def fake_refresh(batch):
        refreshed.extend(a.id for a in batch)
        return {"ok": len(batch), "fail": 0}

    import app.claim as claim_module

    monkeypatch.setattr(claim_module, "auto_claim_all_plans", fake_auto_claim)
    monkeypatch.setattr("app.quota.refresh_accounts", fake_refresh)
    monkeypatch.setattr("app.store.store", _fake_store(accounts))

    manager = ClaimRoundManager()
    await manager._round()

    assert visited == ["ok-1", "ok-2"], "冷却/停用账号必须先被 allows_billing 过滤"
    assert refreshed == ["ok-1"], "仅真正领到套餐的账号触发额度刷新"


@pytest.mark.asyncio
async def test_round_swallows_single_account_error(monkeypatch):
    accounts = [_FakeAccount("boom", billing=True), _FakeAccount("fine", billing=True)]
    visited: list[str] = []

    async def fake_auto_claim(acc, *, skip_plan_ids=None):
        visited.append(acc.id)
        if acc.id == "boom":
            raise RuntimeError("captcha exploded")
        return [{"account_id": acc.id, "ok": True}]

    async def fake_refresh(batch):
        return {"ok": len(batch), "fail": 0}

    import app.claim as claim_module

    monkeypatch.setattr(claim_module, "auto_claim_all_plans", fake_auto_claim)
    monkeypatch.setattr("app.quota.refresh_accounts", fake_refresh)
    monkeypatch.setattr("app.store.store", _fake_store(accounts))

    manager = ClaimRoundManager()
    await manager._round()  # 不应抛出
    assert visited == ["boom", "fine"], "单账号异常不中断整轮"


@pytest.mark.asyncio
async def test_round_1005_next_at_holds_then_clears_on_success(monkeypatch):
    """1005 退避全周期：名额等待期跳过领取 → next_at 过后恢复 → 成功清除退避。"""
    accounts = [_FakeAccount("a1", billing=True)]
    skip_sets: list[set[str]] = []
    refreshed: list[str] = []
    quota_full = {"now": True}

    async def fake_auto_claim(acc, *, skip_plan_ids=None):
        skip = set(skip_plan_ids or set())
        skip_sets.append(skip)
        if "p-quota" in skip:
            return []  # 真实行为：跳过的套餐不产生 outcome
        if quota_full["now"]:
            return [{"account_id": acc.id, "account_name": acc.name, "ok": False,
                     "plan_id": "p-quota", "message": "今日领取名额已用完",
                     "code": 1005, "next_at": round((time.time() + 3600) * 1000)}]
        return [{"account_id": acc.id, "account_name": acc.name, "ok": True,
                 "plan_id": "p-quota", "plan_name": "Quota Plan", "grants": []}]

    async def fake_refresh(batch):
        refreshed.extend(a.id for a in batch)
        return {"ok": len(batch), "fail": 0}

    import app.claim as claim_module

    monkeypatch.setattr(claim_module, "auto_claim_all_plans", fake_auto_claim)
    monkeypatch.setattr("app.quota.refresh_accounts", fake_refresh)
    monkeypatch.setattr("app.store.store", _fake_store(accounts))

    manager = ClaimRoundManager()
    await manager._round()  # 首轮 1005 → 记忆退避
    assert skip_sets[0] == set()
    assert "p-quota" in manager._claim_holds["a1"]
    assert refreshed == [], "1005 失败轮不得触发额度刷新"

    await manager._round()  # 等待期：p-quota 被跳过（preview 照常发现）
    assert skip_sets[1] == {"p-quota"}, "名额等待期必须跳过 claim（省 captcha）"

    # next_at 过后：退避解除，恢复重试并成功 → 退避清除
    manager._claim_holds["a1"]["p-quota"] = round((time.time() - 1) * 1000)
    quota_full["now"] = False
    await manager._round()
    assert skip_sets[2] == set(), "next_at 过后必须恢复重试"
    assert refreshed == ["a1"], "领到套餐立即刷新额度"
    assert manager._claim_holds == {}, "成功领取必须清除退避"


@pytest.mark.asyncio
async def test_round_1005_without_next_at_no_hold(monkeypatch):
    """1005 不带 next_at 时无退避依据，下一轮照常重试（不记忆）。"""
    accounts = [_FakeAccount("a1", billing=True)]
    skip_sets: list[set[str]] = []

    async def fake_auto_claim(acc, *, skip_plan_ids=None):
        skip_sets.append(set(skip_plan_ids or set()))
        return [{"account_id": acc.id, "account_name": acc.name, "ok": False,
                 "plan_id": "p-x", "message": "今日领取名额已用完", "code": 1005}]

    async def fake_refresh(batch):
        return {"ok": len(batch), "fail": 0}

    import app.claim as claim_module

    monkeypatch.setattr(claim_module, "auto_claim_all_plans", fake_auto_claim)
    monkeypatch.setattr("app.quota.refresh_accounts", fake_refresh)
    monkeypatch.setattr("app.store.store", _fake_store(accounts))

    manager = ClaimRoundManager()
    await manager._round()
    await manager._round()
    assert skip_sets == [set(), set()], "无 next_at 不建立退避"
    assert manager._claim_holds == {}


@pytest.mark.asyncio
async def test_stop_cancels_long_tail_round(monkeypatch):
    """停服截止：轮内长尾（验证码求解重试可达分钟级）超时即 cancel。"""
    manager = ClaimRoundManager()

    async def hang(self):
        await asyncio.sleep(60)

    monkeypatch.setattr(ClaimRoundManager, "_round", hang)
    monkeypatch.setattr(ClaimRoundManager, "STOP_GRACE_SECONDS", 0.2)
    manager._task = asyncio.create_task(manager._round())
    await asyncio.sleep(0.05)  # 确保已进入长尾
    task = manager._task

    t0 = time.monotonic()
    await manager.stop()
    assert time.monotonic() - t0 < 5, "stop 必须在截止内返回，不得等完 60s 长尾"
    assert task.cancelled(), "超时后轮任务必须被 cancel"
    assert manager._task is None


@pytest.mark.asyncio
async def test_auto_claim_generic_exception_appends_outcome(monkeypatch):
    """非 ClaimError 异常（如验证码求解失败）也产生失败 outcome，不再只有日志。"""
    import app.claim as claim_module
    from app.models import Account

    acc = Account.create("zai", "boom", "h1.eyJzdWIiOiJhIn0.sig")

    async def fake_activation(a):
        return None

    async def fake_preview(a):
        return [{"plan_id": "p-1", "name": "P", "grants": [], "priority": 0}]

    async def fake_claim(a, plan_id=None):
        raise RuntimeError("solver exploded")

    monkeypatch.setattr(claim_module, "report_activation_events", fake_activation)
    monkeypatch.setattr(claim_module, "preview_plans", fake_preview)
    monkeypatch.setattr(claim_module, "claim", fake_claim)

    outcomes = await claim_module.auto_claim_all_plans(acc)
    assert outcomes == [{"account_id": acc.id, "account_name": acc.name,
                         "ok": False, "plan_id": "p-1", "message": "solver exploded"}]


@pytest.mark.asyncio
async def test_auto_claim_skip_plan_ids_skips_claim_only(monkeypatch):
    """skip_plan_ids 只跳过领取：新套餐照常领，被跳过的不打 claim。"""
    import app.claim as claim_module
    from app.models import Account

    acc = Account.create("zai", "skip", "h1.eyJzdWIiOiJhIn0.sig")
    claimed: list[str] = []

    async def fake_activation(a):
        return None

    async def fake_preview(a):
        return [
            {"plan_id": "p-held", "name": "Held", "grants": [], "priority": 1},
            {"plan_id": "p-new", "name": "New", "grants": [], "priority": 0},
        ]

    async def fake_claim(a, plan_id=None):
        claimed.append(plan_id)
        return {"plan_id": plan_id, "plan_name": plan_id, "grants": [],
                "starts_at": None, "ends_at": None, "server_time": None}

    monkeypatch.setattr(claim_module, "report_activation_events", fake_activation)
    monkeypatch.setattr(claim_module, "preview_plans", fake_preview)
    monkeypatch.setattr(claim_module, "claim", fake_claim)

    outcomes = await claim_module.auto_claim_all_plans(acc, skip_plan_ids={"p-held"})
    assert claimed == ["p-new"], "退避中的套餐不得打 claim"
    assert [o["plan_id"] for o in outcomes] == ["p-new"]
    assert all(o["ok"] for o in outcomes)
