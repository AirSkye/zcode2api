"""ClaimRoundManager 单测：门控过滤 + 轮间隔设置语义。

不跑真实 loop（睡眠周期），直接驱动 _round() 验证：
- 仅 allows_billing() 的 JWT 账号进入轮次（冷却/停用/风控禁用跳过）
- 有新套餐入账才触发额度刷新
"""

from __future__ import annotations

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

    async def fake_auto_claim(acc):
        visited.append(acc.id)
        return [{"account_id": acc.id, "ok": acc.id == "ok-1"}] if acc.id == "ok-1" else []

    async def fake_refresh(batch):
        refreshed.extend(a.id for a in batch)
        return {"ok": len(batch), "fail": 0}

    import app.claim as claim_module

    class _FakeStore:
        @staticmethod
        def list_accounts(_provider):
            return accounts

        @staticmethod
        def find(_provider, aid):
            return next(a for a in accounts if a.id == aid)

    monkeypatch.setattr(claim_module, "auto_claim_all_plans", fake_auto_claim)
    monkeypatch.setattr("app.quota.refresh_accounts", fake_refresh)
    monkeypatch.setattr("app.store.store", _FakeStore())

    manager = ClaimRoundManager()
    await manager._round()

    assert visited == ["ok-1", "ok-2"], "冷却/停用账号必须先被 allows_billing 过滤"
    assert refreshed == ["ok-1"], "仅真正领到套餐的账号触发额度刷新"


@pytest.mark.asyncio
async def test_round_swallows_single_account_error(monkeypatch):
    accounts = [_FakeAccount("boom", billing=True), _FakeAccount("fine", billing=True)]
    visited: list[str] = []

    async def fake_auto_claim(acc):
        visited.append(acc.id)
        if acc.id == "boom":
            raise RuntimeError("captcha exploded")
        return [{"account_id": acc.id, "ok": True}]

    async def fake_refresh(batch):
        return {"ok": len(batch), "fail": 0}

    import app.claim as claim_module

    class _FakeStore:
        @staticmethod
        def list_accounts(_provider):
            return accounts

        @staticmethod
        def find(_provider, aid):
            return next(a for a in accounts if a.id == aid)

    monkeypatch.setattr(claim_module, "auto_claim_all_plans", fake_auto_claim)
    monkeypatch.setattr("app.quota.refresh_accounts", fake_refresh)
    monkeypatch.setattr("app.store.store", _FakeStore())

    manager = ClaimRoundManager()
    await manager._round()  # 不应抛出
    assert visited == ["boom", "fine"], "单账号异常不中断整轮"
