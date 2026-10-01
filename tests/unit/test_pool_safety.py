"""全量 review 回归：删号写回、纯 Key 风控、设置脱敏。"""

from __future__ import annotations

from app.models import Account, Status
from app.store import Store


class TestDeletedAccountNotResurrected:
    def test_update_account_refuses_deleted_id(self, fresh_app):
        acc = fresh_app.add_account("zai", "a", "jwt.token.a")
        aid = acc.id
        assert fresh_app.remove_account("zai", aid)
        assert fresh_app.find("zai", aid) is None

        acc.status = Status.EXHAUSTED
        acc.last_error = "后台任务写回"
        fresh_app.update_account(acc)

        assert fresh_app.find("zai", aid) is None
        reloaded = Store()
        assert reloaded.find("zai", aid) is None
        assert [a.id for a in reloaded.list_accounts("zai")] == []


class TestPureApiKeyRiskCooldown:
    def test_pure_apikey_not_selectable_during_risk_cooldown(self):
        acc = Account.create("zai", "t", "sk-pure-api-key")
        assert acc.mode == "apiKey"
        assert acc.has_apikey_fallback() is False
        acc.risk_penalty(base=900.0, cap=86400.0, ban_strikes=4)
        assert acc.status == Status.COOLING
        assert acc.risk_strikes == 1
        assert acc.enabled is True
        assert acc.is_selectable() is False
        assert acc.cooling_until is not None

    def test_jwt_with_key_cooldown_not_selectable(self):
        acc = Account.create("zai", "t", "a.b.c")
        acc.api_key = "sk-fallback"
        acc.risk_penalty(base=900.0, cap=86400.0, ban_strikes=4)
        assert acc.has_apikey_fallback() is True
        # 冷却期整号不可选（若可选，网关会重打 Plan 通道，风控计数持续累加）；
        # 同请求内的 Key 回退由 force_fallback 保证，不依赖 is_selectable。
        assert acc.is_selectable() is False
        assert acc.allows_billing() is False

    def test_risk_cooldown_escalates_to_disabled_at_4th_strike(self):
        acc = Account.create("zai", "t", "jwt.token")
        for strike in range(1, 5):
            acc.risk_penalty(base=900.0, cap=86400.0, ban_strikes=4)
            assert acc.risk_strikes == strike
        assert acc.status == Status.DISABLED
        assert acc.is_selectable() is False

    def test_pure_apikey_invalid_not_selectable(self):
        acc = Account.create("zai", "t", "sk-dead-key")
        acc.status = Status.INVALID
        assert acc.is_selectable() is False
