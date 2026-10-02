"""指纹换发端点（POST /admin/api/accounts/{id}/fingerprint/rotate）回归。

覆盖 2.6.8 前的端点测试空白：换发 = 新 SKU 档案 + 新 device_mid +
清 installed_at（重跑安装序由后台任务完成）。
"""

from __future__ import annotations

import pytest

from app.fingerprint import profile_for

ADMIN_AUTH = {"Authorization": "Bearer zcode"}  # 默认后台密钥

_RISK_JWT = "hR.eyJzdWIiOiJyIn0.sig"


@pytest.mark.integration
class TestFingerprintRotateEndpoint:
    async def test_rotate_gives_new_identity_and_clears_install(self, gateway_client, fresh_app):
        client, _mock = gateway_client
        from tests.conftest import seed_account

        acc = seed_account(fresh_app, _RISK_JWT, name="a-fp")
        acc.installed_at = 12345.0
        fresh_app.update_account(acc)
        old_mid = profile_for(acc).device_mid

        res = await client.post(
            f"/admin/api/accounts/{acc.id}/fingerprint/rotate", headers=ADMIN_AUTH
        )
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is True

        after = fresh_app.find("zai", acc.id)
        new_mid = profile_for(after).device_mid
        assert new_mid != old_mid
        assert after.installed_at is None  # 清安装标记 → 后台重跑装序

    async def test_rotate_unknown_account_404(self, gateway_client):
        client, _mock = gateway_client
        res = await client.post(
            "/admin/api/accounts/nonexistent/fingerprint/rotate", headers=ADMIN_AUTH
        )
        assert res.status_code == 404
