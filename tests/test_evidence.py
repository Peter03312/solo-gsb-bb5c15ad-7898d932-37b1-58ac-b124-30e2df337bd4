"""批准证据包：导出、边界冻结、离线复核与不可复核历史的测试。"""
import io
import zipfile

import pytest

from tests.helpers import make_ca, make_cert, make_crl, pem

from app import evidence

DOMAIN = "svc.example.com"
EVAL = ("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")


@pytest.fixture()
def root(client):
    ca, ca_key = make_ca()
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    return ca, ca_key


def _approve_gap_free(client, ca, ca_key, *, with_snapshot=False, crl_pem=None):
    cur = _import_leaf(client, ca, ca_key, na="2026-08-01", label="cur")
    nxt = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01", label="next")
    _window(client, cur, "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current")
    _window(client, nxt, "2026-07-01T00:00:00Z", "2027-01-01T00:00:00Z", "planned")
    body = {"domain": DOMAIN, "eval_start": EVAL[0], "eval_end": EVAL[1]}
    if with_snapshot:
        r = client.post("/api/v1/crl-snapshots", json={"version": "s1", "pem": crl_pem})
        assert r.status_code == 201, r.text
        body["crl_snapshot_version"] = "s1"
    r = client.post("/api/v1/plans", json=body)
    assert r.status_code == 201, r.text
    plan_id = r.json()["plan"]["id"]
    r = client.post(f"/api/v1/plans/{plan_id}/approve")
    assert r.status_code == 200, r.text
    approval_id = r.json()["approval"]["id"]
    return plan_id, approval_id, [cur, nxt]


def _import_leaf(client, ca, ca_key, domain=DOMAIN, nb="2026-01-01", na="2027-01-01",
                 sans=None, label=None):
    leaf, _ = make_cert(ca, ca_key, domain, nb=nb, na=na,
                        sans=sans if sans is not None else [domain])
    r = client.post("/api/v1/certificates", json={"pem": pem(leaf), "label": label})
    assert r.status_code == 201, r.text
    return r.json()["fingerprint_sha256"]


def _window(client, fp, start, end, role="current", domain=DOMAIN):
    r = client.post("/api/v1/service-windows", json={
        "domain": domain, "certificate_fingerprint": fp, "role": role,
        "start": start, "end": end,
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _evidence_json(client, approval_id):
    r = client.get(f"/api/v1/approvals/{approval_id}/evidence?format=json")
    assert r.status_code == 200, r.text
    return r.json()


def _verify(client, package):
    return client.post("/api/v1/evidence/verify", json=package)


# ---------------------------------------------------------------------------
# 导出与一致复核
# ---------------------------------------------------------------------------

def test_evidence_package_contents_and_consistent_verify(client, root):
    ca, ca_key = root
    plan_id, approval_id, fps = _approve_gap_free(client, ca, ca_key)

    pkg = _evidence_json(client, approval_id)
    assert pkg["format"] == evidence.EVIDENCE_PACKAGE_FORMAT
    assert pkg["domain"] == DOMAIN
    assert (pkg["eval_start"], pkg["eval_end"]) == (
        "2026-01-01T00:00:00.000Z", "2027-01-01T00:00:00.000Z")
    assert pkg["approval"] == {"approval_id": approval_id, "plan_id": plan_id,
                               "created_at": pkg["approval"]["created_at"]}
    decision = pkg["decision"]
    assert decision["trust_root_version"] == "v1"
    assert decision["crl_snapshot_version"] is None
    assert sorted(decision["cert_fingerprints"]) == sorted(fps)
    assert decision["verdict"]["has_gaps"] is False
    # 实际参与评估的窗口集合随包冻结
    assert len(pkg["windows"]) == 2
    assert sorted(w["role"] for w in pkg["windows"]) == ["current", "planned"]
    # 材料：信任根 + 两张证书链，无快照
    assert pkg["materials"]["trust_root"]["version"] == "v1"
    assert pkg["materials"]["crl_snapshot"] is None
    assert sorted(pkg["materials"]["certificates"]) == sorted(fps)

    r = _verify(client, pkg)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"] == "consistent"
    assert body["differences"] == []
    assert body["recomputed"]["has_gaps"] is False


def test_evidence_zip_roundtrip(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    r = client.get(f"/api/v1/approvals/{approval_id}/evidence")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert "attachment" in r.headers["content-disposition"]
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert any(n.endswith("/manifest.json") for n in names)
    assert any(n.endswith(".pem") for n in names)
    # ZIP 直接上传复核
    r2 = client.post("/api/v1/evidence/verify", content=r.content,
                     headers={"content-type": "application/zip"})
    assert r2.status_code == 200, r2.text
    assert r2.json()["result"] == "consistent"


def test_evidence_with_crl_snapshot_consistent(client, root):
    ca, ca_key = root
    crl_pem = make_crl(ca, ca_key, "2025-12-01", "2027-02-01", revoked=[], number=1)
    _, approval_id, _ = _approve_gap_free(
        client, ca, ca_key, with_snapshot=True, crl_pem=crl_pem)
    pkg = _evidence_json(client, approval_id)
    assert pkg["materials"]["crl_snapshot"]["version"] == "s1"
    r = _verify(client, pkg)
    assert r.status_code == 200, r.text
    assert r.json()["result"] == "consistent"
    assert r.json()["recomputed"]["crl_snapshot_version"] == "s1"


def test_unknown_approval_404(client, root):
    r = client.get("/api/v1/approvals/999/evidence?format=json")
    assert r.status_code == 404


def test_bad_format_query(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    r = client.get(f"/api/v1/approvals/{approval_id}/evidence?format=tar")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# 同一一致性边界冻结：后续窗口删除 / 根或快照切换 / 再次批准不改写旧包
# ---------------------------------------------------------------------------

def test_old_package_not_affected_by_later_window_changes(client, root):
    ca, ca_key = root
    plan_id, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    before = _evidence_json(client, approval_id)

    # 删除一个窗口并新增窗口 → 计划转待复核，随后重新批准
    wins = client.get(f"/api/v1/service-windows?domain={DOMAIN}").json()["items"]
    cur_win = next(w for w in wins if w["role"] == "current")
    client.delete(f"/api/v1/service-windows/{cur_win['id']}")
    new_fp = _import_leaf(client, ca, ca_key, nb="2025-12-01", na="2026-09-01",
                          label="replacement")
    _window(client, new_fp, "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current")
    assert client.post(f"/api/v1/plans/{plan_id}/evaluate").json()["has_gaps"] is False
    client.post(f"/api/v1/plans/{plan_id}/approve")

    after = _evidence_json(client, approval_id)
    # 旧证据包内容（窗口集合、判定、材料）逐字节不变
    assert after == before
    assert _verify(client, after).json()["result"] == "consistent"


def test_old_package_not_affected_by_root_switch_and_reapproval(client, root):
    ca, ca_key = root
    plan_id, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    before = _evidence_json(client, approval_id)

    ca2, _ = make_ca("Root V2")
    client.post("/api/v1/trust-roots", json={"version": "v2", "pem": pem(ca2)})
    client.post("/api/v1/trust-roots/v2/activate")
    client.post(f"/api/v1/plans/{plan_id}/evaluate", json={"trust_root_version": "v1"})
    client.post(f"/api/v1/plans/{plan_id}/approve")

    after = _evidence_json(client, approval_id)
    assert after == before
    # 复核只用包内冻结的 v1 根，与当前在用 v2 无关
    assert _verify(client, after).json()["result"] == "consistent"


def test_superseded_approval_still_exportable_and_consistent(client, root):
    ca, ca_key = root
    plan_id, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    # 触发待复核后再批准 → 新批准，旧批准 superseded 但仍可导出
    fp2 = _import_leaf(client, ca, ca_key, nb="2026-06-01", na="2027-06-01", label="x")
    _window(client, fp2, "2027-01-01T00:00:00Z", "2027-06-01T00:00:00Z", "planned")
    client.post(f"/api/v1/plans/{plan_id}/evaluate")
    r = client.post(f"/api/v1/plans/{plan_id}/approve")
    new_approval = r.json()["approval"]["id"]
    assert new_approval != approval_id
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    old = next(a for a in approvals if a["id"] == approval_id)
    assert old["superseded"] is True and old["evidence_reviewable"] is True
    pkg = _evidence_json(client, approval_id)
    assert _verify(client, pkg).json()["result"] == "consistent"


def test_approve_freezes_windows_at_boundary_not_current(client, root):
    """批准时窗口集合与判定同一事务冻结；批准后删窗不改写，且不能用当前窗补齐。"""
    ca, ca_key = root
    plan_id, approval_id, fps = _approve_gap_free(client, ca, ca_key)
    wins = client.get(f"/api/v1/service-windows?domain={DOMAIN}").json()["items"]
    # 当前库窗口集合发生变化
    client.delete(f"/api/v1/service-windows/{wins[0]['id']}")
    pkg = _evidence_json(client, approval_id)
    # 包内仍是批准时的 2 个窗口，而非当前的 1 个
    assert len(pkg["windows"]) == 2
    current_wins = client.get(f"/api/v1/service-windows?domain={DOMAIN}").json()["items"]
    assert len(current_wins) == 1
    assert _verify(client, pkg).json()["result"] == "consistent"


# ---------------------------------------------------------------------------
# 离线复核：不一致（给出差异原因）
# ---------------------------------------------------------------------------

def test_verify_detects_tampered_frozen_verdict_gap(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["decision"]["verdict"]["has_gaps"] = True
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == "inconsistent"
    paths = [d["path"] for d in body["differences"]]
    assert "verdict.has_gaps" in paths


def test_verify_detects_window_tampering(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    # 改窗口区间制造断档
    pkg["windows"][0]["end"] = "2026-02-01T00:00:00.000Z"
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    body = _verify(client, pkg).json()
    assert body["result"] == "inconsistent"
    diff_paths = [d["path"] for d in body["differences"]]
    assert any(p.startswith("verdict.gaps") or p == "verdict.has_gaps" for p in diff_paths)


# ---------------------------------------------------------------------------
# 可解释错误：缺项 / 指纹不符 / 版本不符 / 非法时间 / 非法结构
# ---------------------------------------------------------------------------

def test_manifest_tamper_without_rehash_is_integrity_error(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["decision"]["verdict"]["has_gaps"] = True  # 不重算清单哈希
    r = _verify(client, pkg)
    assert r.status_code == 422
    assert r.json()["code"] == "PACKAGE_INTEGRITY_ERROR"


def test_missing_windows_error(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["windows"] = []
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "MISSING_WINDOWS"


def test_missing_certificate_material_error(client, root):
    ca, ca_key = root
    _, approval_id, fps = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    del pkg["materials"]["certificates"][fps[0]]
    # decision 指纹集合也同步删掉，使检查推进到材料缺项
    pkg["decision"]["cert_fingerprints"] = [fps[1]]
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "MISSING_CERTIFICATE"


def test_fingerprint_mismatch_error(client, root):
    ca, ca_key = root
    _, approval_id, fps = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    # 用另一张证书的 PEM 顶替该指纹
    other, _ = make_cert(ca, ca_key, "other.example.com", sans=["other.example.com"])
    pkg["materials"]["certificates"][fps[0]]["chain_pem"] = pem(other)
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "FINGERPRINT_MISMATCH"


def test_pem_hash_mismatch_error(client, root):
    ca, ca_key = root
    _, approval_id, fps = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["materials"]["certificates"][fps[0]]["pem_sha256"] = "0" * 64
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "FINGERPRINT_MISMATCH"


def test_trust_root_version_mismatch_error(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["materials"]["trust_root"]["version"] = "v9"
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "VERSION_MISMATCH"


def test_snapshot_version_mismatch_error(client, root):
    ca, ca_key = root
    crl_pem = make_crl(ca, ca_key, "2025-12-01", "2027-02-01", number=1)
    _, approval_id, _ = _approve_gap_free(
        client, ca, ca_key, with_snapshot=True, crl_pem=crl_pem)
    pkg = _evidence_json(client, approval_id)
    pkg["decision"]["crl_snapshot_version"] = "other-snapshot"
    pkg["decision"]["verdict"]["crl_snapshot_version"] = "other-snapshot"
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "VERSION_MISMATCH"


def test_missing_selected_snapshot_error(client, root):
    ca, ca_key = root
    crl_pem = make_crl(ca, ca_key, "2025-12-01", "2027-02-01", number=1)
    _, approval_id, _ = _approve_gap_free(
        client, ca, ca_key, with_snapshot=True, crl_pem=crl_pem)
    pkg = _evidence_json(client, approval_id)
    pkg["materials"]["crl_snapshot"] = None
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "MISSING_CRL_SNAPSHOT"


def test_invalid_interval_error(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["eval_start"], pkg["eval_end"] = pkg["eval_end"], pkg["eval_start"]
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "INVALID_TIME"


def test_naive_timestamp_error(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["eval_start"] = "2026-01-01T00:00:00"  # 无时区
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "INVALID_TIME"


def test_invalid_window_time_error(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["windows"][0]["end"] = "2025-01-01T00:00:00.000Z"  # end < start
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "INVALID_TIME"


def test_unsupported_format_error(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    pkg["format"] = "something-else/9"
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "UNSUPPORTED_FORMAT"


def test_garbage_payload_error(client, root):
    r = client.post("/api/v1/evidence/verify", content=b"not-json-or-zip",
                    headers={"content-type": "application/json"})
    assert r.status_code == 422 and r.json()["code"] == "INVALID_PACKAGE"
    r = client.post("/api/v1/evidence/verify", content=b"PK\x03\x04garbage",
                    headers={"content-type": "application/zip"})
    assert r.status_code == 422 and r.json()["code"] == "INVALID_PACKAGE"


def test_missing_field_error(client, root):
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)
    del pkg["decision"]["verdict"]
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    assert r.status_code == 422 and r.json()["code"] == "MISSING_FIELD"


def test_malformed_crl_time_error(client, root):
    ca, ca_key = root
    crl_pem = make_crl(ca, ca_key, "2025-12-01", "2027-02-01", number=1)
    _, approval_id, _ = _approve_gap_free(
        client, ca, ca_key, with_snapshot=True, crl_pem=crl_pem)
    pkg = _evidence_json(client, approval_id)
    # 非法 CRL（thisUpdate 晚于 nextUpdate）只能通过底层 DER 手术构造，
    # 这里直接用 helpers 的篡改器。
    from tests.helpers import tamper_crl_pem
    bad = tamper_crl_pem(pkg["materials"]["crl_snapshot"]["pem"], "swap_times")
    pkg["materials"]["crl_snapshot"]["pem"] = bad
    pkg["materials"]["crl_snapshot"]["pem_sha256"] = evidence.sha256_text(bad)
    pkg["manifest_sha256"] = evidence._manifest_hash(pkg)
    r = _verify(client, pkg)
    # 签名失效或时间非法：二者必居其一，都必须是可解释错误而非静默放行
    assert r.status_code == 422
    assert r.json()["code"] in ("INVALID_TIME", "MALFORMED_CRL")


# ---------------------------------------------------------------------------
# 既有批准：缺少可还原窗口依据 → 不可复核，不能按当前窗口补齐
# ---------------------------------------------------------------------------

def test_legacy_approval_without_frozen_windows_is_not_reviewable(client, root, monkeypatch):
    """模拟历史批准（frozen_windows_json 为 NULL）：导出明确返回不可复核。"""
    from app import db
    ca, ca_key = root
    plan_id, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    # 直接把冻结依据抹成 NULL，模拟迁移前的既有批准
    with db.connect() as conn:
        conn.execute(
            "UPDATE approvals SET frozen_windows_json = NULL,"
            " frozen_materials_json = NULL WHERE id = ?",
            (approval_id,),
        )
    r = client.get(f"/api/v1/approvals/{approval_id}/evidence")
    assert r.status_code == 422
    assert "not reviewable" in r.json()["detail"]

    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert approvals[0]["evidence_reviewable"] is False

    # 当前窗口仍然存在，但绝不用于补齐：没有任何途径为该批准生成证据包
    wins = client.get(f"/api/v1/service-windows?domain={DOMAIN}").json()["items"]
    assert len(wins) == 2
    assert client.get(f"/api/v1/approvals/{approval_id}/evidence?format=json").status_code == 422


# ---------------------------------------------------------------------------
# 复核不触碰当前业务数据
# ---------------------------------------------------------------------------

def test_verify_does_not_read_or_modify_business_data(client, root, tmp_path, monkeypatch):
    """复核端点即使在业务库缺失/空库时也能工作（只用包内材料）。"""
    from app import db as db_mod
    ca, ca_key = root
    _, approval_id, _ = _approve_gap_free(client, ca, ca_key)
    pkg = _evidence_json(client, approval_id)

    # 把 DB_PATH 指向一个从未初始化的空库；复核不应触库
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "nonexistent.db"))
    r = _verify(client, pkg)
    assert r.status_code == 200, r.text
    assert r.json()["result"] == "consistent"
    import os
    assert not os.path.exists(db_mod.DB_PATH)  # 复核没有创建/初始化业务库


def test_approve_boundary_rejects_stale_gap_free_assumption(client, root):
    """计划当前有断档时批准：边界重算判 409，即使最新评估陈旧地显示无断档。"""
    ca, ca_key = root
    fp = _import_leaf(client, ca, ca_key)
    _window(client, fp, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    r = client.post("/api/v1/plans", json={"domain": DOMAIN, "eval_start": EVAL[0],
                                           "eval_end": EVAL[1]})
    plan_id = r.json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200
    # 待复核 + 制造断档（删除唯一窗口且无接替），不重评直接批准 → 必须 409
    wins = client.get(f"/api/v1/service-windows?domain={DOMAIN}").json()["items"]
    client.delete(f"/api/v1/service-windows/{wins[0]['id']}")
    r = client.post(f"/api/v1/plans/{plan_id}/approve")
    assert r.status_code == 409 and "gap" in r.json()["detail"]
