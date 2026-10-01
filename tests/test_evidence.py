"""运维审计证据包：批准冻结、证据包导出与仅用包内材料的离线复核。"""
import hashlib
import io
import json
import zipfile

import pytest

from tests.helpers import make_ca, make_cert, make_crl, pem

DOMAIN = "audit.example.com"
EVAL_START = "2026-01-01T00:00:00Z"
EVAL_END = "2027-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

@pytest.fixture()
def root(client):
    ca, ca_key = make_ca("Audit Root CA")
    client.post("/api/v1/trust-roots", json={"version": "rv1", "pem": pem(ca)})
    return ca, ca_key


def _leaf(client, ca, ca_key, *, domain=DOMAIN, nb="2026-01-01", na="2027-01-01",
          role="current", start=EVAL_START, end=None, issuer_cert=None,
          issuer_key=None, sans=None):
    issuer_cert = issuer_cert or ca
    issuer_key = issuer_key or ca_key
    leaf, _ = make_cert(issuer_cert, issuer_key, domain, nb=nb, na=na,
                        sans=sans if sans is not None else [domain])
    chain = pem(leaf) if issuer_cert is ca else pem(leaf, issuer_cert)
    fp = client.post("/api/v1/certificates", json={"pem": chain}).json()[
        "fingerprint_sha256"
    ]
    r = client.post("/api/v1/service-windows", json={
        "domain": domain, "certificate_fingerprint": fp, "role": role,
        "start": start, "end": end or EVAL_END,
    })
    assert r.status_code == 201, r.text
    return fp


def _approve_gap_free(client, domain=DOMAIN, snapshot=None,
                      start=EVAL_START, end=EVAL_END):
    body = {"domain": domain, "eval_start": start, "eval_end": end}
    if snapshot is not None:
        body["crl_snapshot_version"] = snapshot
    r = client.post("/api/v1/plans", json=body)
    assert r.status_code == 201, r.text
    plan_id = r.json()["plan"]["id"]
    assert r.json()["evaluation"]["has_gaps"] is False
    r = client.post(f"/api/v1/plans/{plan_id}/approve")
    assert r.status_code == 200, r.text
    return plan_id, r.json()["approval"]["id"]


def _download(client, plan_id, approval_id):
    r = client.get(f"/api/v1/plans/{plan_id}/approvals/{approval_id}/evidence")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    return r.content


def _verify(client, payload):
    return client.post(
        "/api/v1/evidence/verify",
        files={"package": ("evidence.zip", payload, "application/zip")},
    )


def _members(payload):
    zf = zipfile.ZipFile(io.BytesIO(payload))
    return {n: zf.read(n) for n in zf.namelist()}


def _repack(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
    return buf.getvalue()


def _put_json(files, name, obj):
    files[name] = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _redigest(files, manifest, path):
    for fe in manifest["files"]:
        if fe["path"] == path:
            fe["sha256"] = hashlib.sha256(files[path]).hexdigest()
    _put_json(files, "manifest.json", manifest)


# ---------------------------------------------------------------------------
# 批准冻结与导出
# ---------------------------------------------------------------------------

def test_approval_freezes_windows_at_consistency_boundary(client, root):
    ca, ca_key = root
    fp = _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    approval = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"][-1]
    assert approval["replayable"] is True
    assert approval["frozen_windows"] == [
        {
            "window_id": approval["frozen_windows"][0]["window_id"],
            "certificate_fingerprint": fp,
            "role": "current",
            "start": "2026-01-01T00:00:00.000Z",
            "end": "2027-01-01T00:00:00.000Z",
        }
    ]
    assert approval["cert_fingerprints"] == [fp]

    payload = _download(client, plan_id, approval_id)
    files = _members(payload)
    assert f"materials/certificates/{fp}.pem" in files
    assert "materials/trust-root.pem" in files
    assert "materials/crl-snapshot.pem" not in files  # 未选择快照 → 不含该材料
    manifest = json.loads(files["manifest.json"])
    assert manifest["format"] == "tls-checker-evidence/1"
    assert manifest["domain"] == DOMAIN
    assert manifest["trust_root_version"] == "rv1"
    assert manifest["crl_snapshot_version"] is None
    assert manifest["cert_fingerprints"] == [fp]
    assert manifest["window_count"] == 1
    # 清单内全部摘要必须与内容相符
    for fe in manifest["files"]:
        assert hashlib.sha256(files[fe["path"]]).hexdigest() == fe["sha256"]


def test_evidence_package_is_deterministic(client, root):
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)
    a = _download(client, plan_id, approval_id)
    b = _download(client, plan_id, approval_id)
    assert a == b  # 相同冻结材料 → 字节相同的确定性包


def test_unknown_plan_or_approval_404(client, root):
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)
    assert client.get(f"/api/v1/plans/9999/approvals/{approval_id}/evidence").status_code == 404
    assert client.get(f"/api/v1/plans/{plan_id}/approvals/9999/evidence").status_code == 404


def test_legacy_approval_without_frozen_windows_is_not_replayable(client, root, monkeypatch):
    """本轮改造前的既有批准（无冻结窗口）必须明确不可复核，不能按当前窗口补齐。"""
    from app import db

    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)
    with db.connect() as conn:
        conn.execute("UPDATE approvals SET frozen_windows=NULL WHERE id=?", (approval_id,))

    r = client.get(f"/api/v1/plans/{plan_id}/approvals/{approval_id}/evidence")
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "approval_not_replayable"
    assert "current windows must not be back-filled" in body["detail"]

    approval = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"][-1]
    assert approval["replayable"] is False
    assert approval["frozen_windows"] is None


# ---------------------------------------------------------------------------
# 离线复核：一致
# ---------------------------------------------------------------------------

def test_verify_consistent_with_two_adjacent_windows(client, root):
    ca, ca_key = root
    cur = _leaf(client, ca, ca_key, na="2026-08-01", role="current",
                start="2026-01-01T00:00:00Z", end="2026-07-01T00:00:00Z")
    nxt = _leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01", role="planned",
                start="2026-07-01T00:00:00Z", end="2027-01-01T00:00:00Z")
    plan_id, approval_id = _approve_gap_free(client)

    r = _verify(client, _download(client, plan_id, approval_id))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"] == "consistent"
    assert body["differences"] == []
    assert body["domain"] == DOMAIN
    assert body["cert_fingerprints"] == sorted([cur, nxt])
    assert body["window_count"] == 2
    assert body["frozen_verdict"]["has_gaps"] is False


def test_verify_with_intermediate_chain(client):
    ca, ca_key = make_ca("Audit Chain Root")
    client.post("/api/v1/trust-roots", json={"version": "rv1", "pem": pem(ca)})
    inter, inter_key = make_cert(ca, ca_key, "Audit Inter CA", is_ca=True)
    _leaf(client, ca, ca_key, issuer_cert=inter, issuer_key=inter_key)
    plan_id, approval_id = _approve_gap_free(client)

    r = _verify(client, _download(client, plan_id, approval_id))
    assert r.status_code == 200
    assert r.json()["result"] == "consistent"


def test_verify_with_crl_snapshot(client, root):
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    snap = make_crl(ca, ca_key, "2025-12-01", "2027-02-01", number=3)
    r = client.post("/api/v1/crl-snapshots", json={"version": "snap1", "pem": snap})
    assert r.status_code == 201, r.text
    plan_id, approval_id = _approve_gap_free(client, snapshot="snap1")

    payload = _download(client, plan_id, approval_id)
    files = _members(payload)
    assert "materials/crl-snapshot.pem" in files
    body = _verify(client, payload).json()
    assert body["result"] == "consistent"
    assert body["crl_snapshot_version"] == "snap1"
    assert all(
        "revocation" in c for c in body["recomputed_verdict"]["certificates"]
    )


def test_verify_revocation_details_replay_exactly(client, root):
    """把包内快照替换为撤销同一张叶子的快照（版本名义不变）：重算撤销
    结论与冻结判定不一致，差异中含撤销生效时刻与逐证书原因。"""
    from cryptography import x509
    from tests.helpers import cert_serial

    ca, ca_key = root
    fp = _leaf(client, ca, ca_key)
    good = make_crl(ca, ca_key, "2025-12-01", "2027-02-01", number=10)
    client.post("/api/v1/crl-snapshots", json={"version": "good", "pem": good})
    plan_id, approval_id = _approve_gap_free(client, snapshot="good")

    # 从库中导入材料取得叶子真实序列号（仅用于测试准备，不属于复核路径）
    from app import db as _db
    with _db.connect() as conn:
        chain_pem = conn.execute(
            "SELECT chain_pem FROM certificates WHERE fingerprint_sha256=?", (fp,)
        ).fetchone()[0]
    serial = cert_serial(chain_pem)
    revoked_crl = make_crl(
        ca, ca_key, "2025-12-01", "2027-02-01",
        revoked=[(serial, "2026-03-01", x509.ReasonFlags.key_compromise)],
        number=11,
    )

    payload = _download(client, plan_id, approval_id)
    files = _members(payload)
    files["materials/crl-snapshot.pem"] = revoked_crl.encode()
    manifest = json.loads(files["manifest.json"])
    _redigest(files, manifest, "materials/crl-snapshot.pem")

    r = _verify(client, _repack(files))
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == "inconsistent"
    joined = json.dumps(body["differences"], ensure_ascii=False)
    assert "has_gaps: frozen=False recomputed=True" in joined
    assert "2026-03-01T00:00:00.000Z" in joined  # 撤销造成的可用区间截断/断档
    # 重算判定本体携带逐证书撤销原因（含撤销生效时刻）
    recomputed = json.dumps(body["recomputed_verdict"], ensure_ascii=False)
    assert "revoked at 2026-03-01" in recomputed



def test_each_reapproval_freezes_its_own_indestructible_package(client, root):
    ca, ca_key = root
    fp1 = _leaf(client, ca, ca_key, na="2026-08-01", role="current",
                start="2026-01-01T00:00:00Z", end="2026-07-01T00:00:00Z")
    fp2 = _leaf(client, ca, ca_key, nb="2026-06-01", na="2027-02-01", role="planned",
                start="2026-07-01T00:00:00Z", end="2027-01-01T00:00:00Z")
    plan_id, approval_1 = _approve_gap_free(client)
    pkg1 = _download(client, plan_id, approval_1)

    # 新增第三张证书的窗口 → 待复核；重评并再次批准
    fp3 = _leaf(client, ca, ca_key, nb="2026-06-01", na="2027-06-01", role="planned",
                start="2027-01-01T00:00:00Z", end="2027-06-01T00:00:00Z")
    client.post(f"/api/v1/plans/{plan_id}/evaluate")
    r = client.post(f"/api/v1/plans/{plan_id}/approve")
    approval_2 = r.json()["approval"]["id"]
    assert approval_2 != approval_1
    pkg2 = _download(client, plan_id, approval_2)
    assert pkg1 != pkg2

    # 新包含 3 个窗口指纹，旧包仍是 2 个，且两包各自一致
    b1 = _verify(client, pkg1).json()
    b2 = _verify(client, pkg2).json()
    assert b1["result"] == b2["result"] == "consistent"
    assert b1["window_count"] == 2 and b2["window_count"] == 3
    assert set(b2["cert_fingerprints"]) == {fp1, fp2, fp3}
    assert set(b1["cert_fingerprints"]) == {fp1, fp2}


def test_frozen_package_survives_later_changes(client, root):
    """后续窗口删除、信任根切换与再次批准不得改写旧证据包的复核结论。"""
    ca, ca_key = root
    fp = _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)
    old_pkg = _download(client, plan_id, approval_id)

    # 再导入并激活一个新的信任根 → 计划待复核
    ca2, _ = make_ca("Audit Root V2")
    client.post("/api/v1/trust-roots", json={"version": "rv2", "pem": pem(ca2)})
    client.post("/api/v1/trust-roots/rv2/activate")

    # 删除旧窗口、登记新窗口，再用新根复核并再次批准
    win = client.get(f"/api/v1/service-windows?domain={DOMAIN}").json()["items"][0]
    client.delete(f"/api/v1/service-windows/{win['id']}")
    _leaf(client, ca, ca_key, role="current",
          start="2026-01-01T00:00:00Z", end="2027-06-01T00:00:00Z")
    client.post(f"/api/v1/plans/{plan_id}/evaluate",
                json={"trust_root_version": "rv1"})
    client.post(f"/api/v1/plans/{plan_id}/approve")

    assert _verify(client, old_pkg).json()["result"] == "consistent"


# ---------------------------------------------------------------------------
# 离线复核：结构 / 材料错误（可解释错误码）
# ---------------------------------------------------------------------------

def _tampered(client, plan_id, approval_id, mutate):
    payload = _download(client, plan_id, approval_id)
    files = _members(payload)
    manifest = json.loads(files["manifest.json"])
    mutate(files, manifest)
    return _repack(files)


def test_verify_rejects_garbage_and_non_zip(client, root):
    r = _verify(client, b"definitely not a zip")
    assert r.status_code == 400 and r.json()["code"] == "malformed_package"
    r = _verify(client, b"")
    assert r.status_code == 400 and r.json()["code"] == "malformed_package"


def test_verify_rejects_missing_material(client, root):
    ca, ca_key = root
    fp = _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        del files[f"materials/certificates/{fp}.pem"]

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 400 and r.json()["code"] == "missing_material"


def test_verify_rejects_digest_mismatch(client, root):
    ca, ca_key = root
    fp = _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)
    path = f"materials/certificates/{fp}.pem"

    def mutate(files, manifest):
        files[path] = b"\n" + files[path]  # 内容变化但清单摘要未改

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 422 and r.json()["code"] == "digest_mismatch"


def test_verify_rejects_fingerprint_mismatch(client, root):
    ca, ca_key = root
    fp = _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)
    old_path = f"materials/certificates/{fp}.pem"
    fake_fp = "a" * 64
    new_path = f"materials/certificates/{fake_fp}.pem"

    def mutate(files, manifest):
        files[new_path] = files.pop(old_path)
        for fe in manifest["files"]:
            if fe["path"] == old_path:
                fe["path"] = new_path
        manifest["cert_fingerprints"] = [fake_fp]
        _put_json(files, "manifest.json", manifest)

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 422 and r.json()["code"] == "fingerprint_mismatch"


def test_verify_rejects_version_mismatch(client, root):
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        verdict = json.loads(files["verdict.json"])
        verdict["trust_root_version"] = "rv-other"
        _put_json(files, "verdict.json", verdict)
        _redigest(files, manifest, "verdict.json")

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 422 and r.json()["code"] == "manifest_mismatch"
    assert "trust_root_version" in r.json()["detail"]


def test_verify_rejects_unsupported_format(client, root):
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        manifest["format"] = "tls-checker-evidence/9"
        _put_json(files, "manifest.json", manifest)

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 422 and r.json()["code"] == "unsupported_format"


def test_verify_rejects_illegal_window_time(client, root):
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        windows = json.loads(files["windows.json"])
        windows[0]["start"], windows[0]["end"] = windows[0]["end"], windows[0]["start"]
        _put_json(files, "windows.json", windows)
        _redigest(files, manifest, "windows.json")

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 400 and r.json()["code"] == "invalid_time"


def test_verify_rejects_naive_timestamp(client, root):
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        windows = json.loads(files["windows.json"])
        windows[0]["start"] = "2026-01-01T00:00:00"  # 缺时区
        _put_json(files, "windows.json", windows)
        _redigest(files, manifest, "windows.json")

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 400 and r.json()["code"] == "invalid_time"


def test_verify_rejects_windows_verdict_basis_mismatch(client, root):
    """windows.json 与冻结判定的参评窗口不一致 → 非同一一致性边界。"""
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        windows = json.loads(files["windows.json"])
        windows[0]["role"] = "planned"  # 判定里是 current
        _put_json(files, "windows.json", windows)
        _redigest(files, manifest, "windows.json")

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 422 and r.json()["code"] == "frozen_basis_mismatch"


def test_verify_rejects_invalid_trust_root_pem(client, root):
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        files["materials/trust-root.pem"] = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        _redigest(files, manifest, "materials/trust-root.pem")

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 400 and r.json()["code"] == "invalid_trust_root"


def test_verify_rejects_crl_signed_by_stranger(client, root, monkeypatch):
    """包内 CRL 的签名者不在包内 CA 集合中 → 拒绝（不能用当前库补签名者）。"""
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    other_ca, other_key = make_ca("Stranger CA")
    stranger_crl = make_crl(other_ca, other_key, "2025-12-01", "2027-02-01")

    plan_id, approval_id = _approve_gap_free(client, snapshot=None)

    def mutate(files, manifest):
        files["materials/crl-snapshot.pem"] = stranger_crl.encode()
        manifest["crl_snapshot_version"] = "snapX"
        verdict = json.loads(files["verdict.json"])
        verdict["crl_snapshot_version"] = "snapX"
        _put_json(files, "verdict.json", verdict)
        _redigest(files, manifest, "verdict.json")
        manifest["files"].append(
            {"path": "materials/crl-snapshot.pem",
             "sha256": hashlib.sha256(files["materials/crl-snapshot.pem"]).hexdigest()}
        )
        _put_json(files, "manifest.json", manifest)

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 422 and r.json()["code"] == "crl_signature_invalid"


# ---------------------------------------------------------------------------
# 离线复核：结论不一致
# ---------------------------------------------------------------------------

def test_verify_inconsistent_when_frozen_verdict_was_tampered(client, root):
    """材料完整合法，但冻结判定内容与重算不符（如 usable_intervals 被改写）。"""
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        verdict = json.loads(files["verdict.json"])
        # 人为加宽冻结判定中的可用区间（无中生有）
        verdict["certificates"][0]["usable_intervals"] = [
            {"start": "2026-01-01T00:00:00.000Z", "end": "2027-06-01T00:00:00.000Z"}
        ]
        _put_json(files, "verdict.json", verdict)
        _redigest(files, manifest, "verdict.json")

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == "inconsistent"
    assert any("usable_intervals" in d or "end" in d for d in body["differences"])


def test_verify_inconsistent_when_wrong_root_bundled(client, root):
    """包内信任根 PEM 与判定版本名义一致但密钥不同 → 链不完整、结论不一致。"""
    ca, ca_key = root
    _leaf(client, ca, ca_key)
    rogue_ca, _ = make_ca("Audit Root CA")  # 同名不同密钥
    plan_id, approval_id = _approve_gap_free(client)

    def mutate(files, manifest):
        files["materials/trust-root.pem"] = pem(rogue_ca).encode()
        _redigest(files, manifest, "materials/trust-root.pem")

    r = _verify(client, _tampered(client, plan_id, approval_id, mutate))
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == "inconsistent"
    joined = " ".join(body["differences"])
    assert "chain incomplete" in joined or "has_gaps" in joined


# ---------------------------------------------------------------------------
# 复核不触碰业务数据
# ---------------------------------------------------------------------------

def test_verify_does_not_touch_business_db(client, root, monkeypatch):
    from app import db, evidence

    ca, ca_key = root
    _leaf(client, ca, ca_key)
    plan_id, approval_id = _approve_gap_free(client)
    payload = _download(client, plan_id, approval_id)

    def boom(*a, **k):
        raise AssertionError("verification must not open the business database")

    monkeypatch.setattr(db, "connect", boom)
    result = evidence.verify_evidence_package(payload)
    assert result["result"] == "consistent"
