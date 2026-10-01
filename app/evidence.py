"""批准证据包：材料化评估、证据包构建与离线复核。

本模块不访问业务数据库（服务方通过 service 层取材料后调用 build_package；
复核方只带包内材料调用 verify_package），因此离线复核既不导入也不修改当前
业务数据。

证据包（EVIDENCE_PACKAGE_FORMAT = "tls-approval-evidence/1"）包含：

- 批准的域名与评估区间、判定（冻结 verdict）；
- 实际参与评估的服务窗口集合（批准时冻结，不能按当前窗口补齐）；
- 每张窗口证书的完整 PEM 链、信任根 PEM 与选用的 CRL 快照 PEM（可为空）；
- 逐材料 SHA-256 与清单哈希，供完整性校验。

复核只用包内材料重算覆盖、X.509 与撤销结论：
- 重算判定与冻结判定一致 → consistent；不一致 → inconsistent 并给出差异；
- 缺项 / 指纹不符 / 版本不符 / 非法时间 → 可解释错误（EvidenceError）。
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone

from cryptography import x509

from . import certutils, coverage, crlutils

EVIDENCE_PACKAGE_FORMAT = "tls-approval-evidence/1"


class EvidenceError(Exception):
    """证据包结构/材料非法（缺项、指纹不符、版本不符、非法时间等）。

    code 供调用方映射为可解释错误响应。
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# 时间工具（与 service.iso_z/parse_ts 同语义，但对非法/缺时区时间显式报错）
# ---------------------------------------------------------------------------

def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_aware_ts(value, *, field: str) -> datetime:
    """解析证据包内时间戳：必须是带显式时区的 ISO-8601 字符串。"""
    if not isinstance(value, str) or not value:
        raise EvidenceError("INVALID_TIME", f"{field}: timestamp must be an ISO-8601 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("INVALID_TIME", f"{field}: unparsable timestamp '{value}': {exc}") from exc
    if dt.tzinfo is None:
        raise EvidenceError(
            "INVALID_TIME",
            f"{field}: timestamp '{value}' must carry an explicit timezone (e.g. ...Z)",
        )
    return dt.astimezone(timezone.utc)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 冻结窗口 / 材料行（service 层组装；此处只约定结构）
# ---------------------------------------------------------------------------

def frozen_window(window_row) -> dict:
    """批准边界冻结的单个窗口（实际参与评估的窗口集合元素）。"""
    return {
        "window_id": window_row["id"],
        "certificate_fingerprint": window_row["certificate_fingerprint"],
        "role": window_row["role"],
        "start": window_row["start_utc"],
        "end": window_row["end_utc"],
    }


# ---------------------------------------------------------------------------
# 材料化评估（与历史 service._assess_window / _compute_evaluation 等价，
# 但完全不触库：证书链、信任根、CRL 全部来自传入材料）
# ---------------------------------------------------------------------------

def _short_subject(cert) -> str:
    cn = cert.subject.rfc4514_string()
    return cn.split(",", 1)[0] if "," in cn else cn


def _crl_sign_ok(ca) -> bool:
    try:
        ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return ku.crl_sign


def _snapshot_from_pem(version: str, pem: str | None) -> dict | None:
    """把快照原始 PEM 解析为评估器使用的 by_issuer 索引（空快照等价于不选）。"""
    if pem is None:
        return None
    try:
        crls = crlutils.parse_pem_crls(pem)
    except crlutils.PemCrlError as exc:
        raise EvidenceError("MALFORMED_CRL", f"snapshot '{version}': {exc}") from exc
    by_issuer: dict[tuple[str, str], list[dict]] = {}
    for crl in crls:
        entry = {
            "issuer_dn": crl.issuer.rfc4514_string(),
            "issuer_key_id": crlutils.issuer_key(crl)[1],
            "crl_number": crlutils.crl_number(crl),
            "this_update": iso_z(crl.last_update_utc),
            "next_update": iso_z(crl.next_update_utc),
            "revoked_count": len(list(crl)),
            "crl": crl,
        }
        by_issuer.setdefault(crlutils.issuer_key(crl), []).append(entry)
    return {"version": version, "by_issuer": by_issuer}


def _revocation_evidence(child, issuer, snapshot, w_start, w_end):
    """链上一张非根证书的签发者 CRL 证据（纯材料版）。"""
    subj = issuer.subject.rfc4514_string()
    member = {
        "subject": child.subject.rfc4514_string(),
        "issuer": subj,
        "serial_number": format(child.serial_number, "X"),
        "crl": None,
        "reasons": [],
    }
    reasons: list[str] = []
    clean: list[tuple[datetime, datetime]] = []
    label = _short_subject(child)

    entries = snapshot["by_issuer"].get(crlutils.issuer_key(issuer), [])
    if not entries:
        entries = [
            e
            for key, es in snapshot["by_issuer"].items()
            if key[0] == issuer.subject.rfc4514_string()
            for e in es
        ]
        entries = [e for e in entries if crlutils.crl_aki_matches(e["crl"], issuer)]
    matched = [e for e in entries if crlutils.verify_crl_issued_by(e["crl"], issuer)]
    if not matched:
        reason = f"no CRL signed by issuer '{subj}' found in snapshot '{snapshot['version']}'"
        reasons.append(reason)
        member["reasons"].append(reason)
        return member, clean, [f"{label}: {reason}"]
    if len({(e["issuer_dn"], e["issuer_key_id"], e["this_update"], e["next_update"]) for e in matched}) > 1:
        reason = f"multiple CRLs for issuer '{subj}' in snapshot"
        reasons.append(reason)
        member["reasons"].append(reason)
        return member, clean, [f"{label}: {reason}"]

    entry = matched[0]
    crl = entry["crl"]
    if not _crl_sign_ok(issuer):
        reason = f"issuer '{subj}' keyUsage lacks cRLSign"
        reasons.append(reason)
        member["reasons"].append(reason)
        return member, clean, [f"{label}: {reason}"]

    tu = crl.last_update_utc
    nu = crl.next_update_utc
    member["crl"] = {
        "issuer": subj,
        "crl_number": entry["crl_number"],
        "this_update": iso_z(tu),
        "next_update": iso_z(nu),
        "revoked": None,
    }
    valid: list[tuple[datetime, datetime]] = []
    if nu <= w_start:
        reasons.append(
            f"CRL from issuer '{subj}' expired at {iso_z(nu)},"
            f" before window start {iso_z(w_start)}"
        )
    elif tu >= w_end:
        reasons.append(
            f"CRL from issuer '{subj}' not valid until {iso_z(tu)},"
            f" after window end {iso_z(w_end)}"
        )
    else:
        s, e = max(tu, w_start), min(nu, w_end)
        if s < e:
            valid.append((s, e))
        if tu > w_start:
            reasons.append(
                f"CRL from issuer '{subj}' not valid until {iso_z(tu)},"
                f" after window start {iso_z(w_start)}: coverage missing before that"
            )
        if nu < w_end:
            reasons.append(
                f"CRL from issuer '{subj}' expires at {iso_z(nu)},"
                f" before window end {iso_z(w_end)}: coverage missing after that"
            )

    rc = crl.get_revoked_certificate_by_serial_number(child.serial_number)
    revoked_at: datetime | None = None
    if rc is not None:
        revoked_at = rc.revocation_date_utc
        member["crl"]["revoked"] = {
            "effective_at": iso_z(revoked_at),
            "reason": crlutils.revoked_reason(rc),
        }

    for s, e in valid:
        if revoked_at is not None:
            e2 = min(e, revoked_at)
            if s < e2:
                clean.append((s, e2))
        elif s < e:
            clean.append((s, e))

    if revoked_at is not None:
        reasons.append(
            f"certificate {label} (serial {format(child.serial_number, 'X')})"
            f" revoked at {iso_z(revoked_at)}"
        )

    member["reasons"] = reasons
    return member, clean, [f"{label}: {r}" for r in reasons]


def _assess_window_material(window, chain_pem, roots, domain, eval_start, eval_end, snapshot):
    """评估单个冻结窗口（纯材料版，结构对齐历史报告）。"""
    w_start = max(parse_aware_ts(window["start"], field="window.start"), eval_start)
    w_end = min(parse_aware_ts(window["end"], field="window.end"), eval_end)
    fp = window["certificate_fingerprint"]
    reasons: list[str] = []
    intervals: list[tuple[datetime, datetime]] = []
    sans: list[str] = []
    subject: str | None = None
    revocation: list[dict] = []

    if chain_pem is None:
        raise EvidenceError(
            "MISSING_CERTIFICATE",
            f"window {window.get('window_id')} references fingerprint {fp}"
            " but its certificate chain is not included in the package",
        )
    try:
        certs = certutils.parse_pem_chain(chain_pem)
        leaf, intermediates = certs[0], certs[1:]
        subject = leaf.subject.rfc4514_string()
        sans = certutils.san_dns_names(leaf)
        if not sans:
            raise certutils.ChainValidationError("leaf certificate has no DNS subjectAltName")
        if not certutils.san_matches(sans, domain):
            raise certutils.ChainValidationError(
                f"SAN {sans} does not match domain '{domain}'"
            )
        chain = certutils.build_chain(leaf, intermediates, roots)
    except certutils.PemParseError as exc:
        raise EvidenceError("MALFORMED_CERTIFICATE", f"certificate {fp}: {exc}") from exc
    except certutils.ChainValidationError as exc:
        reasons.append(str(exc))
    else:
        if w_start >= w_end:
            reasons.append("service window does not overlap the evaluation interval")
        else:
            nb, na = certutils.chain_validity_interval(chain)
            s, e = max(w_start, nb), min(w_end, na)
            valid_intervals = [(s, e)] if s < e else []
            if nb > w_start:
                reasons.append(
                    f"certificate chain not valid until {iso_z(nb)},"
                    f" after window start {iso_z(w_start)}"
                )
            if na < w_end:
                reasons.append(
                    f"certificate chain expires at {iso_z(na)},"
                    f" before window end {iso_z(w_end)}"
                )
            if not valid_intervals and not reasons:
                reasons.append("certificate validity does not overlap the service window")

            if snapshot is not None:
                acc: list[tuple[datetime, datetime]] | None = None
                for idx in range(len(chain) - 1):
                    member, clean, flat = _revocation_evidence(
                        chain[idx], chain[idx + 1], snapshot, w_start, w_end
                    )
                    revocation.append(member)
                    reasons.extend(flat)
                    acc = clean if acc is None else coverage.intersect(acc, clean)
                valid_intervals = [
                    (max(s, cs), min(e, ce))
                    for s, e in valid_intervals
                    for cs, ce in (acc or [])
                    if max(s, cs) < min(e, ce)
                ]

            intervals = valid_intervals

    report = {
        "window_id": window["window_id"],
        "fingerprint": fp,
        "role": window["role"],
        "window": {"start": window["start"], "end": window["end"]},
        "subject": subject,
        "sans": sans,
        "usable_intervals": [{"start": iso_z(s), "end": iso_z(e)} for s, e in intervals],
        "reasons": reasons,
    }
    if snapshot is not None:
        report["revocation"] = revocation
    return report, intervals


def compute_from_materials(
    *,
    domain: str,
    eval_start: datetime,
    eval_end: datetime,
    trust_root_pem: str,
    windows: list[dict],
    certificates: dict[str, str],
    snapshot_version: str | None,
    snapshot_pem: str | None,
) -> dict:
    """只用给定材料重算评估（覆盖 + X.509 + 撤销），返回 verdict 结构。"""
    roots = certutils.parse_pem_chain(trust_root_pem)
    snapshot = _snapshot_from_pem(snapshot_version, snapshot_pem)

    usable: list[tuple[datetime, datetime]] = []
    reports = []
    for w in sorted(windows, key=lambda x: (x["start"], x["window_id"] is None, x["window_id"] or 0)):
        report, intervals = _assess_window_material(
            w,
            certificates.get(w["certificate_fingerprint"]),
            roots,
            domain,
            eval_start,
            eval_end,
            snapshot,
        )
        usable.extend(intervals)
        reports.append(report)

    gaps = coverage.compute_gaps(eval_start, eval_end, usable)
    return {
        "domain": domain,
        "eval_start": iso_z(eval_start),
        "eval_end": iso_z(eval_end),
        "trust_root_version": None,  # 由调用方按引用版本回填
        "crl_snapshot_version": snapshot_version,
        "has_gaps": bool(gaps),
        "gaps": [{"start": iso_z(s), "end": iso_z(e)} for s, e in gaps],
        "certificates": reports,
        "evaluated_at": None,  # 复核时刻不参与判定比较
    }


# ---------------------------------------------------------------------------
# 证据包构建（服务方）
# ---------------------------------------------------------------------------

def build_package(
    *,
    approval_id: int,
    plan_id: int,
    domain: str,
    eval_start: str,
    eval_end: str,
    trust_root_version: str,
    trust_root_pem: str,
    crl_snapshot_version: str | None,
    crl_snapshot_pem: str | None,
    windows: list[dict],
    certificates: dict[str, str],
    frozen_verdict: dict,
    frozen_material_hashes: dict | None = None,
) -> dict:
    """组装自包含证据包（dict，JSON 可序列化）。逐材料附 SHA-256。"""
    certs_section = {}
    for fp in sorted({w["certificate_fingerprint"] for w in windows}):
        chain_pem = certificates.get(fp)
        if chain_pem is None:
            raise EvidenceError(
                "MISSING_CERTIFICATE",
                f"frozen window references fingerprint {fp}"
                " but the certificate chain is no longer available",
            )
        leaf = certutils.parse_pem_chain(chain_pem)[0]
        actual_fp = certutils.fingerprint_sha256(leaf)
        if actual_fp != fp:
            raise EvidenceError(
                "FINGERPRINT_MISMATCH",
                f"stored certificate chain leaf fingerprint {actual_fp}"
                f" does not match frozen window fingerprint {fp}",
            )
        certs_section[fp] = {
            "chain_pem": chain_pem,
            "leaf_fingerprint_sha256": fp,
            "pem_sha256": sha256_text(chain_pem),
        }

    roots_section = {
        "version": trust_root_version,
        "pem": trust_root_pem,
        "pem_sha256": sha256_text(trust_root_pem),
    }
    snapshot_section = None
    if crl_snapshot_version is not None:
        if crl_snapshot_pem is None:
            raise EvidenceError(
                "MISSING_CRL_SNAPSHOT",
                f"approval selected CRL snapshot '{crl_snapshot_version}'"
                " but its PEM bundle is no longer available",
            )
        snapshot_section = {
            "version": crl_snapshot_version,
            "pem": crl_snapshot_pem,
            "pem_sha256": sha256_text(crl_snapshot_pem),
        }

    material_hashes = {
        "trust_root_pem_sha256": roots_section["pem_sha256"],
        "crl_snapshot_pem_sha256": (
            snapshot_section["pem_sha256"] if snapshot_section else None
        ),
        "certificate_pem_sha256": {fp: c["pem_sha256"] for fp, c in certs_section.items()},
    }
    if frozen_material_hashes is not None and frozen_material_hashes != material_hashes:
        raise EvidenceError(
            "FROZEN_MATERIAL_MISMATCH",
            "material hashes at package generation differ from those frozen at"
            " approval time; the immutable inventory changed underneath the approval",
        )

    package = {
        "format": EVIDENCE_PACKAGE_FORMAT,
        "approval": {
            "approval_id": approval_id,
            "plan_id": plan_id,
            "created_at": frozen_verdict.get("_approval_created_at"),
        },
        "domain": domain,
        "eval_start": eval_start,
        "eval_end": eval_end,
        "decision": {
            "trust_root_version": trust_root_version,
            "crl_snapshot_version": crl_snapshot_version,
            "cert_fingerprints": sorted(certs_section.keys()),
            "verdict": frozen_verdict,
        },
        "windows": windows,
        "materials": {
            "trust_root": roots_section,
            "crl_snapshot": snapshot_section,
            "certificates": certs_section,
        },
    }
    package["manifest_sha256"] = _manifest_hash(package)
    return package


def _manifest_hash(package: dict) -> str:
    """清单哈希：覆盖除清单哈希自身外的全部内容（含 PEM 与冻结判定）。"""
    body = {k: v for k, v in package.items() if k != "manifest_sha256"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_text(blob)


# ---------------------------------------------------------------------------
# ZIP 封装（可下载、可离线传递）
# ---------------------------------------------------------------------------

def package_to_zip(package: dict) -> bytes:
    """证据包打包为 ZIP：manifest.json + 供直接查看的 PEM 材料。"""
    approval_id = package["approval"]["approval_id"]
    plan_id = package["approval"]["plan_id"]
    root = f"approval-{approval_id}-plan-{plan_id}-evidence"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            f"{root}/manifest.json",
            json.dumps(package, indent=2, sort_keys=True, ensure_ascii=False),
        )
        mats = package["materials"]
        zf.writestr(
            f"{root}/trust-root-{mats['trust_root']['version']}.pem",
            mats["trust_root"]["pem"],
        )
        snap = mats["crl_snapshot"]
        if snap is not None:
            zf.writestr(f"{root}/crl-snapshot-{snap['version']}.pem", snap["pem"])
        for fp, cert in mats["certificates"].items():
            zf.writestr(f"{root}/certificates/{fp}.pem", cert["chain_pem"])
    return buf.getvalue()


def package_from_zip(data: bytes) -> dict:
    """从 ZIP 读取证据包；ZIP 内必须恰好包含一个 manifest.json。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise EvidenceError("INVALID_PACKAGE", f"not a valid ZIP archive: {exc}") from exc
    names = [n for n in zf.namelist() if n.endswith("/manifest.json") or n == "manifest.json"]
    bad = zf.testzip()
    if bad is not None:
        raise EvidenceError("INVALID_PACKAGE", f"corrupt entry in ZIP: {bad}")
    if len(names) != 1:
        raise EvidenceError(
            "INVALID_PACKAGE",
            "evidence ZIP must contain exactly one manifest.json"
            f" (found {len(names)})",
        )
    try:
        raw = zf.read(names[0])
    except KeyError as exc:
        raise EvidenceError("INVALID_PACKAGE", f"cannot read {names[0]}") from exc
    return package_from_json_bytes(raw)


def package_from_json_bytes(raw: bytes) -> dict:
    try:
        package = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("INVALID_PACKAGE", f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(package, dict):
        raise EvidenceError("INVALID_PACKAGE", "manifest must be a JSON object")
    return package


# ---------------------------------------------------------------------------
# 离线复核（只用包内材料）
# ---------------------------------------------------------------------------

def _require(obj, key: str, *, where: str, types):
    if key not in obj:
        raise EvidenceError("MISSING_FIELD", f"{where}: missing required field '{key}'")
    value = obj[key]
    if not isinstance(value, types):
        name = types[0].__name__ if isinstance(types, tuple) else types.__name__
        raise EvidenceError("MISSING_FIELD", f"{where}.{key}: expected {name}")
    return value


def verify_package(package: dict) -> dict:
    """只使用包内材料重算并比对冻结判定。

    返回 {"result": "consistent"|"inconsistent", ...}；
    包本身缺项/指纹不符/版本不符/非法时间抛 EvidenceError。
    """
    if not isinstance(package, dict):
        raise EvidenceError("INVALID_PACKAGE", "evidence package must be a JSON object")
    if package.get("format") != EVIDENCE_PACKAGE_FORMAT:
        raise EvidenceError(
            "UNSUPPORTED_FORMAT",
            f"unsupported evidence format {package.get('format')!r};"
            f" expected '{EVIDENCE_PACKAGE_FORMAT}'",
        )
    declared_hash = package.get("manifest_sha256")
    if not isinstance(declared_hash, str):
        raise EvidenceError("MISSING_FIELD", "manifest_sha256: required integrity hash missing")
    if _manifest_hash(package) != declared_hash:
        raise EvidenceError(
            "PACKAGE_INTEGRITY_ERROR",
            "manifest_sha256 does not match the recomputed hash;"
            " package content was altered after sealing",
        )

    domain = _require(package, "domain", where="package", types=str)
    eval_start = parse_aware_ts(_require(package, "eval_start", where="package", types=str),
                                field="eval_start")
    eval_end = parse_aware_ts(_require(package, "eval_end", where="package", types=str),
                              field="eval_end")
    if eval_start >= eval_end:
        raise EvidenceError(
            "INVALID_TIME",
            f"eval_start {iso_z(eval_start)} must be before eval_end {iso_z(eval_end)}",
        )

    windows = _require(package, "windows", where="package", types=list)
    materials = _require(package, "materials", where="package", types=dict)
    decision = _require(package, "decision", where="package", types=dict)
    frozen_verdict = _require(decision, "verdict", where="decision", types=dict)
    root_version = _require(decision, "trust_root_version", where="decision", types=str)
    snap_version = decision.get("crl_snapshot_version")
    if snap_version is not None and not isinstance(snap_version, str):
        raise EvidenceError("VERSION_MISMATCH", "decision.crl_snapshot_version must be a string or null")

    # --- 窗口集合：必须随包冻结，不能缺，也不接受按当前窗口补齐 ---
    if not windows:
        raise EvidenceError(
            "MISSING_WINDOWS",
            "package carries no frozen service windows; approval is not reviewable",
        )
    frozen_windows: list[dict] = []
    for i, w in enumerate(windows):
        where = f"windows[{i}]"
        if not isinstance(w, dict):
            raise EvidenceError("MISSING_FIELD", f"{where}: must be an object")
        fp = _require(w, "certificate_fingerprint", where=where, types=str)
        role = _require(w, "role", where=where, types=str)
        if role not in ("current", "planned"):
            raise EvidenceError("INVALID_WINDOW", f"{where}.role: must be 'current' or 'planned'")
        ws = parse_aware_ts(_require(w, "start", where=where, types=str), field=f"{where}.start")
        we = parse_aware_ts(_require(w, "end", where=where, types=str), field=f"{where}.end")
        if ws >= we:
            raise EvidenceError(
                "INVALID_TIME",
                f"{where}: start {iso_z(ws)} must be before end {iso_z(we)}",
            )
        frozen_windows.append({
            "window_id": w.get("window_id"),
            "certificate_fingerprint": fp,
            "role": role,
            "start": iso_z(ws),
            "end": iso_z(we),
        })

    # --- 信任根材料 ---
    root_section = _require(materials, "trust_root", where="materials", types=dict)
    root_pem = _require(root_section, "pem", where="materials.trust_root", types=str)
    root_pem_hash = _require(root_section, "pem_sha256",
                             where="materials.trust_root", types=str)
    if sha256_text(root_pem) != root_pem_hash:
        raise EvidenceError(
            "FINGERPRINT_MISMATCH",
            "materials.trust_root.pem_sha256 does not match the PEM content",
        )
    if _require(root_section, "version", where="materials.trust_root", types=str) != root_version:
        raise EvidenceError(
            "VERSION_MISMATCH",
            f"trust root version in materials ({root_section['version']}) differs"
            f" from the decision reference ({root_version})",
        )
    try:
        roots = certutils.parse_pem_chain(root_pem)
    except certutils.PemParseError as exc:
        raise EvidenceError("MALFORMED_CERTIFICATE", f"trust root PEM: {exc}") from exc
    if not roots:
        raise EvidenceError("MISSING_TRUST_ROOT", "trust root bundle contains no certificate")

    # --- CRL 快照材料（选择了快照则必须带且版本一致） ---
    snap_section = materials.get("crl_snapshot")
    snap_pem: str | None = None
    if snap_version is not None:
        if not isinstance(snap_section, dict):
            raise EvidenceError(
                "MISSING_CRL_SNAPSHOT",
                f"decision selected CRL snapshot '{snap_version}'"
                " but materials.crl_snapshot is absent",
            )
        if snap_section.get("version") != snap_version:
            raise EvidenceError(
                "VERSION_MISMATCH",
                f"CRL snapshot version in materials ({snap_section.get('version')})"
                f" differs from the decision reference ({snap_version})",
            )
        snap_pem = _require(snap_section, "pem", where="materials.crl_snapshot", types=str)
        snap_hash = _require(snap_section, "pem_sha256",
                             where="materials.crl_snapshot", types=str)
        if sha256_text(snap_pem) != snap_hash:
            raise EvidenceError(
                "FINGERPRINT_MISMATCH",
                "materials.crl_snapshot.pem_sha256 does not match the PEM content",
            )
        try:
            crls = crlutils.parse_pem_crls(snap_pem)
        except crlutils.PemCrlError as exc:
            raise EvidenceError("MALFORMED_CRL", f"CRL snapshot PEM: {exc}") from exc
        for crl in crls:
            if crl.next_update_utc is None:
                raise EvidenceError(
                    "INVALID_TIME",
                    f"CRL issued by '{crl.issuer.rfc4514_string()}' has no nextUpdate"
                    " (indefinite expiry not accepted)",
                )
            if crl.last_update_utc > crl.next_update_utc:
                raise EvidenceError(
                    "INVALID_TIME",
                    f"CRL issued by '{crl.issuer.rfc4514_string()}': thisUpdate"
                    f" {iso_z(crl.last_update_utc)} is after nextUpdate"
                    f" {iso_z(crl.next_update_utc)}",
                )

    # --- 证书材料：每个冻结窗口的指纹都必须在包内，且叶子 DER 指纹相符 ---
    certs_section = _require(materials, "certificates", where="materials", types=dict)
    cert_pems: dict[str, str] = {}
    needed = {w["certificate_fingerprint"] for w in frozen_windows}
    missing = sorted(needed - set(certs_section))
    if missing:
        raise EvidenceError(
            "MISSING_CERTIFICATE",
            f"certificate chain(s) not included in package for fingerprint(s): {missing}",
        )
    for fp, item in certs_section.items():
        where = f"materials.certificates[{fp}]"
        if not isinstance(item, dict):
            raise EvidenceError("MISSING_FIELD", f"{where}: must be an object")
        chain_pem = _require(item, "chain_pem", where=where, types=str)
        try:
            chain = certutils.parse_pem_chain(chain_pem)
        except certutils.PemParseError as exc:
            raise EvidenceError("MALFORMED_CERTIFICATE", f"{where}: {exc}") from exc
        actual_fp = certutils.fingerprint_sha256(chain[0])
        if actual_fp != fp:
            raise EvidenceError(
                "FINGERPRINT_MISMATCH",
                f"{where}: map key fingerprint {fp} does not match leaf DER"
                f" SHA-256 {actual_fp}",
            )
        declared_leaf = item.get("leaf_fingerprint_sha256")
        if declared_leaf is not None and declared_leaf != actual_fp:
            raise EvidenceError(
                "FINGERPRINT_MISMATCH",
                f"{where}: leaf_fingerprint_sha256 {declared_leaf} does not match"
                f" recomputed leaf DER SHA-256 {actual_fp}",
            )
        declared_hash = item.get("pem_sha256")
        if declared_hash is not None and sha256_text(chain_pem) != declared_hash:
            raise EvidenceError(
                "FINGERPRINT_MISMATCH",
                f"{where}: pem_sha256 does not match the PEM content",
            )
        cert_pems[fp] = chain_pem

    # 冻结判定中的证书指纹集合须与窗口集合一致
    frozen_fps = set(_require(decision, "cert_fingerprints", where="decision", types=list))
    if frozen_fps != needed:
        raise EvidenceError(
            "FINGERPRINT_MISMATCH",
            "decision.cert_fingerprints does not match the frozen window fingerprint set",
        )

    # 冻结 verdict 自身的版本引用必须与决策头一致
    if frozen_verdict.get("trust_root_version") != root_version:
        raise EvidenceError(
            "VERSION_MISMATCH",
            "frozen verdict trust_root_version differs from decision reference",
        )
    if frozen_verdict.get("crl_snapshot_version") != snap_version:
        raise EvidenceError(
            "VERSION_MISMATCH",
            "frozen verdict crl_snapshot_version differs from decision reference",
        )

    # --- 只用包内材料重算 ---
    recomputed = compute_from_materials(
        domain=domain,
        eval_start=eval_start,
        eval_end=eval_end,
        trust_root_pem=root_pem,
        windows=frozen_windows,
        certificates=cert_pems,
        snapshot_version=snap_version,
        snapshot_pem=snap_pem,
    )
    recomputed["trust_root_version"] = root_version

    diffs = _diff_verdict(
        _normalize_verdict(frozen_verdict), _normalize_verdict(recomputed)
    )
    return {
        "result": "consistent" if not diffs else "inconsistent",
        "format": EVIDENCE_PACKAGE_FORMAT,
        "approval_id": package["approval"].get("approval_id"),
        "plan_id": package["approval"].get("plan_id"),
        "domain": domain,
        "eval_start": iso_z(eval_start),
        "eval_end": iso_z(eval_end),
        "differences": diffs,
        "recomputed": recomputed,
        "frozen": _normalize_verdict(frozen_verdict),
    }


# ---------------------------------------------------------------------------
# 判定比对（规范化后递归比较，输出路径级差异）
# ---------------------------------------------------------------------------

def _normalize_verdict(verdict: dict) -> dict:
    """去掉与判定无关的易变字段（评估时刻），其余按可比较结构规范化。"""
    v = {k: val for k, val in verdict.items() if k not in ("evaluated_at", "_approval_created_at")}
    certs = []
    for c in v.get("certificates", []):
        certs.append({
            "window_id": c.get("window_id"),
            "fingerprint": c.get("fingerprint"),
            "role": c.get("role"),
            "window": [c.get("window", {}).get("start"),
                       c.get("window", {}).get("end")],
            "subject": c.get("subject"),
            "sans": sorted(c.get("sans", [])),
            "usable_intervals": sorted(
                [iv.get("start"), iv.get("end")]
                for iv in c.get("usable_intervals", [])
            ),
            "reasons": sorted(c.get("reasons", [])),
            "revocation": _normalize_revocation(c.get("revocation")),
        })
    v["certificates"] = sorted(certs, key=lambda c: (c["window_id"] is None, c["window_id"] or -1))
    v["gaps"] = sorted([[g.get("start"), g.get("end")] for g in v.get("gaps", [])])
    return v


def _normalize_revocation(rev):
    if rev is None:
        return None
    out = []
    for m in rev:
        out.append({
            "subject": m.get("subject"),
            "issuer": m.get("issuer"),
            "serial_number": m.get("serial_number"),
            "crl": m.get("crl"),
            "reasons": sorted(m.get("reasons", [])),
        })
    return sorted(out, key=lambda m: (m.get("subject") or "", m.get("serial_number") or ""))


def _diff_verdict(frozen: dict, recomputed: dict, path: str = "verdict") -> list[dict]:
    """递归比较两个规范化判定，返回 [{path, frozen, recomputed}]。"""
    diffs: list[dict] = []
    if isinstance(frozen, dict) and isinstance(recomputed, dict):
        keys = set(frozen) | set(recomputed)
        for key in sorted(keys):
            if key not in frozen:
                diffs.append({"path": f"{path}.{key}", "frozen": None,
                              "recomputed": recomputed[key]})
            elif key not in recomputed:
                diffs.append({"path": f"{path}.{key}", "frozen": frozen[key],
                              "recomputed": None})
            else:
                diffs.extend(_diff_verdict(frozen[key], recomputed[key], f"{path}.{key}"))
        return diffs
    if frozen != recomputed:
        diffs.append({"path": path, "frozen": frozen, "recomputed": recomputed})
    return diffs
