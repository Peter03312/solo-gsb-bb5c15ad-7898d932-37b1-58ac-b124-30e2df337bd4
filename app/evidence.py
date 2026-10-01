"""运维审计证据包：针对一次批准生成可离线复核的冻结材料，并只用包内材料复核。

证据包是一个确定性（字节可复现）的 ZIP，包含：

- ``manifest.json``：格式版本、批准标识、域名与评估区间、判定、信任根/
  CRL 快照版本、窗口集合与逐文件 SHA-256 摘要；
- ``verdict.json``：批准时冻结的判定（断档、逐窗口可用区间、X.509 与
  撤销原因）；
- ``windows.json``：批准同一一致性边界冻结的、实际参与评估的服务窗口；
- ``materials/trust-root.pem``：所选用的信任根版本完整 PEM；
- ``materials/certificates/<fp>.pem``：冻结窗口涉及的每张证书的导入链
  （叶子 + 中间证书）；
- ``materials/crl-snapshot.pem``：所选用的 CRL 快照（仅在批准选择了快照
  时存在）。

复核端 **只使用包内材料** 重算覆盖 / X.509 / 撤销结论，不读取、不导入、
不修改任何当前业务数据。材料齐全且重算判定与冻结判定逐字段一致 →
``consistent``；材料本身可解析但结论对不上 → 200 ``inconsistent`` 并给出
差异原因；缺项、指纹不符、版本不符、非法时间、摘要不符等 → 带错误码的
可解释错误。
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone

from cryptography import x509

from . import certutils, crlutils, service

EVIDENCE_FORMAT = "tls-checker-evidence/1"
MAX_PACKAGE_BYTES = 16 * 1024 * 1024

MANIFEST_PATH = "manifest.json"
VERDICT_PATH = "verdict.json"
WINDOWS_PATH = "windows.json"
MATERIALS_DIR = "materials/"
TRUST_ROOT_PATH = MATERIALS_DIR + "trust-root.pem"
CRL_SNAPSHOT_PATH = MATERIALS_DIR + "crl-snapshot.pem"
CERTS_DIR = MATERIALS_DIR + "certificates/"


class EvidenceError(service.ApiError):
    """证据包生成 / 复核错误：携带可机读错误码。"""

    def __init__(self, status_code: int, code: str, detail: str):
        super().__init__(status_code, detail)
        self.code = code


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj) -> bytes:
    """确定性 JSON 序列化：排序键、无多余空白、不转义非 ASCII。"""
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _parse_iso(value, *, what: str):
    """复核端的时间解析：必须是带显式时区的 ISO-8601 字符串。"""
    if not isinstance(value, str):
        raise EvidenceError(400, "invalid_time", f"{what} must be an ISO-8601 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(400, "invalid_time", f"{what} is not a valid timestamp: {exc}") from exc
    if dt.tzinfo is None:
        raise EvidenceError(
            400, "invalid_time", f"{what} must carry an explicit timezone (e.g. ...Z)"
        )
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# 证据包生成（在线侧，只读业务库）
# ---------------------------------------------------------------------------

def build_evidence_package(conn, approval) -> bytes:
    """依据一条批准记录装配确定性 ZIP 证据包。

    调用方须保证 approval 来自库内查询；缺冻结窗口依据的既有批准应在更
    上层直接判为不可复核，不进入本函数。
    """
    frozen_windows = json.loads(approval["frozen_windows"] or "null")
    if not frozen_windows:
        raise EvidenceError(
            409,
            "approval_not_replayable",
            f"approval #{approval['id']} predates window-set freezing and has no"
            " restorable window basis; it cannot be replayed and no evidence"
            " package can be produced for it",
        )
    verdict = json.loads(approval["verdict_json"])
    domain = verdict["domain"]
    eval_start_s, eval_end_s = verdict["eval_start"], verdict["eval_end"]
    root_version = approval["trust_root_version"]
    snapshot_version = approval["crl_snapshot_version"]

    root_row = conn.execute(
        "SELECT * FROM trust_roots WHERE version = ?", (root_version,)
    ).fetchone()
    if root_row is None:
        # 信任根材料缺失属于库内不一致：不能伪造证据，明确失败。
        raise EvidenceError(
            500,
            "material_unavailable",
            f"frozen trust root version '{root_version}' is no longer present in"
            " local storage; cannot assemble evidence package",
        )
    root_pem = root_row["pem"]

    fps = sorted({w["certificate_fingerprint"] for w in frozen_windows})
    cert_pems: dict[str, str] = {}
    for fp in fps:
        row = conn.execute(
            "SELECT * FROM certificates WHERE fingerprint_sha256 = ?", (fp,)
        ).fetchone()
        if row is None:
            raise EvidenceError(
                500,
                "material_unavailable",
                f"certificate {fp} referenced by frozen approval"
                f" #{approval['id']} is no longer present in local storage;"
                " cannot assemble evidence package",
            )
        cert_pems[fp] = row["chain_pem"]

    snapshot_pem: str | None = None
    if snapshot_version is not None:
        snap_row = conn.execute(
            "SELECT pem FROM crl_snapshots WHERE version = ?", (snapshot_version,)
        ).fetchone()
        if snap_row is None:
            raise EvidenceError(
                500,
                "material_unavailable",
                f"frozen CRL snapshot version '{snapshot_version}' is no longer"
                " present in local storage; cannot assemble evidence package",
            )
        snapshot_pem = snap_row["pem"]

    files: dict[str, bytes] = {
        VERDICT_PATH: _canonical_json(verdict),
        WINDOWS_PATH: _canonical_json(frozen_windows),
        TRUST_ROOT_PATH: root_pem.encode("utf-8"),
    }
    for fp, pem_text in sorted(cert_pems.items()):
        files[CERTS_DIR + fp + ".pem"] = pem_text.encode("utf-8")
    if snapshot_pem is not None:
        files[CRL_SNAPSHOT_PATH] = snapshot_pem.encode("utf-8")

    manifest = {
        "format": EVIDENCE_FORMAT,
        "approval": {
            "approval_id": approval["id"],
            "plan_id": approval["plan_id"],
            "created_at": approval["created_at"],
            "superseded": bool(approval["superseded"]),
        },
        "domain": domain,
        "eval_interval": {"start": eval_start_s, "end": eval_end_s},
        "verdict": {
            "has_gaps": bool(verdict["has_gaps"]),
            "gap_count": len(verdict["gaps"]),
        },
        "trust_root_version": root_version,
        "crl_snapshot_version": snapshot_version,
        "cert_fingerprints": fps,
        "window_count": len(frozen_windows),
        "files": [
            {"path": path, "sha256": _sha256_bytes(data)}
            for path, data in sorted(files.items())
        ],
    }
    files[MANIFEST_PATH] = _canonical_json(manifest)

    buffer = io.BytesIO()
    # 固定 ZIP 日期时间、不逐条目压缩时间元数据 → 相同材料产生字节相同的包。
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[path])
    return buffer.getvalue()


def package_filename(approval) -> str:
    return f"approval-{approval['id']}-evidence.pkb.zip"


# ---------------------------------------------------------------------------
# 证据包复核（离线侧：零业务库访问）
# ---------------------------------------------------------------------------

def _err(code: str, detail: str, status: int = 400) -> EvidenceError:
    return EvidenceError(status, code, detail)


def _validate_digest(path: str, data: bytes, expected: str | None) -> None:
    if not expected:
        raise _err(
            "missing_material",
            f"manifest does not provide a sha256 digest for '{path}'",
            status=422,
        )
    actual = _sha256_bytes(data)
    if actual != expected:
        raise _err(
            "digest_mismatch",
            f"sha256 digest mismatch for '{path}': manifest declares {expected},"
            f" package content hashes to {actual}",
            status=422,
        )


def _require_object(value, *, what: str):
    if not isinstance(value, dict):
        raise _err("malformed_package", f"{what} must be a JSON object")


def _validate_window_records(windows) -> list[dict]:
    if not isinstance(windows, list) or not windows:
        raise _err(
            "malformed_package",
            "windows.json must be a non-empty JSON array of frozen service windows",
        )
    seen_ids: set = set()
    normalized: list[dict] = []
    for i, w in enumerate(windows):
        where = f"windows[{i}]"
        _require_object(w, what=where)
        try:
            fp = w["certificate_fingerprint"]
            role = w["role"]
            start = w["start"]
            end = w["end"]
        except KeyError as exc:
            raise _err("missing_material", f"{where} is missing field {exc}") from exc
        if not isinstance(fp, str) or len(fp) != 64:
            raise _err("malformed_package", f"{where}.certificate_fingerprint must be a 64-char hex string")
        try:
            int(fp, 16)
        except ValueError:
            raise _err("malformed_package", f"{where}.certificate_fingerprint is not hexadecimal")
        if role not in ("current", "planned"):
            raise _err("malformed_package", f"{where}.role must be 'current' or 'planned'")
        s_dt = _parse_iso(start, what=f"{where}.start")
        e_dt = _parse_iso(end, what=f"{where}.end")
        if s_dt >= e_dt:
            raise _err(
                "invalid_time",
                f"{where}: start {start} must be strictly before end {end}",
            )
        wid = w.get("window_id")
        if wid is not None:
            if not isinstance(wid, int) or isinstance(wid, bool):
                raise _err("malformed_package", f"{where}.window_id must be an integer or null")
            if wid in seen_ids:
                raise _err("malformed_package", f"duplicate window_id {wid} in frozen windows")
            seen_ids.add(wid)
        normalized.append(
            {
                "window_id": wid,
                "certificate_fingerprint": fp,
                "role": role,
                "start": service.iso_z(s_dt),
                "end": service.iso_z(e_dt),
            }
        )
    return normalized


def _build_cert_rows(cert_pems: dict[str, bytes]) -> dict[str, dict]:
    """解析全部证书链材料并核验叶子指纹，构造评估核心所需的证书行。"""
    rows: dict[str, dict] = {}
    for fp, raw in cert_pems.items():
        try:
            pem_text = raw.decode("utf-8")
            chain = certutils.parse_pem_chain(pem_text)
        except UnicodeDecodeError as exc:
            raise _err("invalid_certificate", f"certificate material '{fp}.pem' is not UTF-8: {exc}")
        except certutils.PemParseError as exc:
            raise _err("invalid_certificate", f"certificate material '{fp}.pem' is invalid: {exc}") from exc
        leaf = chain[0]
        actual_fp = certutils.fingerprint_sha256(leaf)
        if actual_fp != fp:
            raise _err(
                "fingerprint_mismatch",
                f"certificate material '{fp}.pem' leaf hashes to {actual_fp},"
                " which does not match its declared fingerprint",
                status=422,
            )
        rows[fp] = {
            "fingerprint_sha256": fp,
            "subject": leaf.subject.rfc4514_string(),
            "san_dns": json.dumps(certutils.san_dns_names(leaf)),
            "chain_pem": pem_text,
        }
    return rows


def _verify_crl_materials(crl_pem: str, cert_rows: dict[str, dict], root_pem: str):
    """对快照内每张 CRL 做结构与签名复核（只用包内 CA 证书）。"""
    try:
        crls = crlutils.parse_pem_crls(crl_pem)
    except crlutils.PemCrlError as exc:
        raise _err("invalid_crl", f"CRL snapshot material is invalid: {exc}") from exc

    ca_pool: dict[str, x509.Certificate] = {}
    for cert in certutils.parse_pem_chain(root_pem):
        ca_pool[certutils.fingerprint_sha256(cert)] = cert
    for row in cert_rows.values():
        for cert in certutils.parse_pem_chain(row["chain_pem"])[1:]:
            ca_pool.setdefault(certutils.fingerprint_sha256(cert), cert)

    seen: set[tuple[str, str]] = set()
    parsed_rows: list[dict] = []
    for idx, crl in enumerate(crls):
        if crl.next_update_utc is None:
            raise _err("invalid_crl", f"CRL #{idx + 1} is missing nextUpdate")
        if crl.last_update_utc > crl.next_update_utc:
            raise _err(
                "invalid_time",
                f"CRL #{idx + 1} thisUpdate {service.iso_z(crl.last_update_utc)}"
                f" is after nextUpdate {service.iso_z(crl.next_update_utc)}",
            )
        issuer_dn = crl.issuer.rfc4514_string()
        signer = next(
            (
                ca
                for ca in ca_pool.values()
                if ca.subject == crl.issuer
                and crlutils.crl_aki_matches(crl, ca)
                and crlutils.verify_crl_issued_by(crl, ca)
            ),
            None,
        )
        if signer is None:
            raise _err(
                "crl_signature_invalid",
                f"CRL #{idx + 1} issuer '{issuer_dn}' has no valid signer among the"
                " CAs contained in the package (trust root + certificate chains)",
                status=422,
            )
        key_id = crlutils.issuer_key(crl)[1]
        key = (issuer_dn, key_id)
        if key in seen:
            raise _err(
                "invalid_crl",
                f"CRL snapshot contains more than one CRL for issuer '{issuer_dn}'"
                " (key id " + (key_id or "<none>") + ")",
            )
        seen.add(key)
        parsed_rows.append(
            {
                "id": idx + 1,
                "issuer_dn": issuer_dn,
                "issuer_key_id": key_id,
                "crl_number": crlutils.crl_number(crl),
                "_crl": crl,
            }
        )
    return parsed_rows


def _snapshot_from_rows(entries: list[dict], version: str | None):
    by_issuer: dict[tuple[str, str], list] = {}
    for row in entries:
        by_issuer.setdefault((row["issuer_dn"], row["issuer_key_id"]), []).append(
            (row, row["_crl"])
        )
    return {"version": version, "by_issuer": by_issuer}


# --- 冻结判定与重算判定的结构化差异 ---------------------------------------

def _diff_values(path: str, frozen, recomputed, diffs: list[str]) -> None:
    if isinstance(frozen, dict) and isinstance(recomputed, dict):
        keys = sorted(set(frozen) | set(recomputed))
        for k in keys:
            label = f"{path}.{k}" if path else k
            if k not in frozen:
                diffs.append(f"{label}: only in recomputed verdict")
            elif k not in recomputed:
                diffs.append(f"{label}: only in frozen verdict")
            else:
                _diff_values(label, frozen[k], recomputed[k], diffs)
        return
    if isinstance(frozen, list) and isinstance(recomputed, list):
        if len(frozen) != len(recomputed):
            diffs.append(
                f"{path}: list length differs (frozen={len(frozen)},"
                f" recomputed={len(recomputed)})"
            )
            return
        for i, (a, b) in enumerate(zip(frozen, recomputed)):
            _diff_values(f"{path}[{i}]", a, b, diffs)
        return
    if frozen != recomputed:
        diffs.append(f"{path}: frozen={frozen!r} recomputed={recomputed!r}")


def _diff_cert_reports(frozen_reports, recomputed_reports, diffs):
    f_by_id = {r.get("window_id"): r for r in frozen_reports}
    r_by_id = {r.get("window_id"): r for r in recomputed_reports}
    if set(f_by_id) != set(r_by_id):
        diffs.append(
            "certificates: participating window sets differ"
            f" (frozen window_ids={sorted(f_by_id, key=lambda x: (x is None, x or 0))},"
            f" recomputed window_ids={sorted(r_by_id, key=lambda x: (x is None, x or 0))})"
        )
    for wid in f_by_id.keys() & r_by_id.keys():
        _diff_values(f"certificates[window_id={wid}]", f_by_id[wid], r_by_id[wid], diffs)


def _diff_verdicts(frozen: dict, recomputed: dict) -> list[str]:
    diffs: list[str] = []
    scalar_keys = (
        "domain",
        "eval_start",
        "eval_end",
        "trust_root_version",
        "crl_snapshot_version",
        "has_gaps",
        "gaps",
    )
    for k in scalar_keys:
        if frozen.get(k) != recomputed.get(k):
            diffs.append(f"{k}: frozen={frozen.get(k)!r} recomputed={recomputed.get(k)!r}")
    _diff_cert_reports(
        frozen.get("certificates", []), recomputed.get("certificates", []), diffs
    )
    return diffs


def verify_evidence_package(payload: bytes) -> dict:
    """只用包内材料复核一次批准，全程不访问业务数据库。

    返回 ``{"result": "consistent" | "inconsistent", ...}``；材料或结构
    问题抛出 :class:`EvidenceError`。
    """
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        raise _err("malformed_package", "evidence payload is empty")
    if len(payload) > MAX_PACKAGE_BYTES:
        raise _err(
            "malformed_package",
            f"evidence package exceeds the {MAX_PACKAGE_BYTES // 1024 // 1024} MiB limit",
            status=413,
        )
    try:
        archive = zipfile.ZipFile(io.BytesIO(bytes(payload)))
    except zipfile.BadZipFile as exc:
        raise _err("malformed_package", f"payload is not a valid ZIP archive: {exc}") from exc

    with archive as zf:
        names = zf.namelist()
        bad = [n for n in names if n.startswith("/") or ".." in n.split("/")]
        if bad:
            raise _err("malformed_package", f"unsafe ZIP member path(s): {bad}")

        def read(path: str) -> bytes:
            try:
                info = zf.getinfo(path)
            except KeyError:
                raise _err(
                    "missing_material",
                    f"evidence package is missing required file '{path}'",
                ) from None
            if info.is_dir():
                raise _err("malformed_package", f"'{path}' must be a regular file")
            return zf.read(info)

        def read_json(path: str, *, what: str):
            try:
                return json.loads(read(path).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise _err("malformed_package", f"{what} ('{path}') is not valid JSON: {exc}") from exc

        manifest_raw = read(MANIFEST_PATH)
        try:
            manifest = json.loads(manifest_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _err("malformed_package", f"manifest is not valid JSON: {exc}") from exc

        _require_object(manifest, what="manifest")
        if manifest.get("format") != EVIDENCE_FORMAT:
            raise _err(
                "unsupported_format",
                f"unsupported evidence format {manifest.get('format')!r};"
                f" expected {EVIDENCE_FORMAT}",
                status=422,
            )
        approval_meta = manifest.get("approval")
        _require_object(approval_meta, what="manifest.approval")
        domain = manifest.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            raise _err("malformed_package", "manifest.domain must be a non-empty string")
        interval = manifest.get("eval_interval")
        _require_object(interval, what="manifest.eval_interval")
        eval_start_s, eval_end_s = interval.get("start"), interval.get("end")
        eval_start = _parse_iso(eval_start_s, what="manifest.eval_interval.start")
        eval_end = _parse_iso(eval_end_s, what="manifest.eval_interval.end")
        if eval_start >= eval_end:
            raise _err(
                "invalid_time",
                "evaluation interval start "
                f"{eval_start_s} must be strictly before end {eval_end_s}",
            )
        root_version = manifest.get("trust_root_version")
        if not isinstance(root_version, str) or not root_version:
            raise _err("malformed_package", "manifest.trust_root_version must be a non-empty string")
        snapshot_version = manifest.get("crl_snapshot_version")
        if snapshot_version is not None and (
            not isinstance(snapshot_version, str) or not snapshot_version
        ):
            raise _err("malformed_package", "manifest.crl_snapshot_version must be a string or null")
        declared_fps = manifest.get("cert_fingerprints")
        if not isinstance(declared_fps, list) or not declared_fps:
            raise _err("malformed_package", "manifest.cert_fingerprints must be a non-empty array")
        if any(not isinstance(x, str) for x in declared_fps):
            raise _err("malformed_package", "manifest.cert_fingerprints entries must be strings")

        digest_map: dict[str, str] = {}
        files_meta = manifest.get("files")
        if not isinstance(files_meta, list):
            raise _err("malformed_package", "manifest.files must be an array")
        for entry in files_meta:
            _require_object(entry, what="manifest.files[]")
            p = entry.get("path")
            d = entry.get("sha256")
            if not isinstance(p, str) or not isinstance(d, str):
                raise _err(
                    "malformed_package",
                    "manifest.files[] entries need string 'path' and 'sha256'",
                )
            digest_map[p] = d

        expected_paths = {VERDICT_PATH, WINDOWS_PATH, TRUST_ROOT_PATH}
        expected_paths.update(CERTS_DIR + fp + ".pem" for fp in declared_fps)
        if snapshot_version is not None:
            expected_paths.add(CRL_SNAPSHOT_PATH)
        missing_digests = sorted(p for p in expected_paths if p not in digest_map)
        if missing_digests:
            raise _err(
                "missing_material",
                "manifest.files lacks digest entries for required file(s): "
                + ", ".join(missing_digests),
                status=422,
            )

        loaded: dict[str, bytes] = {p: read(p) for p in expected_paths}
        verdict = read_json(VERDICT_PATH, what="verdict.json")
        windows = read_json(WINDOWS_PATH, what="windows.json")

        for path in expected_paths:
            _validate_digest(path, loaded[path], digest_map.get(path))

    _require_object(verdict, what="verdict.json")
    frozen_windows = _validate_window_records(windows)

    # 清单声明的窗口/指纹集合须与窗口集合自洽。
    window_fps = sorted({w["certificate_fingerprint"] for w in frozen_windows})
    if window_fps != sorted(declared_fps):
        raise _err(
            "fingerprint_mismatch",
            "frozen windows reference a different fingerprint set than"
            f" manifest.cert_fingerprints (windows={window_fps},"
            f" manifest={sorted(declared_fps)})",
            status=422,
        )
    if manifest.get("window_count") != len(frozen_windows):
        raise _err(
            "manifest_mismatch",
            f"manifest.window_count={manifest.get('window_count')} but windows.json"
            f" contains {len(frozen_windows)} windows",
            status=422,
        )

    # 冻结判定须与清单头、冻结窗口集合自洽（同一一致性边界冻结）。
    for k, expected in (
        ("domain", domain),
        ("eval_start", service.iso_z(eval_start)),
        ("eval_end", service.iso_z(eval_end)),
        ("trust_root_version", root_version),
        ("crl_snapshot_version", snapshot_version),
    ):
        if verdict.get(k) != expected:
            raise _err(
                "manifest_mismatch",
                f"verdict.{k}={verdict.get(k)!r} disagrees with the frozen manifest"
                f" value {expected!r}",
                status=422,
            )
    verdict_windows = [
        {
            "window_id": c.get("window_id"),
            "certificate_fingerprint": c.get("fingerprint"),
            "role": c.get("role"),
            "start": (c.get("window") or {}).get("start"),
            "end": (c.get("window") or {}).get("end"),
        }
        for c in verdict.get("certificates", [])
    ]
    norm_verdict_windows = []
    for vw in verdict_windows:
        if vw["start"] is None or vw["end"] is None or vw["role"] not in ("current", "planned"):
            raise _err("malformed_package", "verdict.certificates[] window/role data is incomplete")
        norm_verdict_windows.append(
            {
                "window_id": vw["window_id"],
                "certificate_fingerprint": vw["certificate_fingerprint"],
                "role": vw["role"],
                "start": service.iso_z(_parse_iso(vw["start"], what="verdict window start")),
                "end": service.iso_z(_parse_iso(vw["end"], what="verdict window end")),
            }
        )
    if sorted(_canonical_json(w) for w in norm_verdict_windows) != sorted(
        _canonical_json(w) for w in frozen_windows
    ):
        raise _err(
            "frozen_basis_mismatch",
            "the window set frozen in windows.json does not match the windows that"
            " participated in the frozen verdict; package was not produced at a"
            " single consistency boundary",
            status=422,
        )
    if verdict.get("has_gaps"):
        raise _err(
            "frozen_verdict_invalid",
            "the frozen verdict reports coverage gaps; an approval must be gap-free,"
            " so this package cannot represent a valid approval",
            status=422,
        )

    # --- 只使用包内材料重算 ----------------------------------------------
    try:
        root_pem = loaded[TRUST_ROOT_PATH].decode("utf-8")
        roots = certutils.parse_pem_chain(root_pem)
    except UnicodeDecodeError as exc:
        raise _err("invalid_trust_root", f"trust root material is not UTF-8: {exc}")
    except certutils.PemParseError as exc:
        raise _err("invalid_trust_root", f"trust root material is invalid: {exc}") from exc

    cert_pems = {
        fp: loaded[CERTS_DIR + fp + ".pem"]
        for fp in declared_fps
        if (CERTS_DIR + fp + ".pem") in loaded
    }
    cert_rows = _build_cert_rows(cert_pems)

    snapshot = None
    if snapshot_version is not None:
        try:
            crl_pem_text = loaded[CRL_SNAPSHOT_PATH].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _err("invalid_crl", f"CRL snapshot material is not UTF-8: {exc}")
        entries = _verify_crl_materials(crl_pem_text, cert_rows, root_pem)
        snapshot = _snapshot_from_rows(entries, snapshot_version)

    window_rows = [
        {
            "id": w["window_id"],
            "certificate_fingerprint": w["certificate_fingerprint"],
            "role": w["role"],
            "start_utc": w["start"],
            "end_utc": w["end"],
        }
        for w in frozen_windows
    ]
    recomputed = service._evaluation_from_materials(
        domain,
        eval_start,
        eval_end,
        root_version,
        snapshot_version,
        window_rows,
        roots,
        snapshot,
        cert_rows,
    )

    frozen_norm = {k: v for k, v in verdict.items() if k != "evaluated_at"}
    recomputed_norm = {k: v for k, v in recomputed.items() if k != "evaluated_at"}
    diffs = _diff_verdicts(frozen_norm, recomputed_norm)

    return {
        "result": "consistent" if not diffs else "inconsistent",
        "format": EVIDENCE_FORMAT,
        "approval_id": approval_meta.get("approval_id"),
        "plan_id": approval_meta.get("plan_id"),
        "domain": domain,
        "eval_interval": {"start": service.iso_z(eval_start), "end": service.iso_z(eval_end)},
        "trust_root_version": root_version,
        "crl_snapshot_version": snapshot_version,
        "window_count": len(frozen_windows),
        "cert_fingerprints": window_fps,
        "differences": diffs,
        "frozen_verdict": frozen_norm,
        "recomputed_verdict": recomputed_norm,
    }
