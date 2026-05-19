from __future__ import annotations
import asyncio
import uuid
from datetime import datetime, timezone

import nmap

from app.core.logging import logger
from app.core.metrics import (
    findings_total, shadow_services_total, active_scans_gauge,
    scan_duration_seconds,
)
from app.ml.classifier import new_classifier, extract_features
from app.models.scan import (
    FindingModel, ScanRecord, ScanStatus, ScanSummary,
    SeverityBreakdown, ScanType,
)

_scans: dict[str, ScanRecord] = {}


def get_scan(scan_id: str) -> ScanRecord | None:
    return _scans.get(scan_id)


def list_scans() -> list[ScanRecord]:
    return list(_scans.values())


SCAN_ARGS: dict[ScanType, str] = {
    ScanType.quick:   "-sV -T4 --top-ports 100 --open",
    ScanType.full:    "-sV -T3 -p- --open",
    ScanType.stealth: "-sT -Pn -T2 --top-ports 200 --open",
}


async def start_scan(record: ScanRecord, ws_manager) -> None:
    _scans[record.scan_id] = record
    asyncio.create_task(_run(record, ws_manager))


async def _run(record: ScanRecord, ws_manager) -> None:
    sid = record.scan_id
    log = logger.bind(scan_id=sid, target=record.target)
    active_scans_gauge.inc()
    t_start = asyncio.get_event_loop().time()

    try:
        await _emit(ws_manager, sid, "log", f"Scan started — target: {record.target}, mode: {record.scan_type}")

        findings = await _nmap_scan(record, ws_manager)
        record.findings = findings

        if record.run_amass:
            assets = await _amass_enum(record.target, sid, ws_manager)
            record.assets = assets

        if findings:
            classifier = new_classifier()
            all_features = [f.feature_vector for f in findings]
            classifier.fit(all_features)
            for f in findings:
                result = classifier.classify(f.port, f.service, f.state)
                f.risk_score      = result["risk_score"]
                f.risk_level      = result["risk_level"]
                f.category        = result["category"]
                f.is_shadow       = result["is_shadow"]
                f.anomaly_score   = result["anomaly_score"]
                f.description     = result["description"]
                findings_total.labels(
                    category=f.category.value,
                    is_shadow=str(f.is_shadow),
                ).inc()
                if f.is_shadow:
                    shadow_services_total.inc()

        record.summary = _build_summary(record)
        record.status = ScanStatus.completed
        record.completed_at = datetime.now(timezone.utc)

        duration = asyncio.get_event_loop().time() - t_start
        scan_duration_seconds.labels(scan_type=record.scan_type.value).observe(duration)

        shadow_count = sum(1 for f in findings if f.is_shadow)
        await _emit(ws_manager, sid, "complete", {
            "summary": record.summary.model_dump(mode="json"),
            "message": f"Scan complete — {len(findings)} services, {shadow_count} shadow detected",
        })
        log.info("scan_complete", services=len(findings), shadow=shadow_count, duration_s=round(duration, 1))

    except Exception as exc:
        record.status = ScanStatus.failed
        record.error = str(exc)
        record.completed_at = datetime.now(timezone.utc)
        await _emit(ws_manager, sid, "error", f"Scan failed: {exc}")
        log.error("scan_failed", error=str(exc))

    finally:
        active_scans_gauge.dec()


async def _nmap_scan(record: ScanRecord, ws_manager) -> list[FindingModel]:
    sid = record.scan_id
    nm = nmap.PortScanner()
    args = SCAN_ARGS[record.scan_type]

    await _emit(ws_manager, sid, "log", f"Nmap: starting {record.scan_type} scan with args: {args}")

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: nm.scan(hosts=record.target, arguments=args),
        )
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap error: {exc}") from exc

    findings: list[FindingModel] = []
    for host in nm.all_hosts():
        await _emit(ws_manager, sid, "log", f"Host: {host} ({nm[host].state()})")

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                if info.get("state") != "open":
                    continue

                service = info.get("name", "unknown")
                product = info.get("product", "")
                version = info.get("version", "")

                from app.ml.classifier import AnomalyClassifier
                clf = AnomalyClassifier()
                result = clf.classify(port, service, "open")

                finding = FindingModel(
                    id=str(uuid.uuid4()),
                    host=host,
                    port=port,
                    protocol=proto,
                    service=service,
                    product=product,
                    version=version,
                    state="open",
                    risk_score=result["risk_score"],
                    risk_level=result["risk_level"],
                    category=result["category"],
                    is_shadow=result["is_shadow"],
                    description=result["description"],
                    anomaly_score=result["anomaly_score"],
                    feature_vector=result["feature_vector"],
                    discovered_at=datetime.now(timezone.utc),
                )
                findings.append(finding)

                await _emit(ws_manager, sid, "finding", finding.model_dump(mode="json"))
                await asyncio.sleep(0.05)

    await _emit(ws_manager, sid, "log", f"Nmap: discovered {len(findings)} open services")
    return findings


async def _amass_enum(target: str, sid: str, ws_manager) -> list[str]:
    await _emit(ws_manager, sid, "log", f"Amass: passive enumeration for {target}")
    try:
        proc = await asyncio.create_subprocess_exec(
            "amass", "enum", "-passive", "-d", target, "-timeout", "2",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=130)
        assets = [l.strip() for l in stdout.decode().splitlines() if l.strip()]
        for asset in assets:
            await _emit(ws_manager, sid, "asset", {"name": asset, "type": "subdomain"})
        await _emit(ws_manager, sid, "log", f"Amass: found {len(assets)} assets")
        return assets
    except Exception as exc:
        await _emit(ws_manager, sid, "log", f"Amass: {exc} (normal on non-domain targets)")
        return []


def _build_summary(record: ScanRecord) -> ScanSummary:
    findings = record.findings
    scores = [f.risk_score for f in findings] or [0]
    categories: dict[str, int] = {}
    for f in findings:
        categories[f.category.value] = categories.get(f.category.value, 0) + 1

    sev = SeverityBreakdown(
        critical=sum(1 for f in findings if f.risk_score >= 80),
        high=sum(1 for f in findings if 60 <= f.risk_score < 80),
        medium=sum(1 for f in findings if 40 <= f.risk_score < 60),
        low=sum(1 for f in findings if f.risk_score < 40),
    )

    import numpy as np
    return ScanSummary(
        target=record.target,
        total_services=len(findings),
        shadow_count=sum(1 for f in findings if f.is_shadow),
        avg_risk=round(float(np.mean(scores)), 1),
        max_risk=int(max(scores)),
        severity=sev,
        categories=categories,
        scanned_at=record.completed_at or datetime.now(timezone.utc),
    )


async def _emit(ws_manager, sid: str, event_type: str, payload) -> None:
    await ws_manager.broadcast(sid, {"type": event_type, "data": payload})
