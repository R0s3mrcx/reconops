from __future__ import annotations
import asyncio
import re
import uuid
from datetime import datetime, timezone

import nmap

from app.core.logging import logger
from app.core.metrics import (
    findings_total,
    shadow_services_total,
    active_scans_gauge,
    scan_duration_seconds,
)
from app.ml.classifier import new_classifier, AnomalyClassifier
from app.models.scan import (
    FindingModel,
    ScanRecord,
    ScanStatus,
    ScanSummary,
    SeverityBreakdown,
    ScanType,
)

_scans: dict[str, ScanRecord] = {}


def get_scan(scan_id: str) -> ScanRecord | None:
    return _scans.get(scan_id)


def list_scans() -> list[ScanRecord]:
    return list(_scans.values())


# host-timeout scales with scan scope
SCAN_ARGS: dict[ScanType, str] = {
    ScanType.quick:   "-Pn -sT --top-ports 20  --host-timeout 60s",
    ScanType.stealth: "-Pn -sT --top-ports 50  --host-timeout 90s",
    ScanType.full:    "-Pn -sT -p 1-1000       --host-timeout 300s",
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
        await _emit(ws_manager, sid, "log",
            f"Scan started — target: {record.target}, mode: {record.scan_type}")

        findings = await _nmap_scan(record, ws_manager)
        record.findings = findings

        if record.run_amass:
            record.assets = await _amass_enum(record.target, sid, ws_manager)

        # Re-fit ML on full baseline then re-score
        if findings:
            classifier = new_classifier()
            classifier.fit([f.feature_vector for f in findings])
            for f in findings:
                result = classifier.classify(f.port, f.service, f.state)
                f.risk_score    = result["risk_score"]
                f.risk_level    = result["risk_level"]
                f.category      = result["category"]
                f.is_shadow     = result["is_shadow"]
                f.anomaly_score = result["anomaly_score"]
                f.description   = result["description"]
                findings_total.labels(
                    category=f.category.value,
                    is_shadow=str(f.is_shadow),
                ).inc()
                if f.is_shadow:
                    shadow_services_total.inc()

        record.summary      = _build_summary(record)
        record.status       = ScanStatus.completed
        record.completed_at = datetime.now(timezone.utc)
        duration            = asyncio.get_event_loop().time() - t_start
        shadow_count        = sum(1 for f in findings if f.is_shadow)

        scan_duration_seconds.labels(scan_type=record.scan_type.value).observe(duration)

        await _emit(ws_manager, sid, "complete", {
            "summary": record.summary.model_dump(mode="json"),
            "message": f"Scan complete — {len(findings)} services, {shadow_count} shadow detected",
        })
        log.info("scan_complete",
            services=len(findings), shadow=shadow_count, duration_s=round(duration, 1))

    except Exception as exc:
        record.status       = ScanStatus.failed
        record.error        = str(exc)
        record.completed_at = datetime.now(timezone.utc)
        await _emit(ws_manager, sid, "error", f"Scan failed: {exc}")
        log.error("scan_failed", error=str(exc))
    finally:
        active_scans_gauge.dec()


async def _nmap_scan(record: ScanRecord, ws_manager) -> list[FindingModel]:
    sid  = record.scan_id
    nm   = nmap.PortScanner()
    args = SCAN_ARGS[record.scan_type]

    await _emit(ws_manager, sid, "log",
        f"Nmap: starting {record.scan_type} scan")

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: nm.scan(hosts=record.target, arguments=args),
        )
    except nmap.PortScannerError as exc:
        raise RuntimeError(f"Nmap error: {exc}") from exc

    await _emit(ws_manager, sid, "log", f"Nmap command: {nm.command_line()}")

    hosts_with_open = [
        h for h in nm.all_hosts()
        if any(
            nm[h][p][port].get("state", "") == "open"
            for p in nm[h].all_protocols()
            for port in nm[h][p].keys()
        )
    ]
    await _emit(ws_manager, sid, "log",
        f"Hosts with open ports: {len(hosts_with_open)} of {len(nm.all_hosts())} scanned")

    findings: list[FindingModel] = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info  = nm[host][proto][port]
                state = info.get("state", "")
                if "open" not in state:
                    continue

                service = info.get("name", "unknown")
                product = info.get("product", "")
                version = info.get("version", "")

                clf    = AnomalyClassifier()
                result = clf.classify(port, service, state)

                finding = FindingModel(
                    id=str(uuid.uuid4()),
                    host=host,
                    port=port,
                    protocol=proto,
                    service=service,
                    product=product,
                    version=version,
                    state=state,
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

                # Log shadow services only ONCE here (not again after ML re-score)
                if finding.is_shadow:
                    await _emit(ws_manager, sid, "log",
                        f"Shadow service detected — :{port} {service} (risk {result['risk_score']})")

                await _emit(ws_manager, sid, "finding", finding.model_dump(mode="json"))
                await asyncio.sleep(0.05)

    await _emit(ws_manager, sid, "log",
        f"Nmap: discovered {len(findings)} open services")

    return findings


async def _amass_enum(target: str, sid: str, ws_manager) -> list[str]:
    """Passive DNS enumeration. Only works for domain targets, not IPs."""
    is_ip = bool(re.match(r'^[\d./:]+$', target))
    if is_ip:
        await _emit(ws_manager, sid, "log",
            "Amass: skipped — IP target (Amass requires a domain name, e.g. example.com)")
        return []

    await _emit(ws_manager, sid, "log",
        f"Amass: passive subdomain enumeration for {target}")

    try:
        proc = await asyncio.create_subprocess_exec(
            "amass", "enum", "-passive", "-d", target, "-timeout", "2",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=150)
        assets = [l.strip() for l in stdout.decode().splitlines() if l.strip()]

        if assets:
            for asset in assets:
                await _emit(ws_manager, sid, "asset", {"name": asset, "type": "subdomain"})
            await _emit(ws_manager, sid, "log", f"Amass: found {len(assets)} subdomains")
        else:
            err  = stderr.decode().strip()
            note = f" — {err[:100]}" if err else ""
            await _emit(ws_manager, sid, "log", f"Amass: no results returned{note}")

        return assets

    except asyncio.TimeoutError:
        await _emit(ws_manager, sid, "log", "Amass: timed out after 2.5 minutes")
        return []
    except FileNotFoundError:
        await _emit(ws_manager, sid, "log", "Amass: binary not available in this environment")
        return []
    except Exception as exc:
        await _emit(ws_manager, sid, "log", f"Amass: {exc}")
        return []


def _build_summary(record: ScanRecord) -> ScanSummary:
    import numpy as np
    findings   = record.findings
    scores     = [f.risk_score for f in findings] or [0]
    categories: dict[str, int] = {}
    for f in findings:
        categories[f.category.value] = categories.get(f.category.value, 0) + 1

    return ScanSummary(
        target         =record.target,
        total_services =len(findings),
        shadow_count   =sum(1 for f in findings if f.is_shadow),
        avg_risk       =round(float(np.mean(scores)), 1),
        max_risk       =int(max(scores)),
        severity       =SeverityBreakdown(
            critical=sum(1 for f in findings if f.risk_score >= 80),
            high    =sum(1 for f in findings if 60 <= f.risk_score < 80),
            medium  =sum(1 for f in findings if 40 <= f.risk_score < 60),
            low     =sum(1 for f in findings if f.risk_score < 40),
        ),
        categories     =categories,
        scanned_at     =record.completed_at or datetime.now(timezone.utc),
    )


async def _emit(ws_manager, sid: str, event_type: str, payload) -> None:
    await ws_manager.broadcast(sid, {"type": event_type, "data": payload})