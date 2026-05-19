from __future__ import annotations
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from app.models.scan import ScanRecord, ScanRequest, ScanStatus, ScanType
from app.services import scanner
from app.services.ws import ws_manager
from app.services.report import generate_report
from app.core.metrics import scans_total

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", status_code=202)
async def create_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())
    record = ScanRecord(
        scan_id=scan_id,
        target=req.target,
        scan_type=req.scan_type,
        run_amass=req.run_amass,
        status=ScanStatus.pending,
        started_at=datetime.now(timezone.utc),
    )
    scans_total.labels(scan_type=req.scan_type.value, status="started").inc()
    await scanner.start_scan(record, ws_manager)
    return {"scan_id": scan_id, "status": "pending", "target": req.target}


@router.get("")
async def list_scans():
    return [
        {
            "scan_id": s.scan_id,
            "target": s.target,
            "scan_type": s.scan_type,
            "status": s.status,
            "started_at": s.started_at,
            "completed_at": s.completed_at,
            "total_services": len(s.findings),
            "shadow_count": s.summary.shadow_count if s.summary else 0,
        }
        for s in scanner.list_scans()
    ]


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    record = scanner.get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record.model_dump(mode="json")


@router.get("/{scan_id}/report")
async def download_report(scan_id: str):
    record = scanner.get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    if record.status != ScanStatus.completed:
        raise HTTPException(status_code=409, detail="Scan not yet complete")
    path = generate_report(record)
    return FileResponse(
        path,
        media_type="text/markdown",
        filename=f"reconops-report-{scan_id[:8]}.md",
    )


@router.websocket("/{scan_id}/ws")
async def scan_ws(ws: WebSocket, scan_id: str):
    await ws_manager.connect(scan_id, ws)
    try:
        record = scanner.get_scan(scan_id)
        if record:
            for f in record.findings:
                await ws.send_json({"type": "finding", "data": f.model_dump(mode="json")})
            if record.status == ScanStatus.completed and record.summary:
                await ws.send_json({
                    "type": "complete",
                    "data": {
                        "summary": record.summary.model_dump(mode="json"),
                        "message": "Scan already complete",
                    },
                })
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, ws)
