"""
Scan management endpoints
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog

from ..db.database import get_db_session
from ..db.crud import get_commands_by_type

router = APIRouter(tags=["scans"])
logger = structlog.get_logger()


class ScanResult(BaseModel):
    """Scan result model"""
    id: str
    agent_id: str
    scan_type: str = Field(..., description="Type of scan: quick, full, custom")
    path: Optional[str] = Field(None, description="Scan path for custom scans")
    status: str = Field(..., description="Scan status: pending, running, completed, failed")
    threats_found: int = Field(default=0, description="Number of threats found")
    files_scanned: int = Field(default=0, description="Number of files scanned")
    started_at: str = Field(..., description="Scan start timestamp")
    completed_at: Optional[str] = Field(None, description="Scan completion timestamp")
    progress: Optional[int] = Field(None, description="Scan progress percentage")
    result_details: Optional[Dict[str, Any]] = Field(None, description="Detailed scan results")
    
    class Config:
        from_attributes = True


class ScanResultsResponse(BaseModel):
    """Scan results list response"""
    items: List[ScanResult]
    total: int
    page: int
    per_page: int
    pages: int


@router.get("/scans", response_model=ScanResultsResponse)
async def get_scan_results(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    status: Optional[str] = Query(None, description="Filter by scan status"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get scan results with filtering and pagination
    
    Returns a list of scan results from agent scan commands,
    with optional filtering by agent, status, or scan type.
    """
    try:
        # Get scan commands from the database
        commands = await get_commands_by_type(
            db=db,
            command_type="scan",
            agent_id=agent_id,
            status=status,
            limit=per_page,
            offset=(page - 1) * per_page
        )
        
        # Convert commands to scan results
        scan_results = []
        for command in commands:
            # Extract scan information from command payload and results
            payload = command.payload or {}
            result = command.result or {}
            
            scan_result = ScanResult(
                id=command.command_id,
                agent_id=command.agent_id,
                scan_type=payload.get("scan_type", "unknown"),
                path=payload.get("path"),
                status=_map_command_status_to_scan_status(command.status),
                threats_found=result.get("threats_found", 0),
                files_scanned=result.get("files_scanned", 0),
                started_at=command.created_at.isoformat(),
                completed_at=command.completed_at.isoformat() if command.completed_at else None,
                progress=result.get("progress"),
                result_details=result
            )
            scan_results.append(scan_result)
        
        # Calculate total pages (simplified - in production, use a proper count query)
        total = len(scan_results)
        pages = (total + per_page - 1) // per_page
        
        return ScanResultsResponse(
            items=scan_results,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        logger.error("Failed to get scan results", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan results"
        )


@router.get("/scans/{scan_id}")
async def get_scan_details(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get detailed information about a specific scan
    
    Returns complete scan information including results,
    threats found, and execution logs.
    """
    try:
        from ..db.crud import get_command_by_id
        
        command = await get_command_by_id(db, scan_id)
        if not command or command.command_type != "scan":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found"
            )
        
        payload = command.payload or {}
        result = command.result or {}
        
        scan_details = {
            "id": command.command_id,
            "agent_id": command.agent_id,
            "scan_type": payload.get("scan_type", "unknown"),
            "path": payload.get("path"),
            "status": _map_command_status_to_scan_status(command.status),
            "threats_found": result.get("threats_found", 0),
            "files_scanned": result.get("files_scanned", 0),
            "started_at": command.created_at.isoformat(),
            "completed_at": command.completed_at.isoformat() if command.completed_at else None,
            "progress": result.get("progress"),
            "result_details": result,
            "command_info": {
                "priority": command.priority,
                "expires_at": command.expires_at.isoformat(),
                "error_message": command.error_message
            }
        }
        
        return scan_details
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan details", scan_id=scan_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan details"
        )


@router.get("/scans/{scan_id}/logs")
async def get_scan_logs(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get real-time logs for a running scan
    
    Returns scan execution logs and progress information
    for monitoring active scans.
    """
    try:
        from ..db.crud import get_command_by_id
        
        command = await get_command_by_id(db, scan_id)
        if not command or command.command_type != "scan":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found"
            )
        
        # Get logs from command result
        result = command.result or {}
        logs = result.get("execution_logs", [])
        
        # Add real-time status information
        if command.status == "running" or command.status == "sent":
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Scan in progress...")
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Files scanned: {result.get('files_scanned', 0)}")
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Threats found: {result.get('threats_found', 0)}")
        elif command.status == "completed":
            if not logs:
                logs = [
                    "Scan completed successfully",
                    f"Total files scanned: {result.get('files_scanned', 0)}",
                    f"Threats found: {result.get('threats_found', 0)}"
                ]
        elif command.status == "failed":
            logs.append(f"Scan failed: {command.error_message or 'Unknown error'}")
        
        return {
            "scan_id": scan_id,
            "logs": logs,
            "status": command.status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan logs", scan_id=scan_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan logs"
        )


def _map_command_status_to_scan_status(command_status: str) -> str:
    """Map command status to scan status"""
    status_mapping = {
        "pending": "pending",
        "sent": "pending", 
        "acknowledged": "running",
        "running": "running",
        "completed": "completed",
        "failed": "failed",
        "expired": "failed"
    }
    return status_mapping.get(command_status, "unknown")