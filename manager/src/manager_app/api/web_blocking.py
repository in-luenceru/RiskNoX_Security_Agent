"""
Web blocking management endpoints
"""

from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog
import uuid

from ..db.database import get_db_session

router = APIRouter(tags=["web-blocking"])
logger = structlog.get_logger()


class BlockedUrl(BaseModel):
    """Blocked URL model"""
    id: str
    url: str = Field(..., description="Blocked URL")
    category: str = Field(..., description="URL category")
    added_at: str = Field(..., description="When the URL was blocked")
    blocked_count: int = Field(default=0, description="Number of times this URL was blocked")
    added_by: Optional[str] = Field(None, description="User who added the block")
    is_active: bool = Field(default=True, description="Whether the block is active")
    agent_ids: List[str] = Field(default_factory=list, description="Agent IDs where this URL is blocked")
    
    class Config:
        from_attributes = True


class BlockedUrlsResponse(BaseModel):
    """Blocked URLs list response"""
    items: List[BlockedUrl]
    total: int
    page: int
    per_page: int
    pages: int


class AddBlockedUrlRequest(BaseModel):
    """Request to add a blocked URL"""
    url: str = Field(..., description="URL to block")
    category: str = Field(..., description="URL category")
    agent_ids: List[str] = Field(..., description="Agent IDs to apply the block to")


class RemoveBlockedUrlRequest(BaseModel):
    """Request to remove a blocked URL"""
    agent_ids: List[str] = Field(..., description="Agent IDs to remove the block from")


# Use database to store blocked URLs instead of in-memory storage
async def get_blocked_urls_from_db(db: AsyncSession) -> List[dict]:
    """Get blocked URLs from database - implemented as stored commands"""
    try:
        from ..db.crud import get_commands_by_type
        
        # Get web blocking commands to see what URLs are blocked
        blocking_commands = await get_commands_by_type(
            db=db,
            command_type="web_block",
            status="completed",
            limit=1000
        )
        
        # Group by URL and collect agent IDs
        url_blocks = {}
        for command in blocking_commands:
            if command.result and command.result.get("success"):
                urls = command.payload.get("urls", [])
                agent_id = command.agent.agent_id if command.agent else "unknown"
                
                for url in urls:
                    if url not in url_blocks:
                        url_blocks[url] = {
                            "id": str(uuid.uuid4()),
                            "url": url,
                            "category": command.payload.get("category", "other"),
                            "added_at": command.created_at.isoformat(),
                            "blocked_count": 0,
                            "added_by": command.created_by,
                            "is_active": True,
                            "agent_ids": []
                        }
                    
                    if agent_id not in url_blocks[url]["agent_ids"]:
                        url_blocks[url]["agent_ids"].append(agent_id)
                        url_blocks[url]["blocked_count"] += 1
        
        return list(url_blocks.values())
        
    except Exception as e:
        logger.error("Failed to get blocked URLs from database", error=str(e))
        return []


@router.get("/web-blocking/urls", response_model=BlockedUrlsResponse)
async def get_blocked_urls(
    category: Optional[str] = Query(None, description="Filter by category"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get blocked URLs with filtering and pagination
    
    Returns a list of currently blocked URLs across all agents,
    with optional filtering by category.
    """
    try:
        # Get blocked URLs from database
        all_blocked_urls = await get_blocked_urls_from_db(db)
        
        # Filter by category if specified
        filtered_urls = all_blocked_urls
        if category:
            filtered_urls = [url for url in filtered_urls if url["category"] == category]
        
        # Apply pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_urls = filtered_urls[start_idx:end_idx]
        
        # Convert to response models
        blocked_urls = [BlockedUrl(**url) for url in paginated_urls]
        
        # Calculate pagination info
        total = len(filtered_urls)
        pages = (total + per_page - 1) // per_page
        
        return BlockedUrlsResponse(
            items=blocked_urls,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        logger.error("Failed to get blocked URLs", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve blocked URLs"
        )


@router.post("/web-blocking/urls")
async def add_blocked_url(
    request: AddBlockedUrlRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Add a new URL to the block list
    
    Adds the URL to the central block list and triggers
    web blocking commands to the specified agents.
    """
    try:
        from ..db.crud import create_command, get_agent_by_id
        from ..ws.connection_manager import connection_manager
        
        # Validate agents exist
        valid_agents = []
        invalid_agents = []
        
        for agent_id in request.agent_ids:
            agent = await get_agent_by_id(db, agent_id)
            if agent:
                valid_agents.append(agent_id)
            else:
                invalid_agents.append(agent_id)
        
        if not valid_agents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid agents specified"
            )
        
        # Create web blocking commands for each agent
        successful_commands = []
        failed_commands = []
        
        for agent_id in valid_agents:
            try:
                # Create command payload
                command_payload = {
                    "urls": [request.url],
                    "category": request.category,
                    "action": "block"
                }
                
                # Create command in database
                expires_at = datetime.utcnow() + timedelta(hours=24)
                command = await create_command(
                    db=db,
                    agent_id=agent_id,
                    command_type="web_block",
                    payload=command_payload,
                    signature="",  # Will be signed before sending
                    created_by="admin",  # TODO: Get from auth context
                    expires_at=expires_at,
                    priority=5
                )
                
                # Send command to agent if online
                if agent_id in connection_manager.agent_connections:
                    command_message = {
                        "type": "command",
                        "command_id": command.command_id,
                        "command_type": "web_block",
                        "payload": command_payload,
                        "expires_at": expires_at.isoformat()
                    }
                    
                    success = await connection_manager.send_command(agent_id, command_message)
                    if success:
                        successful_commands.append({"agent_id": agent_id, "command_id": command.command_id})
                        # Update command status
                        from ..db.crud import update_command_status
                        await update_command_status(db, command.command_id, "sent")
                    else:
                        failed_commands.append({"agent_id": agent_id, "error": "Failed to send command"})
                else:
                    # Agent offline, command will be delivered when agent comes online
                    successful_commands.append({"agent_id": agent_id, "command_id": command.command_id, "status": "queued"})
                    
            except Exception as e:
                logger.error("Failed to create web block command", agent_id=agent_id, error=str(e))
                failed_commands.append({"agent_id": agent_id, "error": str(e)})
        
        logger.info(
            "URL blocking commands created",
            url=request.url,
            category=request.category,
            successful=len(successful_commands),
            failed=len(failed_commands)
        )
        
        return {
            "success": len(successful_commands) > 0,
            "message": f"URL blocking initiated for {len(successful_commands)} agents",
            "url": request.url,
            "successful_commands": successful_commands,
            "failed_commands": failed_commands,
            "invalid_agents": invalid_agents
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to add blocked URL", url=request.url, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add blocked URL"
        )


@router.delete("/web-blocking/urls/{url_id}")
async def remove_blocked_url(
    url_id: str,
    request: RemoveBlockedUrlRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Remove a URL from the block list
    
    Removes the URL from the central block list and triggers
    unblock commands to the specified agents.
    """
    try:
        from ..db.crud import create_command, get_agent_by_id
        from ..ws.connection_manager import connection_manager
        
        # Get the current blocked URLs to find the URL
        blocked_urls = await get_blocked_urls_from_db(db)
        target_url_data = next((url for url in blocked_urls if url["id"] == url_id), None)
        
        if not target_url_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Blocked URL {url_id} not found"
            )
        
        target_url = target_url_data["url"]
        
        # Validate agents exist
        valid_agents = []
        for agent_id in request.agent_ids:
            agent = await get_agent_by_id(db, agent_id)
            if agent:
                valid_agents.append(agent_id)
        
        if not valid_agents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid agents specified"
            )
        
        # Create web unblocking commands for each agent
        successful_commands = []
        failed_commands = []
        
        for agent_id in valid_agents:
            try:
                # Create command payload
                command_payload = {
                    "urls": [target_url],
                    "action": "unblock"
                }
                
                # Create command in database
                expires_at = datetime.utcnow() + timedelta(hours=24)
                command = await create_command(
                    db=db,
                    agent_id=agent_id,
                    command_type="web_unblock",
                    payload=command_payload,
                    signature="",
                    created_by="admin",
                    expires_at=expires_at,
                    priority=5
                )
                
                # Send command to agent if online
                if agent_id in connection_manager.agent_connections:
                    command_message = {
                        "type": "command",
                        "command_id": command.command_id,
                        "command_type": "web_unblock",
                        "payload": command_payload,
                        "expires_at": expires_at.isoformat()
                    }
                    
                    success = await connection_manager.send_command(agent_id, command_message)
                    if success:
                        successful_commands.append({"agent_id": agent_id, "command_id": command.command_id})
                        from ..db.crud import update_command_status
                        await update_command_status(db, command.command_id, "sent")
                    else:
                        failed_commands.append({"agent_id": agent_id, "error": "Failed to send command"})
                else:
                    successful_commands.append({"agent_id": agent_id, "command_id": command.command_id, "status": "queued"})
                    
            except Exception as e:
                logger.error("Failed to create web unblock command", agent_id=agent_id, error=str(e))
                failed_commands.append({"agent_id": agent_id, "error": str(e)})
        
        logger.info(
            "URL unblocking commands created",
            url=target_url,
            url_id=url_id,
            successful=len(successful_commands),
            failed=len(failed_commands)
        )
        
        return {
            "success": len(successful_commands) > 0,
            "message": f"URL unblocking initiated for {len(successful_commands)} agents",
            "url": target_url,
            "successful_commands": successful_commands,
            "failed_commands": failed_commands
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to remove blocked URL", url_id=url_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove blocked URL"
        )


@router.get("/web-blocking/categories")
async def get_blocking_categories(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get available URL blocking categories
    
    Returns a list of predefined categories for organizing
    blocked URLs by type.
    """
    try:
        categories = [
            {"name": "malicious", "description": "Malicious and dangerous websites"},
            {"name": "phishing", "description": "Phishing and scam websites"},
            {"name": "gambling", "description": "Gambling and betting websites"},
            {"name": "adult", "description": "Adult content websites"},
            {"name": "social", "description": "Social media platforms"},
            {"name": "entertainment", "description": "Entertainment and gaming websites"},
            {"name": "shopping", "description": "Shopping websites"},
            {"name": "other", "description": "Other categories"}
        ]
        
        return {
            "categories": categories,
            "total": len(categories)
        }
        
    except Exception as e:
        logger.error("Failed to get blocking categories", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve blocking categories"
        )


@router.get("/web-blocking/stats")
async def get_blocking_stats(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get web blocking statistics
    
    Returns statistics about blocked URLs, block attempts,
    and category distribution.
    """
    try:
        # Get statistics from database
        blocked_urls = await get_blocked_urls_from_db(db)
        
        total_blocked_urls = len(blocked_urls)
        total_block_attempts = sum(url["blocked_count"] for url in blocked_urls)
        
        # Category distribution
        category_stats = {}
        for url in blocked_urls:
            category = url["category"]
            if category not in category_stats:
                category_stats[category] = {"count": 0, "blocks": 0}
            category_stats[category]["count"] += 1
            category_stats[category]["blocks"] += url["blocked_count"]
        
        most_blocked_category = None
        if category_stats:
            most_blocked_category = max(
                category_stats.keys(), 
                key=lambda k: category_stats[k]["blocks"]
            )
        
        return {
            "total_blocked_urls": total_blocked_urls,
            "total_block_attempts": total_block_attempts,
            "category_distribution": category_stats,
            "most_blocked_category": most_blocked_category,
            "active_agents_with_blocks": len(set(
                agent_id for url in blocked_urls for agent_id in url["agent_ids"]
            ))
        }
        
    except Exception as e:
        logger.error("Failed to get blocking stats", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve blocking statistics"
        )