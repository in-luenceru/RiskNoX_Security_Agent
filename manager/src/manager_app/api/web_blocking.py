"""
Web blocking management endpoints
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog

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


# Storage for blocked URLs (in production, this would be in the database)
# Starting with empty list to show real state - URLs will be added dynamically
_blocked_urls_storage = []


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
        # Filter by category if specified
        filtered_urls = _blocked_urls_storage
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
        # Check if URL already exists
        existing_url = next((url for url in _blocked_urls_storage if url["url"] == request.url), None)
        if existing_url:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"URL {request.url} is already blocked"
            )
        
        # Add to storage
        new_blocked_url = {
            "id": str(len(_blocked_urls_storage) + 1),
            "url": request.url,
            "category": request.category,
            "added_at": datetime.now().isoformat(),
            "blocked_count": 0,
            "added_by": "admin",  # TODO: Get from auth context
            "is_active": True
        }
        _blocked_urls_storage.append(new_blocked_url)
        
        logger.info(
            "URL added to block list",
            url=request.url,
            category=request.category,
            agent_count=len(request.agent_ids)
        )
        
        return {
            "success": True,
            "message": f"URL {request.url} added to block list",
            "blocked_url": BlockedUrl(**new_blocked_url),
            "agent_count": len(request.agent_ids)
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
        # Find the URL to remove
        url_index = next((i for i, url in enumerate(_blocked_urls_storage) if url["id"] == url_id), None)
        if url_index is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Blocked URL {url_id} not found"
            )
        
        # Remove from storage
        removed_url = _blocked_urls_storage.pop(url_index)
        
        logger.info(
            "URL removed from block list",
            url=removed_url["url"],
            url_id=url_id,
            agent_count=len(request.agent_ids)
        )
        
        return {
            "success": True,
            "message": f"URL {removed_url['url']} removed from block list",
            "removed_url": removed_url["url"],
            "agent_count": len(request.agent_ids)
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
        # Calculate statistics from storage
        total_blocked_urls = len(_blocked_urls_storage)
        total_block_attempts = sum(url["blocked_count"] for url in _blocked_urls_storage)
        
        # Category distribution
        category_stats = {}
        for url in _blocked_urls_storage:
            category = url["category"]
            if category not in category_stats:
                category_stats[category] = {"count": 0, "blocks": 0}
            category_stats[category]["count"] += 1
            category_stats[category]["blocks"] += url["blocked_count"]
        
        return {
            "total_blocked_urls": total_blocked_urls,
            "total_block_attempts": total_block_attempts,
            "category_distribution": category_stats,
            "most_blocked_category": max(category_stats.keys(), key=lambda k: category_stats[k]["blocks"]) if category_stats else None
        }
        
    except Exception as e:
        logger.error("Failed to get blocking stats", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve blocking statistics"
        )