"""
Health check and system status endpoints
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as redis
import structlog

from ..db.database import get_db_session
from ..settings import get_settings

router = APIRouter(tags=["health"])
logger = structlog.get_logger()


async def check_database(db: AsyncSession) -> Dict[str, Any]:
    """Check database connectivity"""
    try:
        start_time = time.time()
        result = await db.execute(text("SELECT 1"))
        duration = time.time() - start_time
        
        return {
            "status": "healthy",
            "response_time_ms": round(duration * 1000, 2),
            "connection_pool": {
                "size": db.bind.pool.size(),
                "checked_in": db.bind.pool.checkedin(),
                "checked_out": db.bind.pool.checkedout(),
            }
        }
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "error": str(e)
        }


async def check_redis() -> Dict[str, Any]:
    """Check Redis connectivity"""
    settings = get_settings()
    try:
        start_time = time.time()
        redis_client = redis.from_url(settings.REDIS_URL)
        
        await redis_client.ping()
        info = await redis_client.info()
        
        duration = time.time() - start_time
        await redis_client.close()
        
        return {
            "status": "healthy",
            "response_time_ms": round(duration * 1000, 2),
            "version": info.get("redis_version"),
            "connected_clients": info.get("connected_clients"),
            "memory_usage": info.get("used_memory_human"),
        }
    except Exception as e:
        logger.error("Redis health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "error": str(e)
        }


async def check_s3_storage() -> Dict[str, Any]:
    """Check S3 storage connectivity"""
    settings = get_settings()
    try:
        import boto3
        from botocore.exceptions import ClientError
        
        start_time = time.time()
        
        s3_client = boto3.client(
            's3',
            endpoint_url=settings.S3_ENDPOINT,
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY,
            region_name=settings.S3_REGION
        )
        
        # Try to list objects (minimal operation)
        s3_client.list_objects_v2(Bucket=settings.S3_BUCKET, MaxKeys=1)
        
        duration = time.time() - start_time
        
        return {
            "status": "healthy",
            "response_time_ms": round(duration * 1000, 2),
            "bucket": settings.S3_BUCKET,
            "endpoint": settings.S3_ENDPOINT
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucket':
            return {
                "status": "unhealthy", 
                "error": f"Bucket '{settings.S3_BUCKET}' does not exist"
            }
        return {
            "status": "unhealthy",
            "error": f"S3 error: {error_code}"
        }
    except Exception as e:
        logger.error("S3 health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "error": str(e)
        }


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db_session)):
    """
    Comprehensive health check endpoint
    
    Returns overall system health including:
    - Database connectivity and performance
    - Redis connectivity and stats
    - S3 storage accessibility
    - System resource usage
    """
    start_time = time.time()
    
    # Run health checks concurrently
    database_task = asyncio.create_task(check_database(db))
    redis_task = asyncio.create_task(check_redis())
    s3_task = asyncio.create_task(check_s3_storage())
    
    database_health, redis_health, s3_health = await asyncio.gather(
        database_task, redis_task, s3_task, return_exceptions=True
    )
    
    # Handle exceptions from concurrent tasks
    if isinstance(database_health, Exception):
        database_health = {"status": "unhealthy", "error": str(database_health)}
    if isinstance(redis_health, Exception):
        redis_health = {"status": "unhealthy", "error": str(redis_health)}
    if isinstance(s3_health, Exception):
        s3_health = {"status": "unhealthy", "error": str(s3_health)}
    
    # Determine overall health
    all_healthy = all([
        database_health["status"] == "healthy",
        redis_health["status"] == "healthy", 
        s3_health["status"] == "healthy"
    ])
    
    overall_status = "healthy" if all_healthy else "degraded"
    http_status = status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    
    total_duration = time.time() - start_time
    
    response = {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "0.1.0",
        "checks": {
            "database": database_health,
            "redis": redis_health,
            "storage": s3_health,
        },
        "response_time_ms": round(total_duration * 1000, 2)
    }
    
    # Log health check results
    logger.info(
        "Health check completed",
        status=overall_status,
        duration_ms=round(total_duration * 1000, 2),
        database_status=database_health["status"],
        redis_status=redis_health["status"],
        s3_status=s3_health["status"]
    )
    
    return response


@router.get("/ready") 
async def readiness_check(db: AsyncSession = Depends(get_db_session)):
    """
    Kubernetes readiness probe endpoint
    
    Simple check that core services are available
    """
    try:
        # Quick database check
        await db.execute(text("SELECT 1"))
        
        return {
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return {
            "status": "not ready",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }


@router.get("/live")
async def liveness_check():
    """
    Kubernetes liveness probe endpoint
    
    Basic endpoint to verify the application is running
    """
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }