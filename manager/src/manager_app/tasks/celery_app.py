"""
Celery application setup for background task processing
"""

from celery import Celery
from celery.schedules import crontab
import structlog

from ..settings import get_settings

logger = structlog.get_logger()

# Get settings
settings = get_settings()

# Create Celery application
celery_app = Celery(
    "manager",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.REDIS_URL,
    include=[
        'manager_app.tasks.command_delivery',
        'manager_app.tasks.scheduler',
        'manager_app.tasks.maintenance'
    ]
)

# Celery configuration
celery_app.conf.update(
    # Task routing
    task_routes={
        'manager_app.tasks.command_delivery.*': {'queue': 'commands'},
        'manager_app.tasks.scheduler.*': {'queue': 'scheduler'},
        'manager_app.tasks.maintenance.*': {'queue': 'maintenance'},
    },
    
    # Task serialization
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    
    # Task execution
    task_always_eager=False,
    task_eager_propagates=True,
    task_ignore_result=False,
    
    # Worker configuration
    worker_max_tasks_per_child=1000,
    worker_prefetch_multiplier=4,
    
    # Timezone
    timezone='UTC',
    enable_utc=True,
    
    # Beat schedule for periodic tasks
    beat_schedule={
        # Cleanup stale connections every 5 minutes
        'cleanup-stale-connections': {
            'task': 'manager_app.tasks.maintenance.cleanup_stale_connections',
            'schedule': crontab(minute='*/5'),
        },
        
        # Process scheduled scans every minute
        'process-scheduled-scans': {
            'task': 'manager_app.tasks.scheduler.process_scheduled_scans',
            'schedule': crontab(minute='*'),
        },
        
        # Certificate expiry check daily at 2 AM
        'check-certificate-expiry': {
            'task': 'manager_app.tasks.maintenance.check_certificate_expiry',
            'schedule': crontab(hour=2, minute=0),
        },
        
        # Retry failed commands every 10 minutes
        'retry-failed-commands': {
            'task': 'manager_app.tasks.command_delivery.retry_failed_commands',
            'schedule': crontab(minute='*/10'),
        },
    },
)


@celery_app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery setup"""
    logger.info("Celery debug task executed", request_id=self.request.id)
    return {'status': 'success', 'message': 'Celery is working!'}


if __name__ == '__main__':
    celery_app.start()