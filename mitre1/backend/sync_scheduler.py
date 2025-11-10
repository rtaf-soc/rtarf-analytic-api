# sync_scheduler.py
# สำหรับรันอัตโนมัติทุก ๆ ช่วงเวลาที่กำหนดไว้ในเซิฟเวอร์จริง
"""
Production-ready scheduler for RTARF sync operations
Supports multiple scheduling strategies and monitoring
"""

import asyncio
import logging
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
import httpx
import os
import signal
import sys

# Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
SYNC_MAX_RECORDS = int(os.getenv("SYNC_MAX_RECORDS", "10000"))
SYNC_BATCH_SIZE = int(os.getenv("SYNC_BATCH_SIZE", "500"))
SYNC_COMMIT_BATCH = int(os.getenv("SYNC_COMMIT_BATCH", "100"))

# Scheduling (choose one strategy below)
SYNC_INTERVAL_MINUTES = int(os.getenv("SYNC_INTERVAL_MINUTES", "60"))  # Every hour
SYNC_CRON = os.getenv("SYNC_CRON", None)  # e.g., "0 */2 * * *" for every 2 hours

# Monitoring
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", None)
EMAIL_ALERTS = os.getenv("EMAIL_ALERTS", None)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SyncScheduler:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.client = httpx.AsyncClient(timeout=30.0)
        self.current_job_id = None
        self.last_sync_status = None
        
    async def start_sync(self):
        """Start a sync job"""
        try:
            logger.info("Starting scheduled sync...")
            
            # Check if previous sync is still running
            status_response = await self.client.get(f"{API_BASE_URL}/sync-status")
            if status_response.status_code == 200:
                status_data = status_response.json()
                if status_data.get("status") == "running":
                    logger.warning(f"Previous sync {status_data.get('job_id')} still running, skipping this cycle")
                    return
            
            # Start new sync
            response = await self.client.post(
                f"{API_BASE_URL}/sync-rtarf-all",
                params={
                    "max_records": SYNC_MAX_RECORDS,
                    "batch_size": SYNC_BATCH_SIZE,
                    "commit_batch_size": SYNC_COMMIT_BATCH
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                self.current_job_id = data.get("job_id")
                logger.info(f"✅ Sync started successfully: {self.current_job_id}")
                
                # Monitor the sync in background
                asyncio.create_task(self.monitor_sync(self.current_job_id))
            else:
                logger.error(f"❌ Failed to start sync: {response.text}")
                await self.send_alert(f"Sync failed to start: {response.text}", "error")
                
        except Exception as e:
            logger.error(f"❌ Error starting sync: {e}")
            await self.send_alert(f"Sync error: {str(e)}", "error")
    
    async def monitor_sync(self, job_id: str):
        """Monitor a sync job until completion"""
        logger.info(f"Monitoring job {job_id}...")
        
        check_interval = 30  # Check every 30 seconds
        timeout = 3600  # 1 hour timeout
        start_time = datetime.now()
        
        while True:
            try:
                # Check if we've exceeded timeout
                if (datetime.now() - start_time).seconds > timeout:
                    logger.error(f"Job {job_id} exceeded timeout of {timeout}s")
                    await self.send_alert(f"Sync job {job_id} timeout", "error")
                    break
                
                # Get job status
                response = await self.client.get(f"{API_BASE_URL}/sync-status/{job_id}")
                
                if response.status_code == 200:
                    status = response.json()
                    self.last_sync_status = status
                    
                    job_status = status.get("status")
                    records_fetched = status.get("records_fetched", 0)
                    records_inserted = status.get("records_inserted", 0)
                    
                    logger.info(
                        f"Job {job_id}: {job_status} - "
                        f"Fetched: {records_fetched}, Inserted: {records_inserted}"
                    )
                    
                    # Check if job is complete
                    if job_status == "completed":
                        logger.info(f"✅ Job {job_id} completed successfully")
                        await self.send_alert(
                            f"Sync completed: {records_inserted} records inserted",
                            "success"
                        )
                        break
                    elif job_status == "failed":
                        error_msg = status.get("error_message", "Unknown error")
                        logger.error(f"❌ Job {job_id} failed: {error_msg}")
                        await self.send_alert(f"Sync failed: {error_msg}", "error")
                        break
                    elif job_status == "cancelled":
                        logger.warning(f"⚠️ Job {job_id} was cancelled")
                        await self.send_alert(f"Sync cancelled: {job_id}", "warning")
                        break
                
                await asyncio.sleep(check_interval)
                
            except Exception as e:
                logger.error(f"Error monitoring job {job_id}: {e}")
                await asyncio.sleep(check_interval)
    
    async def send_alert(self, message: str, level: str = "info"):
        """Send alerts via configured channels"""
        alert_message = f"[{level.upper()}] RTARF Sync Alert: {message}"
        
        # Slack notification
        if SLACK_WEBHOOK:
            try:
                await self.client.post(
                    SLACK_WEBHOOK,
                    json={
                        "text": alert_message,
                        "icon_emoji": "🔄" if level == "info" else ("✅" if level == "success" else "❌")
                    }
                )
            except Exception as e:
                logger.error(f"Failed to send Slack alert: {e}")
        
        # Email notification (implement with your email service)
        if EMAIL_ALERTS:
            # TODO: Implement email alerts
            pass
    
    async def health_check(self):
        """Periodic health check of the API"""
        try:
            response = await self.client.get(f"{API_BASE_URL}/health")
            if response.status_code == 200:
                health = response.json()
                if health.get("status") != "ok":
                    logger.warning(f"⚠️ API health degraded: {health}")
                    await self.send_alert(f"API health degraded: {health}", "warning")
            else:
                logger.error(f"❌ Health check failed: {response.status_code}")
                await self.send_alert("API health check failed", "error")
        except Exception as e:
            logger.error(f"❌ Health check error: {e}")
            await self.send_alert(f"API unreachable: {str(e)}", "error")
    
    def start(self):
        """Start the scheduler"""
        # Add sync job
        if SYNC_CRON:
            # Use cron expression
            logger.info(f"Scheduling sync with cron: {SYNC_CRON}")
            self.scheduler.add_job(
                self.start_sync,
                CronTrigger.from_crontab(SYNC_CRON),
                id="sync_job",
                name="RTARF Sync Job"
            )
        else:
            # Use interval
            logger.info(f"Scheduling sync every {SYNC_INTERVAL_MINUTES} minutes")
            self.scheduler.add_job(
                self.start_sync,
                'interval',
                minutes=SYNC_INTERVAL_MINUTES,
                id="sync_job",
                name="RTARF Sync Job"
            )
        
        # Add health check (every 5 minutes)
        self.scheduler.add_job(
            self.health_check,
            'interval',
            minutes=5,
            id="health_check",
            name="API Health Check"
        )
        
        # Start scheduler
        self.scheduler.start()
        logger.info("✅ Scheduler started successfully")
        
        # Run first sync immediately (optional)
        # asyncio.create_task(self.start_sync())
    
    async def stop(self):
        """Stop the scheduler gracefully"""
        logger.info("Stopping scheduler...")
        self.scheduler.shutdown()
        await self.client.aclose()
        logger.info("✅ Scheduler stopped")


# Signal handlers for graceful shutdown
def signal_handler(signum, frame):
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)


async def main():
    """Main entry point"""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and start scheduler
    scheduler = SyncScheduler()
    scheduler.start()
    
    logger.info("Scheduler is running. Press Ctrl+C to stop.")
    
    # Keep running
    try:
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        await scheduler.stop()


if __name__ == "__main__":
    asyncio.run(main())