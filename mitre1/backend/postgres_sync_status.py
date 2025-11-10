# postgres_sync_status.py
"""
Migration script to add sync_status table to existing database.
Run this once to upgrade your database schema.
"""

from sqlalchemy import create_engine, text
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:patpimol00823@localhost:5432/esData"
)

def migrate():
    """Create sync_status table"""
    engine = create_engine(DATABASE_URL)
    
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS sync_status (
        id SERIAL PRIMARY KEY,
        job_id VARCHAR UNIQUE NOT NULL,
        status VARCHAR NOT NULL,
        started_at TIMESTAMP NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMP,
        max_records INTEGER,
        batch_size INTEGER NOT NULL DEFAULT 500,
        commit_batch_size INTEGER NOT NULL DEFAULT 100,
        records_fetched INTEGER NOT NULL DEFAULT 0,
        records_inserted INTEGER NOT NULL DEFAULT 0,
        records_updated INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        last_updated TIMESTAMP NOT NULL DEFAULT NOW()
    );
    
    CREATE INDEX IF NOT EXISTS idx_sync_status_job_id ON sync_status(job_id);
    CREATE INDEX IF NOT EXISTS idx_sync_status_status ON sync_status(status);
    CREATE INDEX IF NOT EXISTS idx_sync_status_started_at ON sync_status(started_at DESC);
    """
    
    try:
        with engine.connect() as conn:
            conn.execute(text(create_table_sql))
            conn.commit()
            logger.info("✅ sync_status table created successfully")
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        raise

if __name__ == "__main__":
    migrate()