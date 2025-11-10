from fastapi import FastAPI, Depends, BackgroundTasks, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import desc
from db import SessionLocal, Rtarf, SyncStatus, init_db
from elastic_client import es
from dateutil import parser as dateparser
from sqlalchemy.exc import IntegrityError
from typing import Optional
from datetime import datetime
import logging
import uuid

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    """Initialize database on application startup"""
    logger.info("Initializing database tables...")
    init_db()
    logger.info("Database ready!")


# Dependency for DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _extract_fields(source):
    """Extract and normalize fields from Elasticsearch document"""
    # --- Palo-XSIAM ---
    palo = source.get("palo-xsiam") or source
    px_tactics = palo.get("mitre_tactics_ids_and_names")
    px_techniques = palo.get("mitre_techniques_ids_and_names")
    description = palo.get("description")
    severity = palo.get("severity")
    alert_categories = palo.get("alert_categories")

    # --- CrowdStrike ---
    cs_event = source.get("crowdstrike", {}).get("event", {})
    cs_raw = source.get("crowdstrike", {}).get("event", {}).get("MitreAttack", [])
    cs_severity = source.get("crowdstrike", {}).get("event", {}).get("SeverityName")
    cs_event_name = cs_event.get("Name")  
    cs_event_objective = cs_event.get("Objective") 
    
    # --- Suricata ---
    suricata_class = source.get("suricata", {}).get("classification")
    
    # normalize cs_raw to a list of dicts
    if isinstance(cs_raw, dict):
        cs_list = [cs_raw]
    elif isinstance(cs_raw, list):
        cs_list = cs_raw
    else:
        cs_list = []

    # collect all fields across list items
    cs_tactics = []
    cs_tactics_ids = []
    cs_techniques = []
    cs_techniques_ids = []

    for item in cs_list:
        if not isinstance(item, dict):
            continue
        if item.get("Tactic"):
            cs_tactics.append(item["Tactic"])
        if item.get("TacticID"):
            cs_tactics_ids.append(item["TacticID"])
        if item.get("Technique"):
            cs_techniques.append(item["Technique"])
        if item.get("TechniqueID"):
            cs_techniques_ids.append(item["TechniqueID"])

    # --- normalize all lists ---
    def normalize_list(val):
        if val is None:
            return []
        if isinstance(val, str):
            return [v.strip() for v in val.split(",")] if "," in val else [val]
        if isinstance(val, list):
            return val
        return [val]
    
    cs_severity = cs_severity if isinstance(cs_severity, str) else None
    cs_event_name = cs_event_name if isinstance(cs_event_name, str) else None
    cs_event_objective = cs_event_objective if isinstance(cs_event_objective, str) else None
    suricata_class = suricata_class if isinstance(suricata_class, str) else None

    return {
        "palo_tactics": normalize_list(px_tactics),
        "palo_techniques": normalize_list(px_techniques),
        "description": description,
        "severity": severity,
        "alert_categories": normalize_list(alert_categories),
        "cs_tactics": normalize_list(cs_tactics),
        "cs_tactics_ids": normalize_list(cs_tactics_ids),
        "cs_techniques": normalize_list(cs_techniques),
        "cs_techniques_ids": normalize_list(cs_techniques_ids),
        "cs_severity": cs_severity,
        "cs_event_name": cs_event_name,
        "cs_event_objective": cs_event_objective,
        "suricata_classification": suricata_class
    }


async def _bulk_upsert_records(db: Session, records: list):
    """
    Perform bulk upsert using PostgreSQL's ON CONFLICT DO UPDATE
    This is much faster than individual inserts/updates
    """
    if not records:
        return 0, 0
    
    try:
        # Use PostgreSQL's INSERT ... ON CONFLICT for upsert
        stmt = insert(Rtarf).values(records)
        
        # Define what to do on conflict (when event_id already exists)
        update_dict = {
            'mitre_tactics_ids_and_names': stmt.excluded.mitre_tactics_ids_and_names,
            'mitre_techniques_ids_and_names': stmt.excluded.mitre_techniques_ids_and_names,
            'description': stmt.excluded.description,
            'severity': stmt.excluded.severity,
            'alert_categories': stmt.excluded.alert_categories,
            'crowdstrike_tactics': stmt.excluded.crowdstrike_tactics,
            'crowdstrike_tactics_ids': stmt.excluded.crowdstrike_tactics_ids,
            'crowdstrike_techniques': stmt.excluded.crowdstrike_techniques,
            'crowdstrike_techniques_ids': stmt.excluded.crowdstrike_techniques_ids,
            'crowdstrike_severity': stmt.excluded.crowdstrike_severity,
            'crowdstrike_event_name': stmt.excluded.crowdstrike_event_name,
            'crowdstrike_event_objective': stmt.excluded.crowdstrike_event_objective,
            'suricata_classification': stmt.excluded.suricata_classification,
            'timestamp': stmt.excluded.timestamp,
        }
        
        stmt = stmt.on_conflict_do_update(
            index_elements=['event_id'],
            set_=update_dict
        )
        
        result = db.execute(stmt)
        db.commit()
        
        return len(records), 0
        
    except Exception as e:
        db.rollback()
        logger.error(f"Bulk upsert failed: {e}")
        raise


def _update_sync_progress(db: Session, job_id: str, **kwargs):
    """Update sync status in database"""
    try:
        sync_record = db.query(SyncStatus).filter(SyncStatus.job_id == job_id).first()
        if sync_record:
            for key, value in kwargs.items():
                setattr(sync_record, key, value)
            sync_record.last_updated = datetime.utcnow()
            db.commit()
            db.refresh(sync_record)
    except Exception as e:
        logger.error(f"Failed to update sync progress: {e}")
        db.rollback()


async def _sync_rtarf_background(
    job_id: str,
    max_records: Optional[int] = None,
    batch_size: int = 500,
    commit_batch_size: int = 100
):
    """
    Background task for syncing RTARF data with database-tracked status
    """
    logger.info(f"Starting background sync job {job_id} (max_records={max_records})")
    
    db = SessionLocal()
    scroll_time = "2m"
    total_fetched = 0
    total_inserted = 0
    total_updated = 0
    scroll_id = None
    
    query = {
        "query": {
            # "bool": {
            #     "should": [
            #         {"exists": {"field": "palo-xsiam.mitre_tactics_ids_and_names"}},
            #         {"exists": {"field": "crowdstrike.event.MitreAttack.Tactic"}},
            #         # {"exists": {"field": "suricata.classification"}}
            #     ],
            #     "minimum_should_match": 1
            # }
            "match_all": {}
        }
    }
    
    try:
        # Initial search
        resp = await es.search(
            index="rtarf-events-beat*",
            body=query,
            scroll=scroll_time,
            size=batch_size
        )
        scroll_id = resp["_scroll_id"]
        
        # Batch accumulator for bulk operations
        record_batch = []
        
        while True:
            # Check if job was cancelled
            sync_record = db.query(SyncStatus).filter(SyncStatus.job_id == job_id).first()
            if sync_record and sync_record.status == "cancelled":
                logger.info(f"Job {job_id} was cancelled, stopping sync")
                return
            
            hits = resp["hits"]["hits"]
            if not hits:
                break
            
            # Check if we've reached the limit
            if max_records and total_fetched >= max_records:
                logger.info(f"Reached max_records limit: {max_records}")
                break
            
            for hit in hits:
                try:
                    source = hit.get("_source", {})
                    es_id = hit.get("_id")
                    fields = _extract_fields(source)
                    
                    # Parse timestamp with error handling
                    ts = source.get("@timestamp") or source.get("timestamp")
                    parsed_ts = None
                    if ts:
                        try:
                            parsed_ts = dateparser.parse(ts)
                        except Exception as e:
                            logger.warning(f"Failed to parse timestamp for {es_id}: {e}")
                    
                    # Build record dict for bulk operation
                    record = {
                        "event_id": es_id,
                        "mitre_tactics_ids_and_names": fields["palo_tactics"],
                        "mitre_techniques_ids_and_names": fields["palo_techniques"],
                        "description": fields["description"],
                        "severity": fields["severity"],
                        "alert_categories": fields["alert_categories"],
                        "crowdstrike_tactics": fields["cs_tactics"],
                        "crowdstrike_tactics_ids": fields["cs_tactics_ids"],
                        "crowdstrike_techniques": fields["cs_techniques"],
                        "crowdstrike_techniques_ids": fields["cs_techniques_ids"],
                        "crowdstrike_severity": fields["cs_severity"],
                        "crowdstrike_event_name": fields["cs_event_name"],
                        "crowdstrike_event_objective": fields["cs_event_objective"],
                        "suricata_classification": fields["suricata_classification"],
                        "timestamp": parsed_ts
                    }
                    
                    record_batch.append(record)
                    
                    # Perform bulk upsert when batch is full
                    if len(record_batch) >= commit_batch_size:
                        inserted, updated = await _bulk_upsert_records(db, record_batch)
                        total_inserted += inserted
                        total_updated += updated
                        
                        # Update progress in database
                        _update_sync_progress(
                            db, 
                            job_id,
                            records_fetched=total_fetched,
                            records_inserted=total_inserted,
                            records_updated=total_updated
                        )
                        
                        logger.info(f"Job {job_id}: Bulk upserted {len(record_batch)} records")
                        record_batch = []
                    
                except Exception as e:
                    logger.error(f"Error processing document {hit.get('_id')}: {e}")
                    continue
            
            total_fetched += len(hits)
            logger.info(f"Job {job_id}: Fetched {total_fetched} documents...")
            
            # Check limit again
            if max_records and total_fetched >= max_records:
                break
            
            # Fetch next batch
            resp = await es.scroll(scroll_id=scroll_id, scroll=scroll_time)
        
        # Final bulk upsert for remaining records
        if record_batch:
            inserted, updated = await _bulk_upsert_records(db, record_batch)
            total_inserted += inserted
            total_updated += updated
            logger.info(f"Job {job_id}: Final bulk upsert of {len(record_batch)} records")
        
        # Mark as completed
        _update_sync_progress(
            db,
            job_id,
            status="completed",
            completed_at=datetime.utcnow(),
            records_fetched=total_fetched,
            records_inserted=total_inserted,
            records_updated=total_updated
        )
        
        logger.info(f"Job {job_id} completed: fetched={total_fetched}, inserted={total_inserted}")
        
    except Exception as e:
        error_msg = f"Sync failed: {str(e)}"
        logger.error(f"Job {job_id}: {error_msg}")
        
        # Mark as failed
        _update_sync_progress(
            db,
            job_id,
            status="failed",
            completed_at=datetime.utcnow(),
            error_message=error_msg,
            records_fetched=total_fetched,
            records_inserted=total_inserted,
            records_updated=total_updated
        )
        db.rollback()
        
    finally:
        db.close()
        
        # Always cleanup scroll context
        if scroll_id:
            try:
                await es.clear_scroll(scroll_id=scroll_id)
            except Exception as e:
                logger.error(f"Failed to clear scroll: {e}")


@app.get("/sync-rtarf")
async def sync_rtarf_to_postgres(db: Session = Depends(get_db)):
    """Original sync endpoint - synchronous, limited to 300 records"""
    query = {
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "palo-xsiam.mitre_tactics_ids_and_names"}},
                    {"exists": {"field": "crowdstrike.event.MitreAttack.Tactic"}}
                ],
                "minimum_should_match": 1
            }
        }
    }
    
    resp = await es.search(index="rtarf-events-beat*", body=query, size=300)
    
    record_batch = []
    
    for hit in resp["hits"]["hits"]:
        source = hit.get("_source", {})
        es_id = hit.get("_id")
        fields = _extract_fields(source)
        
        ts = source.get("@timestamp") or source.get("timestamp")
        parsed_ts = None
        if ts:
            try:
                parsed_ts = dateparser.parse(ts)
            except Exception:
                parsed_ts = None
        
        record = {
            "event_id": es_id,
            "mitre_tactics_ids_and_names": fields["palo_tactics"],
            "mitre_techniques_ids_and_names": fields["palo_techniques"],
            "description": fields["description"],
            "severity": fields["severity"],
            "alert_categories": fields["alert_categories"],
            "crowdstrike_tactics": fields["cs_tactics"],
            "crowdstrike_tactics_ids": fields["cs_tactics_ids"],
            "crowdstrike_techniques": fields["cs_techniques"],
            "crowdstrike_techniques_ids": fields["cs_techniques_ids"],
            "crowdstrike_severity": fields["cs_severity"],  
            "crowdstrike_event_name": fields["cs_event_name"],
            "crowdstrike_event_objective": fields["cs_event_objective"],
            "suricata_classification": fields["suricata_classification"],
            "timestamp": parsed_ts
        }
        record_batch.append(record)
    
    try:
        inserted, updated = await _bulk_upsert_records(db, record_batch)
        return {"inserted": len(record_batch), "updated": 0}
    except IntegrityError:
        db.rollback()
        return {"error": "integrity error inserting records"}


@app.get("/sync-rtarf-palo")
async def sync_rtarf_palo(db: Session = Depends(get_db)):
    """Sync only Palo-XSIAM events"""
    query = {
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "palo-xsiam.mitre_tactics_ids_and_names"}}
                ],
                "minimum_should_match": 1
            }
        }
    }
    
    resp = await es.search(index="rtarf-events-beat*", body=query, size=100)
    
    record_batch = []
    
    for hit in resp["hits"]["hits"]:
        source = hit.get("_source", {})
        es_id = hit.get("_id")
        fields = _extract_fields(source)
        
        ts = source.get("@timestamp") or source.get("timestamp")
        parsed_ts = None
        if ts:
            try:
                parsed_ts = dateparser.parse(ts)
            except Exception:
                parsed_ts = None
        
        record = {
            "event_id": es_id,
            "mitre_tactics_ids_and_names": fields["palo_tactics"],
            "mitre_techniques_ids_and_names": fields["palo_techniques"],
            "description": fields["description"],
            "severity": fields["severity"],
            "alert_categories": fields["alert_categories"],
            "crowdstrike_tactics": fields["cs_tactics"],
            "crowdstrike_tactics_ids": fields["cs_tactics_ids"],
            "crowdstrike_techniques": fields["cs_techniques"],
            "crowdstrike_techniques_ids": fields["cs_techniques_ids"],
            "crowdstrike_severity": fields["cs_severity"],
            "crowdstrike_event_name": fields["cs_event_name"],
            "crowdstrike_event_objective": fields["cs_event_objective"],
            "suricata_classification": fields["suricata_classification"],
            "timestamp": parsed_ts
        }
        record_batch.append(record)
    
    try:
        inserted, updated = await _bulk_upsert_records(db, record_batch)
        return {"inserted": len(record_batch), "updated": 0}
    except IntegrityError:
        db.rollback()
        return {"error": "integrity error inserting records"}


@app.get("/sync-rtarf-suricata")
async def sync_rtarf_suricata(db: Session = Depends(get_db)):
    """Sync only Suricata events"""
    query = {
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "suricata.classification"}}
                ],
                "minimum_should_match": 1
            }
        }
    }
    
    resp = await es.search(index="rtarf-events-beat*", body=query, size=100)
    
    record_batch = []
    
    for hit in resp["hits"]["hits"]:
        source = hit.get("_source", {})
        es_id = hit.get("_id")
        fields = _extract_fields(source)
        
        ts = source.get("@timestamp") or source.get("timestamp")
        parsed_ts = None
        if ts:
            try:
                parsed_ts = dateparser.parse(ts)
            except Exception:
                parsed_ts = None
        
        record = {
            "event_id": es_id,
            "mitre_tactics_ids_and_names": fields["palo_tactics"],
            "mitre_techniques_ids_and_names": fields["palo_techniques"],
            "description": fields["description"],
            "severity": fields["severity"],
            "alert_categories": fields["alert_categories"],
            "crowdstrike_tactics": fields["cs_tactics"],
            "crowdstrike_tactics_ids": fields["cs_tactics_ids"],
            "crowdstrike_techniques": fields["cs_techniques"],
            "crowdstrike_techniques_ids": fields["cs_techniques_ids"],
            "crowdstrike_severity": fields["cs_severity"],
            "crowdstrike_event_name": fields["cs_event_name"],
            "crowdstrike_event_objective": fields["cs_event_objective"],
            "suricata_classification": fields["suricata_classification"],
            "timestamp": parsed_ts
        }
        record_batch.append(record)
    
    try:
        inserted, updated = await _bulk_upsert_records(db, record_batch)
        return {"inserted": len(record_batch), "updated": 0}
    except IntegrityError:
        db.rollback()
        return {"error": "integrity error inserting records"}


@app.get("/sync-rtarf-crowdstrike")
async def sync_rtarf_crowdstrike(db: Session = Depends(get_db)):
    """Sync only CrowdStrike events"""
    query = {
        "query": {
            "bool": {
                "should": [
                    {"exists": {"field": "crowdstrike.event.MitreAttack.Tactic"}}
                ],
                "minimum_should_match": 1
            }
        }
    }
    
    resp = await es.search(index="rtarf-events-beat*", body=query, size=100)
    
    record_batch = []
    
    for hit in resp["hits"]["hits"]:
        source = hit.get("_source", {})
        es_id = hit.get("_id")
        fields = _extract_fields(source)
        
        ts = source.get("@timestamp") or source.get("timestamp")
        parsed_ts = None
        if ts:
            try:
                parsed_ts = dateparser.parse(ts)
            except Exception:
                parsed_ts = None
        
        record = {
            "event_id": es_id,
            "mitre_tactics_ids_and_names": fields["palo_tactics"],
            "mitre_techniques_ids_and_names": fields["palo_techniques"],
            "description": fields["description"],
            "severity": fields["severity"],
            "alert_categories": fields["alert_categories"],
            "crowdstrike_tactics": fields["cs_tactics"],
            "crowdstrike_tactics_ids": fields["cs_tactics_ids"],
            "crowdstrike_techniques": fields["cs_techniques"],
            "crowdstrike_techniques_ids": fields["cs_techniques_ids"],
            "crowdstrike_severity": fields["cs_severity"],
            "crowdstrike_event_name": fields["cs_event_name"],
            "crowdstrike_event_objective": fields["cs_event_objective"],
            "suricata_classification": fields["suricata_classification"],
            "timestamp": parsed_ts
        }
        record_batch.append(record)
    
    try:
        inserted, updated = await _bulk_upsert_records(db, record_batch)
        return {"inserted": len(record_batch), "updated": 0}
    except IntegrityError:
        db.rollback()
        return {"error": "integrity error inserting records"}


@app.post("/sync-rtarf-all")
async def sync_rtarf_all(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    max_records: Optional[int] = Query(None, description="Maximum number of records to sync (None for all)"),
    batch_size: int = Query(500, description="Elasticsearch scroll batch size"),
    commit_batch_size: int = Query(100, description="Database commit batch size")
):
    """
    Start background sync of RTARF data from Elasticsearch to PostgreSQL
    
    - **max_records**: Limit total records to sync (useful for testing)
    - **batch_size**: How many records to fetch per Elasticsearch scroll
    - **commit_batch_size**: How many records to bulk upsert at once
    
    Returns immediately with job_id for tracking
    """
    # Check if there's already a running sync
    running_sync = db.query(SyncStatus).filter(
        SyncStatus.status == "running"
    ).first()
    
    if running_sync:
        return {
            "status": "already_running",
            "message": "A sync is already in progress",
            "job_id": running_sync.job_id,
            "started_at": running_sync.started_at.isoformat()
        }
    
    # Create new sync job record
    job_id = str(uuid.uuid4())
    sync_record = SyncStatus(
        job_id=job_id,
        status="running",
        started_at=datetime.utcnow(),
        max_records=max_records,
        batch_size=batch_size,
        commit_batch_size=commit_batch_size
    )
    
    try:
        db.add(sync_record)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create sync job: {e}")
    
    # Start background task
    background_tasks.add_task(
        _sync_rtarf_background,
        job_id=job_id,
        max_records=max_records,
        batch_size=batch_size,
        commit_batch_size=commit_batch_size
    )
    
    return {
        "status": "started",
        "message": "Sync started in background",
        "job_id": job_id,
        "max_records": max_records,
        "batch_size": batch_size,
        "commit_batch_size": commit_batch_size
    }


@app.get("/sync-status/{job_id}")
async def get_sync_status_by_id(job_id: str, db: Session = Depends(get_db)):
    """Get the status of a specific sync job by job_id"""
    sync_record = db.query(SyncStatus).filter(SyncStatus.job_id == job_id).first()
    
    if not sync_record:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    return {
        "job_id": sync_record.job_id,
        "status": sync_record.status,
        "started_at": sync_record.started_at.isoformat() if sync_record.started_at else None,
        "completed_at": sync_record.completed_at.isoformat() if sync_record.completed_at else None,
        "last_updated": sync_record.last_updated.isoformat() if sync_record.last_updated else None,
        "max_records": sync_record.max_records,
        "batch_size": sync_record.batch_size,
        "commit_batch_size": sync_record.commit_batch_size,
        "records_fetched": sync_record.records_fetched,
        "records_inserted": sync_record.records_inserted,
        "records_updated": sync_record.records_updated,
        "error_message": sync_record.error_message
    }


@app.get("/sync-status")
async def get_latest_sync_status(db: Session = Depends(get_db)):
    """Get the status of the most recent sync job"""
    sync_record = db.query(SyncStatus).order_by(desc(SyncStatus.started_at)).first()
    
    if not sync_record:
        return {
            "status": "no_jobs",
            "message": "No sync jobs found"
        }
    
    return {
        "job_id": sync_record.job_id,
        "status": sync_record.status,
        "started_at": sync_record.started_at.isoformat() if sync_record.started_at else None,
        "completed_at": sync_record.completed_at.isoformat() if sync_record.completed_at else None,
        "last_updated": sync_record.last_updated.isoformat() if sync_record.last_updated else None,
        "max_records": sync_record.max_records,
        "batch_size": sync_record.batch_size,
        "commit_batch_size": sync_record.commit_batch_size,
        "records_fetched": sync_record.records_fetched,
        "records_inserted": sync_record.records_inserted,
        "records_updated": sync_record.records_updated,
        "error_message": sync_record.error_message
    }


@app.get("/sync-history")
async def get_sync_history(
    limit: int = Query(10, description="Number of recent jobs to return"),
    db: Session = Depends(get_db)
):
    """Get history of sync jobs"""
    sync_records = db.query(SyncStatus).order_by(
        desc(SyncStatus.started_at)
    ).limit(limit).all()
    
    return {
        "total": len(sync_records),
        "jobs": [
            {
                "job_id": record.job_id,
                "status": record.status,
                "started_at": record.started_at.isoformat() if record.started_at else None,
                "completed_at": record.completed_at.isoformat() if record.completed_at else None,
                "records_fetched": record.records_fetched,
                "records_inserted": record.records_inserted,
                "records_updated": record.records_updated,
                "error_message": record.error_message
            }
            for record in sync_records
        ]
    }


@app.delete("/sync-history")
async def clear_sync_history(
    keep_last: int = Query(5, description="Number of recent jobs to keep"),
    db: Session = Depends(get_db)
):
    """Clear old sync history, keeping only the most recent N jobs"""
    # Get all job IDs ordered by date
    all_jobs = db.query(SyncStatus.id).order_by(desc(SyncStatus.started_at)).all()
    
    if len(all_jobs) <= keep_last:
        return {
            "status": "no_deletion",
            "message": f"Only {len(all_jobs)} jobs found, keeping all"
        }
    
    # Get IDs to keep
    keep_ids = [job.id for job in all_jobs[:keep_last]]
    
    # Delete old jobs
    deleted = db.query(SyncStatus).filter(
        ~SyncStatus.id.in_(keep_ids)
    ).delete(synchronize_session=False)
    
    db.commit()
    
    return {
        "status": "success",
        "deleted": deleted,
        "kept": keep_last
    }


@app.post("/sync-stop/{job_id}")
async def stop_sync_job(job_id: str, db: Session = Depends(get_db)):
    """
    Mark a running sync job as stopped/cancelled
    Note: This marks it in the database but doesn't forcefully kill the background task.
    The background task will see this status and stop gracefully at the next checkpoint.
    """
    sync_record = db.query(SyncStatus).filter(SyncStatus.job_id == job_id).first()
    
    if not sync_record:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    if sync_record.status != "running":
        return {
            "status": "not_running",
            "message": f"Job {job_id} is not running (status: {sync_record.status})",
            "job_id": job_id
        }
    
    # Mark as cancelled
    sync_record.status = "cancelled"
    sync_record.completed_at = datetime.utcnow()
    sync_record.error_message = "Manually cancelled by user"
    db.commit()
    
    logger.info(f"Job {job_id} marked as cancelled")
    
    return {
        "status": "cancelled",
        "message": f"Job {job_id} has been marked for cancellation",
        "job_id": job_id,
        "note": "The background task will stop at the next checkpoint"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )