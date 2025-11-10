# postgres_api.py
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import String, func, and_, or_, desc
from typing import List, Optional, Dict, Any, Set
from pydantic import BaseModel
from datetime import datetime, timedelta
from db import SessionLocal, Rtarf
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="MITRE ATT&CK PostgreSQL API",
    description="FastAPI endpoints using PostgreSQL as data source"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency for DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ===================================
# Pydantic Models
# ===================================

class Technique(BaseModel):
    id: str
    eventIds: List[int] = []

class DateRange(BaseModel):
    start: str
    end: str

class TechniqueStatsRequest(BaseModel):
    techniques: List[Technique]
    dateRange: Optional[DateRange] = None

class StatsRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    dayRange: Optional[int] = 7

class SearchRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    size: Optional[int] = 10
    page: Optional[int] = 1

class TopTechniquesRequest(BaseModel):
    dayRange: Optional[int] = 7
    limit: Optional[int] = 5
    tactic: Optional[str] = "all"


# ===================================
# Helper Functions
# ===================================

def parse_date_range(date_range: Optional[DateRange], day_range: Optional[int] = 7):
    """Parse date range from request or calculate from day_range"""
    if date_range:
        try:
            start = datetime.fromisoformat(date_range.start.replace("Z", "+00:00"))
            end = datetime.fromisoformat(date_range.end.replace("Z", "+00:00"))
        except Exception as e:
            logger.error(f"Error parsing dates: {e}")
            end = datetime.utcnow()
            start = end - timedelta(days=day_range or 7)
    else:
        end = datetime.utcnow()
        start = end - timedelta(days=day_range or 7)
    
    return start, end


def extract_tactic_id(tactic_value: str) -> str:
    """Extract tactic ID from combined format like 'TA0002 - Execution'"""
    if not tactic_value:
        return None
    if " - " in tactic_value:
        return tactic_value.split(" - ")[0].strip()
    return tactic_value.strip()


def extract_technique_id(technique_value: str) -> str:
    """Extract technique ID from combined format like 'T1059 - Command and Scripting'"""
    if not technique_value:
        return None
    if " - " in technique_value:
        return technique_value.split(" - ")[0].strip()
    return technique_value.strip()


def calculate_severity(count: int, last_seen: datetime, cs_severity: str = None) -> str:
    """
    Calculate severity based on count, recency, and CrowdStrike severity
    
    CrowdStrike Severity Scale (as strings):
    - "Critical" or "5"
    - "High" or "4"
    - "Medium" or "3"
    - "Low" or "2"
    - "Informational" or "1"
    """
    # If we have CrowdStrike severity, use it as primary indicator
    if cs_severity:
        cs_severity_lower = str(cs_severity).lower()
        
        # Handle both numeric and string formats
        if cs_severity_lower in ["critical", "5"]:
            return "critical"
        elif cs_severity_lower in ["high", "4"]:
            return "high"
        elif cs_severity_lower in ["medium", "3"]:
            return "medium"
        elif cs_severity_lower in ["low", "2", "informational", "1"]:
            return "low"
    
    # Fallback to count/recency based calculation
    if not last_seen:
        return "none" if count == 0 else "low"
    
    days_ago = (datetime.utcnow() - last_seen).days
    
    # High volume recent activity
    if count >= 100 and days_ago <= 1:
        return "critical"
    elif count >= 50 and days_ago <= 7:
        return "high"
    elif count >= 10 and days_ago <= 30:
        return "medium"
    elif count > 0:
        return "low"
    else:
        return "none"
    
# ===================================
# Mapper Function
# ===================================

# CrowdStrike Tactic IDs to MITRE ATT&CK mapping
CROWDSTRIKE_TACTIC_MAPPING = {
    "CSTA0001": "TA0043",  # Reconnaissance -> Reconnaissance
    "CSTA0002": "TA0042",  # Resource Development -> Resource Development
    "CSTA0003": "TA0001",  # Initial Access -> Initial Access
    "CSTA0004": "TA0002",  # Execution -> Execution
    "CSTA0005": "TA0003",  # Persistence -> Persistence
    "CSTA0006": "TA0004",  # Privilege Escalation -> Privilege Escalation
    "CSTA0007": "TA0005",  # Defense Evasion -> Defense Evasion
    "CSTA0008": "TA0006",  # Credential Access -> Credential Access
    "CSTA0009": "TA0007",  # Discovery -> Discovery
    "CSTA0010": "TA0008",  # Lateral Movement -> Lateral Movement
    "CSTA0011": "TA0009",  # Collection -> Collection
    "CSTA0012": "TA0011",  # Command and Control -> Command and Control
    "CSTA0013": "TA0010",  # Exfiltration -> Exfiltration
    "CSTA0014": "TA0040",  # Impact -> Impact
}

# CrowdStrike CST ID to MITRE ATT&CK Technique ID Mapping
CROWDSTRIKE_TECHNIQUE_ID_MAPPING = {
    # CrowdStrike-specific detection methods (no MITRE equivalent)
    "CST0003": None,  # Suspicious Activity
    "CST0006": None,  # Adware/PUP
    "CST0007": None,  # Sensor-based ML
    "CST0008": None,  # Cloud-based ML
    "CST0012": None,  # Exploit Mitigation
    "CST0013": None,  # PUP
    "CST0021": "T1059",  # Command and Scripting Interpreter
    
    # Add more CST mappings as you discover them in your data
}

# CrowdStrike Technique Names to MITRE ATT&CK Technique IDs Mapping
CROWDSTRIKE_TECHNIQUE_NAME_MAPPING = {
    # MITRE ATT&CK Techniques (Direct Mappings)
    "Application Layer Protocol": "T1071",
    "Masquerading": "T1036",
    "Indirect Command Execution": "T1202",
    "Shared Modules": "T1129",
    "Ingress Tool Transfer": "T1105",
    "Process Injection": "T1055",
    "PowerShell": "T1059.001",
    "Inhibit System Recovery": "T1490",
    "Data Encrypted for Impact": "T1486",
    "Registry Run Keys / Startup Folder": "T1547.001",
    "Disable or Modify Tools": "T1562.001",
    "Command and Scripting Interpreter": "T1059",
    "Remote Access Tools": "T1219",
    
    # CrowdStrike-Specific Detection Methods (No direct MITRE equivalent)
    "Sensor-based ML": None,  # CST0007
    "Cloud-based ML": None,  # CST0008
    "PUP": None,  # CST0013
    "Adware/PUP": None,  # CST0006
    "Suspicious Activity": None,  # CST0003
    "Exploit Mitigation": None,  # CST0012
}

# CrowdStrike Technique prefixes that need mapping
CROWDSTRIKE_TECHNIQUE_PREFIXES = ["CST", "CSTA"]


def normalize_tactic_id(tactic_id: str) -> str:
    """
    Normalize tactic ID to MITRE ATT&CK format
    Converts CrowdStrike CSTA#### to MITRE TA####
    
    Args:
        tactic_id: Original tactic ID (e.g., "CSTA0001" or "TA0001")
    
    Returns:
        MITRE ATT&CK tactic ID (e.g., "TA0043")
    """
    if not tactic_id:
        return None
    
    # Extract clean ID
    clean_id = extract_tactic_id(tactic_id)
    
    # Check if it's a CrowdStrike tactic
    if clean_id and clean_id.startswith("CSTA"):
        mitre_id = CROWDSTRIKE_TACTIC_MAPPING.get(clean_id)
        if mitre_id:
            logger.debug(f"Mapped CrowdStrike tactic {clean_id} -> MITRE {mitre_id}")
            return mitre_id
        else:
            logger.warning(f"Unknown CrowdStrike tactic ID: {clean_id}")
            return clean_id  # Return original if no mapping found
    
    return clean_id


def normalize_technique_id(technique_id: str) -> str:
    """
    Normalize technique ID to MITRE ATT&CK format
    
    Handles:
    - Standard MITRE IDs (T1234, T1234.001)
    - CrowdStrike CST IDs (CST0007 -> mapped or None)
    
    Args:
        technique_id: Original technique ID (e.g., "CST0007", "T1059")
    
    Returns:
        MITRE ATT&CK technique ID or None if no mapping exists
    """
    if not technique_id:
        return None
    
    # Extract clean ID
    clean_id = extract_technique_id(technique_id)
    
    # Check if it's a CrowdStrike CST ID
    if clean_id and clean_id.startswith("CST"):
        mitre_id = CROWDSTRIKE_TECHNIQUE_ID_MAPPING.get(clean_id)
        if mitre_id:
            logger.debug(f"Mapped CrowdStrike CST {clean_id} -> MITRE {mitre_id}")
        else:
            logger.debug(f"CrowdStrike-specific technique (no MITRE mapping): {clean_id}")
        return mitre_id  # Returns None for CrowdStrike-specific detections
    
    # Return as-is if already MITRE format (T####)
    return clean_id

def normalize_crowdstrike_technique_name(technique_name: str) -> str:
    """
    Normalize CrowdStrike technique name to MITRE ATT&CK technique ID
    
    Args:
        technique_name: CrowdStrike technique name (e.g., "PowerShell", "Sensor-based ML")
    
    Returns:
        MITRE ATT&CK technique ID (e.g., "T1059.001") or None if no mapping exists
    """
    if not technique_name:
        return None
    
    # Clean the technique name
    clean_name = technique_name.strip()
    
    # Look up in mapping
    mitre_id = CROWDSTRIKE_TECHNIQUE_NAME_MAPPING.get(clean_name)
    
    if mitre_id:
        logger.debug(f"Mapped CrowdStrike technique '{clean_name}' -> MITRE {mitre_id}")
    else:
        logger.debug(f"CrowdStrike-specific technique (no MITRE mapping): '{clean_name}'")
    
    return mitre_id


def get_all_tactic_ids_from_record(record: Rtarf) -> List[str]:
    """
    Extract and normalize all tactic IDs from a record
    Combines Palo-XSIAM and CrowdStrike tactics, normalized to MITRE format
    
    Args:
        record: Rtarf database record
    
    Returns:
        List of normalized MITRE tactic IDs
    """
    tactic_ids = set()
    
    # From Palo-XSIAM
    if record.mitre_tactics_ids_and_names:
        try:
            tactics = record.mitre_tactics_ids_and_names if isinstance(record.mitre_tactics_ids_and_names, list) else []
            for tactic in tactics:
                normalized = normalize_tactic_id(tactic)
                if normalized:
                    tactic_ids.add(normalized)
        except Exception as e:
            logger.warning(f"Error parsing Palo tactics: {e}")
    
    # From CrowdStrike
    if record.crowdstrike_tactics_ids:
        try:
            tactics = record.crowdstrike_tactics_ids if isinstance(record.crowdstrike_tactics_ids, list) else []
            for tactic in tactics:
                normalized = normalize_tactic_id(tactic)
                if normalized:
                    tactic_ids.add(normalized)
        except Exception as e:
            logger.warning(f"Error parsing CrowdStrike tactics: {e}")
    
    return list(tactic_ids)


def get_all_technique_ids_from_record(record: Rtarf) -> List[str]:
    """
    Extract and normalize all technique IDs from a record
    Combines Palo-XSIAM techniques, CrowdStrike technique IDs, and CrowdStrike technique names
    
    Args:
        record: Rtarf database record
    
    Returns:
        List of normalized MITRE technique IDs (duplicates removed, None values filtered)
    """
    technique_ids = set()
    
    # From Palo-XSIAM (MITRE technique IDs)
    if record.mitre_techniques_ids_and_names:
        try:
            techniques = record.mitre_techniques_ids_and_names if isinstance(record.mitre_techniques_ids_and_names, list) else []
            for technique in techniques:
                normalized = normalize_technique_id(technique)
                if normalized and normalized.startswith("T"):
                    technique_ids.add(normalized)
        except Exception as e:
            logger.warning(f"Error parsing Palo techniques: {e}")
    
    # From CrowdStrike technique IDs (both T#### and CST#### formats)
    if record.crowdstrike_techniques_ids:
        try:
            techniques = record.crowdstrike_techniques_ids if isinstance(record.crowdstrike_techniques_ids, list) else []
            for technique in techniques:
                # Handle both T#### (already MITRE) and CST#### (needs mapping)
                technique_str = str(technique)
                if technique_str.startswith("T"):
                    # Already MITRE format
                    technique_ids.add(technique_str)
                elif technique_str.startswith("CST"):
                    # Map CST to MITRE
                    normalized = normalize_technique_id(technique_str)
                    if normalized:  # Only add if mapping exists
                        technique_ids.add(normalized)
        except Exception as e:
            logger.warning(f"Error parsing CrowdStrike technique IDs: {e}")
    
    # From CrowdStrike technique NAMES (backup/validation)
    if hasattr(record, 'crowdstrike_techniques') and record.crowdstrike_techniques:
        try:
            techniques = record.crowdstrike_techniques if isinstance(record.crowdstrike_techniques, list) else []
            for technique_name in techniques:
                mitre_id = normalize_crowdstrike_technique_name(str(technique_name))
                if mitre_id:  # Only add if mapping exists
                    technique_ids.add(mitre_id)
        except Exception as e:
            logger.warning(f"Error parsing CrowdStrike technique names: {e}")
    
    return list(technique_ids)

def get_crowdstrike_detection_methods(record: Rtarf) -> List[str]:
    """
    Extract CrowdStrike-specific detection methods that don't map to MITRE
    Useful for tracking HOW threats were detected
    
    Args:
        record: Rtarf database record
    
    Returns:
        List of CrowdStrike detection method names/IDs
    """
    detection_methods = set()
    
    # From CST IDs
    if record.crowdstrike_techniques_ids:
        try:
            techniques = record.crowdstrike_techniques_ids if isinstance(record.crowdstrike_techniques_ids, list) else []
            for technique in techniques:
                technique_str = str(technique)
                if technique_str.startswith("CST"):
                    # Check if it's a CrowdStrike-specific detection (no MITRE mapping)
                    if CROWDSTRIKE_TECHNIQUE_ID_MAPPING.get(technique_str) is None:
                        detection_methods.add(technique_str)
        except Exception as e:
            logger.warning(f"Error parsing CrowdStrike detection methods: {e}")
    
    # From technique names
    if hasattr(record, 'crowdstrike_techniques') and record.crowdstrike_techniques:
        try:
            techniques = record.crowdstrike_techniques if isinstance(record.crowdstrike_techniques, list) else []
            for technique_name in techniques:
                name_str = str(technique_name)
                # Check if it's a CrowdStrike-specific detection
                if CROWDSTRIKE_TECHNIQUE_NAME_MAPPING.get(name_str) is None:
                    detection_methods.add(name_str)
        except Exception as e:
            logger.warning(f"Error parsing CrowdStrike detection method names: {e}")
    
    return list(detection_methods)


def should_include_in_mitre_filter(tactic_id: str = None, technique_id: str = None, 
                                    include_crowdstrike_specific: bool = False) -> bool:
    """
    Determine if a tactic/technique should be included in MITRE ATT&CK filtering
    
    Args:
        tactic_id: Tactic ID to check
        technique_id: Technique ID to check
        include_crowdstrike_specific: Whether to include CrowdStrike-specific IDs
    
    Returns:
        True if should be included in filtering
    """
    if not include_crowdstrike_specific:
        # Exclude CrowdStrike-specific techniques that don't map to MITRE
        if technique_id and any(technique_id.startswith(prefix) for prefix in CROWDSTRIKE_TECHNIQUE_PREFIXES):
            return False
    
    return True


# ===================================
# Endpoint 1: Technique Statistics (with CrowdStrike mapping) (Matrix View tab)
# ===================================

@app.post("/api/postgres/technique-stats", summary="Get statistics for MITRE techniques from PostgreSQL")
async def get_technique_stats(
    request: TechniqueStatsRequest,
    db: Session = Depends(get_db)
):
    """
    Get detection counts and latest timestamps for specified MITRE techniques.
    Supports MITRE ATT&CK IDs, CrowdStrike CST IDs, and CrowdStrike technique names.
    Automatically maps CrowdStrike identifiers to MITRE when possible.
    Returns unified severity for ATT&CK Navigator but also keeps original severities.
    """
    try:
        start_date, end_date = parse_date_range(request.dateRange)
        all_stats = {}

        for tech in request.techniques:
            technique_id = tech.id
            normalized_technique_id = normalize_technique_id(technique_id)

            # Base query for count and last_seen
            query = db.query(
                func.count(Rtarf.id).label("count"),
                func.max(Rtarf.timestamp).label("last_seen")
            ).filter(
                and_(
                    Rtarf.timestamp >= start_date,
                    Rtarf.timestamp <= end_date
                )
            )

            # Build list of technique identifiers to search for
            technique_conditions = []
            search_ids = [technique_id]
            if normalized_technique_id and normalized_technique_id != technique_id:
                search_ids.append(normalized_technique_id)

            # Reverse mappings: CrowdStrike CST IDs & technique names that map to this MITRE ID
            reverse_cst_ids = [
                cst_id for cst_id, mitre_id in CROWDSTRIKE_TECHNIQUE_ID_MAPPING.items()
                if mitre_id == normalized_technique_id
            ]
            reverse_names = [
                name for name, mitre_id in CROWDSTRIKE_TECHNIQUE_NAME_MAPPING.items()
                if mitre_id == normalized_technique_id
            ]

            # Search in Palo (mitre_techniques_ids_and_names)
            for s in search_ids:
                try:
                    technique_conditions.append(
                        func.jsonb_array_length(
                            func.jsonb_path_query_array(
                                Rtarf.mitre_techniques_ids_and_names,
                                f'$[*] ? (@ like_regex "{s}" flag "i")'
                            )
                        ) > 0
                    )
                except:
                    pass

            # Search in CrowdStrike technique IDs
            for s in search_ids + reverse_cst_ids:
                try:
                    technique_conditions.append(
                        func.jsonb_array_length(
                            func.jsonb_path_query_array(
                                Rtarf.crowdstrike_techniques_ids,
                                f'$[*] ? (@ like_regex "{s}" flag "i")'
                            )
                        ) > 0
                    )
                except:
                    pass

            # Search in CrowdStrike technique names
            for n in reverse_names:
                try:
                    technique_conditions.append(
                        func.jsonb_array_length(
                            func.jsonb_path_query_array(
                                Rtarf.crowdstrike_techniques,
                                f'$[*] ? (@ like_regex "{n}" flag "i")'
                            )
                        ) > 0
                    )
                except:
                    pass

            # If no JSON path matches → fallback to ILIKE string search
            if not technique_conditions:
                for s in search_ids + reverse_cst_ids:
                    technique_conditions.extend([
                        func.cast(Rtarf.mitre_techniques_ids_and_names, String).ilike(f"%{s}%"),
                        func.cast(Rtarf.crowdstrike_techniques_ids, String).ilike(f"%{s}%")
                    ])
                for n in reverse_names:
                    technique_conditions.append(
                        func.cast(Rtarf.crowdstrike_techniques, String).ilike(f"%{n}%")
                    )

            # No matches anywhere → return empty
            if not technique_conditions:
                all_stats[technique_id] = {
                    "count": 0,
                    "severity": "none",
                    "paloSeverity": None,
                    "crowdStrikeSeverity": None,
                    "lastSeen": None,
                    "normalizedId": normalized_technique_id
                }
                continue

            # Apply the OR condition list
            query = query.filter(or_(*technique_conditions))
            result = query.first()

            count = result.count if result and result.count else 0
            last_seen = result.last_seen if result and result.last_seen else None

            # Get one sample event for severity, source and detection methods
            palo_severity = None
            cs_severity = None
            source_type = None
            detection_methods = []

            if count > 0:
                sample = db.query(Rtarf).filter(
                    Rtarf.timestamp >= start_date,
                    Rtarf.timestamp <= end_date
                ).filter(
                    or_(*technique_conditions)
                ).first()

                if sample:
                    palo_severity = sample.severity
                    cs_severity = sample.crowdstrike_severity

                    if sample.crowdstrike_techniques or sample.crowdstrike_techniques_ids:
                        source_type = "crowdstrike"
                    elif sample.mitre_techniques_ids_and_names:
                        source_type = "palo-xsiam"

                    detection_methods = get_crowdstrike_detection_methods(sample)

            # ✅ Final unified severity used in ATT&CK Navigator
            final_severity = calculate_severity(count, last_seen, cs_severity)

            all_stats[technique_id] = {
                "count": count,
                "severity": final_severity,  # unified severity
                "paloSeverity": palo_severity,
                "crowdStrikeSeverity": cs_severity,
                "lastSeen": last_seen.isoformat() if last_seen else None,
                "normalizedId": normalized_technique_id if normalized_technique_id != technique_id else None,
                "sourceType": source_type,
                "detectionMethods": detection_methods
            }

        return all_stats

    except Exception as e:
        logger.error(f"Error in technique-stats: {e}")
        raise HTTPException(status_code=500, detail="Error fetching technique stats")

# ===================================
# Endpoint 2: Overall Statistics (Matrix View tab)
# ===================================

@app.post("/api/postgres/stats", summary="Get overall statistics from PostgreSQL")
async def get_statistics(
    request: StatsRequest,
    db: Session = Depends(get_db)
):
    """
    Get aggregated statistics including:
    - Total events
    - Count by severity
    - Count by tactic
    
    Example request:
    {
        "search": "malware",
        "tactic": "all",
        "severity": "all",
        "dayRange": 7
    }
    """
    try:
        start_date, end_date = parse_date_range(None, request.dayRange)
        
        # Build base query
        query = db.query(Rtarf).filter(
            and_(
                Rtarf.timestamp >= start_date,
                Rtarf.timestamp <= end_date
            )
        )
        
        # Apply search filter
        if request.search:
            search_pattern = f"%{request.search}%"
            query = query.filter(
                or_(
                    Rtarf.description.ilike(search_pattern),
                    func.cast(Rtarf.alert_categories, str).ilike(search_pattern),
                    func.cast(Rtarf.mitre_tactics_ids_and_names, str).ilike(search_pattern),
                    func.cast(Rtarf.mitre_techniques_ids_and_names, str).ilike(search_pattern)
                )
            )
        
        # Apply tactic filter
        if request.tactic and request.tactic != "all":
            tactic_conditions = [
                func.cast(Rtarf.mitre_tactics_ids_and_names, str).like(f'%{request.tactic}%'),
                func.cast(Rtarf.crowdstrike_tactics_ids, str).like(f'%{request.tactic}%')
            ]
            query = query.filter(or_(*tactic_conditions))
        
        # Apply severity filter
        if request.severity and request.severity != "all":
            query = query.filter(Rtarf.severity == request.severity)
        
        # Get total count
        total = query.count()
        
        # Count by severity
        try:
            severity_expr = func.lower(
                func.coalesce(Rtarf.severity, Rtarf.crowdstrike_severity)
            ).label("severity")
            
            severity_counts = (
                db.query(
                    severity_expr,
                    func.count(Rtarf.id).label("count")
                )
                .filter(
                    and_(
                        Rtarf.timestamp >= start_date,
                        Rtarf.timestamp <= end_date
                    )
                )
                .group_by(severity_expr)
                .all()
            )
            
            severity_dict = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
            
            for severity, count in severity_counts:
                if severity in severity_dict:
                    severity_dict[severity] += count
                else:
                    logger.warning(f"Unexpected severity value: {severity}")
        except Exception as e:
            logger.exception("Error while counting severity")
            severity_dict = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        
        # Count unique tactics (approximate)
        # This is tricky with JSONB arrays, so we'll do a simple count
        tactics_query = db.query(Rtarf).filter(
            and_(
                Rtarf.timestamp >= start_date,
                Rtarf.timestamp <= end_date,
                or_(
                    Rtarf.mitre_tactics_ids_and_names.isnot(None),
                    Rtarf.crowdstrike_tactics_ids.isnot(None)
                )
            )
        )
        
        if request.tactic and request.tactic != "all":
            tactics_query = tactics_query.filter(
                or_(
                    func.cast(Rtarf.mitre_tactics_ids_and_names, str).like(f'%{request.tactic}%'),
                    func.cast(Rtarf.crowdstrike_tactics_ids, str).like(f'%{request.tactic}%')
                )
            )
        
        # Get unique tactics count (simplified)
        unique_tactics = len(set(
            extract_tactic_id(str(item)) 
            for record in tactics_query.limit(1000).all()
            for item in (record.mitre_tactics_ids_and_names or []) + (record.crowdstrike_tactics_ids or [])
            if item
        ))
        
        return {
            "total": total,
            "critical": severity_dict["critical"],
            "high": severity_dict["high"],
            "medium": severity_dict["medium"],
            "low": severity_dict["low"],
            "tactics": unique_tactics
        }
    
    except Exception as e:
        logger.error(f"Error in stats: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching statistics: {str(e)}")
    

# ===================================
# Endpoint: Aggregated Technique Statistics
# ===================================

class TechniqueAggregateStatsRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    dayRange: Optional[int] = 7
    includeSubTechniques: Optional[bool] = True
    includeCrowdStrikeSpecific: Optional[bool] = False


# ===================================
# Endpoint: Aggregated Technique Statistics
# ===================================

class TechniqueAggregateStatsRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    dayRange: Optional[int] = 7
    includeSubTechniques: Optional[bool] = True
    includeCrowdStrikeSpecific: Optional[bool] = False


# ===================================
# Endpoint: Aggregated Technique Statistics
# ===================================

class TechniqueAggregateStatsRequest(BaseModel):
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    dayRange: Optional[int] = 7
    includeSubTechniques: Optional[bool] = True
    includeCrowdStrikeSpecific: Optional[bool] = False


# ===================================
# Endpoint: Aggregated Technique Statistics
# ===================================

class TechniqueAggregateStatsRequest(BaseModel):
    dayRange: Optional[int] = 7
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"
    includeSubTechniques: Optional[bool] = True
    includeCrowdStrikeSpecific: Optional[bool] = False


@app.post("/api/postgres/technique-aggregate-stats", summary="Get aggregated statistics for all techniques")
async def get_technique_aggregate_stats(
    request: TechniqueAggregateStatsRequest,
    db: Session = Depends(get_db)
):
    """
    Get aggregated statistics for ALL techniques/sub-techniques in the database.
    Similar to /stats endpoint but counts every unique technique with calculated severity.
    
    Returns:
    {
        "total": <total_events>,
        "techniques": {
            "T1059": {
                "count": 150,
                "severity": "high",
                "lastSeen": "2025-01-15T10:30:00",
                "sources": ["palo-xsiam", "crowdstrike"],
                "subTechniques": {
                    "T1059.001": {
                        "count": 80,
                        "severity": "medium",
                        "lastSeen": "2025-01-15T09:20:00"
                    }
                }
            }
        },
        "severityCounts": {
            "critical": 10,
            "high": 45,
            "medium": 80,
            "low": 20
        },
        "crowdStrikeSpecific": {
            "CST0007": {
                "count": 25,
                "name": "Sensor-based ML",
                "lastSeen": "2025-01-14T15:00:00"
            }
        }
    }
    """
    try:
        start_date, end_date = parse_date_range(None, request.dayRange)
        
        # Build base query
        query = db.query(Rtarf).filter(
            and_(
                Rtarf.timestamp >= start_date,
                Rtarf.timestamp <= end_date
            )
        )
        
        # Apply search filter
        if request.search:
            search_pattern = f"%{request.search}%"
            query = query.filter(
                or_(
                    Rtarf.description.ilike(search_pattern),
                    func.cast(Rtarf.alert_categories, str).ilike(search_pattern),
                    func.cast(Rtarf.mitre_tactics_ids_and_names, str).ilike(search_pattern),
                    func.cast(Rtarf.mitre_techniques_ids_and_names, str).ilike(search_pattern),
                    func.cast(Rtarf.crowdstrike_techniques, str).ilike(search_pattern),
                    func.cast(Rtarf.crowdstrike_techniques_ids, str).ilike(search_pattern)
                )
            )
        
        # Apply tactic filter
        if request.tactic and request.tactic != "all":
            normalized_tactic = normalize_tactic_id(request.tactic)
            
            # Build conditions to check if tactic exists in arrays
            tactic_conditions = []
            
            # Search patterns - both original and normalized
            search_patterns = [request.tactic]
            if normalized_tactic and normalized_tactic != request.tactic:
                search_patterns.append(normalized_tactic)
            
            for pattern in search_patterns:
                # Check in Palo-XSIAM tactics (mitre_tactics_ids_and_names)
                try:
                    tactic_conditions.append(
                        func.jsonb_array_length(
                            func.jsonb_path_query_array(
                                Rtarf.mitre_tactics_ids_and_names,
                                f'$[*] ? (@ like_regex "{pattern}" flag "i")'
                            )
                        ) > 0
                    )
                except:
                    # Fallback to string search
                    tactic_conditions.append(
                        func.cast(Rtarf.mitre_tactics_ids_and_names, str).ilike(f'%{pattern}%')
                    )
                
                # Check in CrowdStrike tactics (crowdstrike_tactics_ids)
                try:
                    tactic_conditions.append(
                        func.jsonb_array_length(
                            func.jsonb_path_query_array(
                                Rtarf.crowdstrike_tactics_ids,
                                f'$[*] ? (@ like_regex "{pattern}" flag "i")'
                            )
                        ) > 0
                    )
                except:
                    # Fallback to string search
                    tactic_conditions.append(
                        func.cast(Rtarf.crowdstrike_tactics_ids, str).ilike(f'%{pattern}%')
                    )
            
            if tactic_conditions:
                query = query.filter(or_(*tactic_conditions))
        
        # Get all records
        records = query.all()
        total_events = len(records)
        
        # Aggregation dictionaries
        technique_stats = {}  # {technique_id: {count, last_seen, severities[], sources[]}}
        crowdstrike_specific = {}  # {CST_ID: {count, name, last_seen}}
        
        # Process each record
        for record in records:
            # Extract all technique IDs from this record (already normalized via get_all_technique_ids_from_record)
            # This function uses CROWDSTRIKE_TECHNIQUE_ID_MAPPING to convert CST#### to T####
            technique_ids = get_all_technique_ids_from_record(record)
            
            # Determine source type
            source_type = None
            if record.crowdstrike_techniques or record.crowdstrike_techniques_ids:
                source_type = "crowdstrike"
            elif record.mitre_techniques_ids_and_names:
                source_type = "palo-xsiam"
            
            # Get severity from record
            record_severity = record.crowdstrike_severity or record.severity
            
            # Aggregate MITRE techniques (technique_ids already mapped from CST to T)
            for tech_id in technique_ids:
                if tech_id not in technique_stats:
                    technique_stats[tech_id] = {
                        "count": 0,
                        "last_seen": None,
                        "severities": [],
                        "sources": set()
                    }
                
                technique_stats[tech_id]["count"] += 1
                
                # Update last seen
                if record.timestamp:
                    if not technique_stats[tech_id]["last_seen"] or record.timestamp > technique_stats[tech_id]["last_seen"]:
                        technique_stats[tech_id]["last_seen"] = record.timestamp
                
                # Track severities for calculation
                if record_severity:
                    technique_stats[tech_id]["severities"].append(record_severity)
                
                # Track sources
                if source_type:
                    technique_stats[tech_id]["sources"].add(source_type)
            
            # Track CrowdStrike-specific detections
            if request.includeCrowdStrikeSpecific:
                detection_methods = get_crowdstrike_detection_methods(record)
                for method in detection_methods:
                    if method not in crowdstrike_specific:
                        crowdstrike_specific[method] = {
                            "count": 0,
                            "name": method,
                            "last_seen": None
                        }
                    
                    crowdstrike_specific[method]["count"] += 1
                    
                    if record.timestamp:
                        if not crowdstrike_specific[method]["last_seen"] or record.timestamp > crowdstrike_specific[method]["last_seen"]:
                            crowdstrike_specific[method]["last_seen"] = record.timestamp
        
        # Calculate unified severity for each technique
        techniques_output = {}
        
        for tech_id, stats in technique_stats.items():
            # Determine most severe severity from all events
            most_severe = None
            if stats["severities"]:
                severity_priority = {"critical": 4, "5": 4, "high": 3, "4": 3, 
                                   "medium": 2, "3": 2, "low": 1, "2": 1, "1": 1}
                most_severe = max(stats["severities"], 
                                key=lambda s: severity_priority.get(str(s).lower(), 0))
            
            # Calculate unified severity
            unified_severity = calculate_severity(
                stats["count"],
                stats["last_seen"],
                most_severe
            )
            
            # Apply severity filter if specified
            if request.severity and request.severity != "all":
                if unified_severity != request.severity.lower():
                    continue
            
            # Separate parent techniques from sub-techniques
            is_sub_technique = "." in tech_id
            
            if is_sub_technique and not request.includeSubTechniques:
                continue
            
            technique_data = {
                "count": stats["count"],
                "severity": unified_severity,
                "lastSeen": stats["last_seen"].isoformat() if stats["last_seen"] else None,
                "sources": list(stats["sources"])
            }
            
            # Handle parent/sub-technique hierarchy
            if is_sub_technique:
                parent_id = tech_id.split(".")[0]
                
                # Ensure parent exists
                if parent_id not in techniques_output:
                    techniques_output[parent_id] = {
                        "count": 0,
                        "severity": "none",
                        "lastSeen": None,
                        "sources": set(),
                        "subTechniques": {}
                    }
                
                # Add as sub-technique
                techniques_output[parent_id]["subTechniques"][tech_id] = technique_data
                
                # DON'T increment parent count here - sub-technique counts are separate
                # Parent will have its own count if it has direct detections
                
                # Update parent last seen
                if stats["last_seen"]:
                    if not techniques_output[parent_id]["lastSeen"] or \
                       stats["last_seen"].isoformat() > techniques_output[parent_id]["lastSeen"]:
                        techniques_output[parent_id]["lastSeen"] = stats["last_seen"].isoformat()
                
                # Merge sources
                if isinstance(techniques_output[parent_id]["sources"], set):
                    techniques_output[parent_id]["sources"].update(stats["sources"])
                
                # Update parent severity (take most severe)
                parent_severity = techniques_output[parent_id]["severity"]
                severity_order = ["none", "low", "medium", "high", "critical"]
                if severity_order.index(unified_severity) > severity_order.index(parent_severity):
                    techniques_output[parent_id]["severity"] = unified_severity
            else:
                # Parent technique
                if tech_id not in techniques_output:
                    techniques_output[tech_id] = technique_data
                    techniques_output[tech_id]["subTechniques"] = {}
                else:
                    # Parent already exists (from sub-techniques), update with direct detection data
                    techniques_output[tech_id]["count"] = technique_data["count"]
                    techniques_output[tech_id]["sources"] = technique_data["sources"]
                    
                    if technique_data["lastSeen"]:
                        if not techniques_output[tech_id]["lastSeen"] or \
                           technique_data["lastSeen"] > techniques_output[tech_id]["lastSeen"]:
                            techniques_output[tech_id]["lastSeen"] = technique_data["lastSeen"]
                    
                    # Update severity with direct detection severity
                    severity_order = ["none", "low", "medium", "high", "critical"]
                    if severity_order.index(unified_severity) > severity_order.index(techniques_output[tech_id]["severity"]):
                        techniques_output[tech_id]["severity"] = unified_severity
        
        # Calculate severity counts AFTER building the hierarchy
        # Count only parent techniques (not sub-techniques)
        # Also convert sources set to list for JSON serialization
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0
        }
        
        for tech_id, tech_data in techniques_output.items():
            # Convert sources set to list
            if isinstance(tech_data["sources"], set):
                tech_data["sources"] = list(tech_data["sources"])
            
            # Only count parent-level techniques (ones without dots are parents)
            if "." not in tech_id:
                severity_counts[tech_data["severity"]] += 1
        
        # Format CrowdStrike-specific output
        crowdstrike_output = {}
        if request.includeCrowdStrikeSpecific:
            for method, stats in crowdstrike_specific.items():
                crowdstrike_output[method] = {
                    "count": stats["count"],
                    "name": stats["name"],
                    "lastSeen": stats["last_seen"].isoformat() if stats["last_seen"] else None
                }
        
        return {
            "total": total_events,
            "techniques": techniques_output,
            "severityCounts": severity_counts,
            "crowdStrikeSpecific": crowdstrike_output if request.includeCrowdStrikeSpecific else None,
            "dateRange": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            }
        }
    
    except Exception as e:
        logger.error(f"Error in technique-aggregate-stats: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching technique aggregate stats: {str(e)}")
    

# ===================================
# Endpoint: Aggregated Technique Statistics sum
# ===================================

@app.post("/api/postgres/technique-aggregate-stats-sum", summary="Get aggregated statistics for all techniques")
async def get_technique_aggregate_stats(
    request: TechniqueAggregateStatsRequest,
    db: Session = Depends(get_db)
):
    """
    Get aggregated statistics for ALL techniques/sub-techniques in the database.
    Similar to /stats endpoint but counts every unique technique with calculated severity.
    
    Returns:
    {
        "total": <total_events>,
        "techniques": {
            "T1059": {
                "count": 150,
                "severity": "high",
                "lastSeen": "2025-01-15T10:30:00",
                "sources": ["palo-xsiam", "crowdstrike"],
                "subTechniques": {
                    "T1059.001": {
                        "count": 80,
                        "severity": "medium",
                        "lastSeen": "2025-01-15T09:20:00"
                    }
                }
            }
        },
        "severityCounts": {
            "critical": 10,
            "high": 45,
            "medium": 80,
            "low": 20
        },
        "crowdStrikeSpecific": {
            "CST0007": {
                "count": 25,
                "name": "Sensor-based ML",
                "lastSeen": "2025-01-14T15:00:00"
            }
        }
    }
    """
    try:
        start_date, end_date = parse_date_range(None, request.dayRange)
        
        # Build base query
        query = db.query(Rtarf).filter(
            and_(
                Rtarf.timestamp >= start_date,
                Rtarf.timestamp <= end_date
            )
        )
        
        # Apply search filter
        if request.search:
            search_pattern = f"%{request.search}%"
            query = query.filter(
                or_(
                    Rtarf.description.ilike(search_pattern),
                    func.cast(Rtarf.alert_categories, str).ilike(search_pattern),
                    func.cast(Rtarf.mitre_tactics_ids_and_names, str).ilike(search_pattern),
                    func.cast(Rtarf.mitre_techniques_ids_and_names, str).ilike(search_pattern),
                    func.cast(Rtarf.crowdstrike_techniques, str).ilike(search_pattern),
                    func.cast(Rtarf.crowdstrike_techniques_ids, str).ilike(search_pattern)
                )
            )
        
        # Apply tactic filter
        if request.tactic and request.tactic != "all":
            normalized_tactic = normalize_tactic_id(request.tactic)
            
            # Build conditions to check if tactic exists in arrays
            tactic_conditions = []
            
            # Search patterns - both original and normalized
            search_patterns = [request.tactic]
            if normalized_tactic and normalized_tactic != request.tactic:
                search_patterns.append(normalized_tactic)
            
            for pattern in search_patterns:
                # Check in Palo-XSIAM tactics (mitre_tactics_ids_and_names)
                try:
                    tactic_conditions.append(
                        func.jsonb_array_length(
                            func.jsonb_path_query_array(
                                Rtarf.mitre_tactics_ids_and_names,
                                f'$[*] ? (@ like_regex "{pattern}" flag "i")'
                            )
                        ) > 0
                    )
                except:
                    # Fallback to string search
                    tactic_conditions.append(
                        func.cast(Rtarf.mitre_tactics_ids_and_names, str).ilike(f'%{pattern}%')
                    )
                
                # Check in CrowdStrike tactics (crowdstrike_tactics_ids)
                try:
                    tactic_conditions.append(
                        func.jsonb_array_length(
                            func.jsonb_path_query_array(
                                Rtarf.crowdstrike_tactics_ids,
                                f'$[*] ? (@ like_regex "{pattern}" flag "i")'
                            )
                        ) > 0
                    )
                except:
                    # Fallback to string search
                    tactic_conditions.append(
                        func.cast(Rtarf.crowdstrike_tactics_ids, str).ilike(f'%{pattern}%')
                    )
            
            if tactic_conditions:
                query = query.filter(or_(*tactic_conditions))
        
        # Get all records
        records = query.all()
        total_events = len(records)
        
        # Aggregation dictionaries
        technique_stats = {}  # {technique_id: {count, last_seen, severities[], sources[]}}
        crowdstrike_specific = {}  # {CST_ID: {count, name, last_seen}}
        
        # Process each record
        for record in records:
            # Extract all technique IDs from this record (already normalized via get_all_technique_ids_from_record)
            # This function uses CROWDSTRIKE_TECHNIQUE_ID_MAPPING to convert CST#### to T####
            technique_ids = get_all_technique_ids_from_record(record)
            
            # Determine source type
            source_type = None
            if record.crowdstrike_techniques or record.crowdstrike_techniques_ids:
                source_type = "crowdstrike"
            elif record.mitre_techniques_ids_and_names:
                source_type = "palo-xsiam"
            
            # Get severity from record
            record_severity = record.crowdstrike_severity or record.severity
            
            # Aggregate MITRE techniques (technique_ids already mapped from CST to T)
            for tech_id in technique_ids:
                if tech_id not in technique_stats:
                    technique_stats[tech_id] = {
                        "count": 0,
                        "last_seen": None,
                        "severities": [],
                        "sources": set()
                    }
                
                technique_stats[tech_id]["count"] += 1
                
                # Update last seen
                if record.timestamp:
                    if not technique_stats[tech_id]["last_seen"] or record.timestamp > technique_stats[tech_id]["last_seen"]:
                        technique_stats[tech_id]["last_seen"] = record.timestamp
                
                # Track severities for calculation
                if record_severity:
                    technique_stats[tech_id]["severities"].append(record_severity)
                
                # Track sources
                if source_type:
                    technique_stats[tech_id]["sources"].add(source_type)
            
            # Track CrowdStrike-specific detections
            if request.includeCrowdStrikeSpecific:
                detection_methods = get_crowdstrike_detection_methods(record)
                for method in detection_methods:
                    if method not in crowdstrike_specific:
                        crowdstrike_specific[method] = {
                            "count": 0,
                            "name": method,
                            "last_seen": None
                        }
                    
                    crowdstrike_specific[method]["count"] += 1
                    
                    if record.timestamp:
                        if not crowdstrike_specific[method]["last_seen"] or record.timestamp > crowdstrike_specific[method]["last_seen"]:
                            crowdstrike_specific[method]["last_seen"] = record.timestamp
        
        # Calculate unified severity for each technique
        techniques_output = {}
        
        for tech_id, stats in technique_stats.items():
            # Determine most severe severity from all events
            most_severe = None
            if stats["severities"]:
                severity_priority = {"critical": 4, "5": 4, "high": 3, "4": 3, 
                                   "medium": 2, "3": 2, "low": 1, "2": 1, "1": 1}
                most_severe = max(stats["severities"], 
                                key=lambda s: severity_priority.get(str(s).lower(), 0))
            
            # Calculate unified severity
            unified_severity = calculate_severity(
                stats["count"],
                stats["last_seen"],
                most_severe
            )
            
            # Apply severity filter if specified
            if request.severity and request.severity != "all":
                if unified_severity != request.severity.lower():
                    continue
            
            # Separate parent techniques from sub-techniques
            is_sub_technique = "." in tech_id
            
            if is_sub_technique and not request.includeSubTechniques:
                continue
            
            technique_data = {
                "count": stats["count"],
                "severity": unified_severity,
                "lastSeen": stats["last_seen"].isoformat() if stats["last_seen"] else None,
                "sources": list(stats["sources"])
            }
            
            # Handle parent/sub-technique hierarchy
            if is_sub_technique:
                parent_id = tech_id.split(".")[0]
                
                # Ensure parent exists
                if parent_id not in techniques_output:
                    techniques_output[parent_id] = {
                        "count": 0,
                        "severity": "none",
                        "lastSeen": None,
                        "sources": set(),
                        "subTechniques": {}
                    }
                
                # Add as sub-technique
                techniques_output[parent_id]["subTechniques"][tech_id] = technique_data
                
                # DON'T increment parent count here - sub-technique counts are separate
                # Parent will have its own count if it has direct detections
                
                # Update parent last seen
                if stats["last_seen"]:
                    if not techniques_output[parent_id]["lastSeen"] or \
                       stats["last_seen"].isoformat() > techniques_output[parent_id]["lastSeen"]:
                        techniques_output[parent_id]["lastSeen"] = stats["last_seen"].isoformat()
                
                # Merge sources
                if isinstance(techniques_output[parent_id]["sources"], set):
                    techniques_output[parent_id]["sources"].update(stats["sources"])
                
                # Update parent severity (take most severe)
                parent_severity = techniques_output[parent_id]["severity"]
                severity_order = ["none", "low", "medium", "high", "critical"]
                if severity_order.index(unified_severity) > severity_order.index(parent_severity):
                    techniques_output[parent_id]["severity"] = unified_severity
            else:
                # Parent technique
                if tech_id not in techniques_output:
                    techniques_output[tech_id] = technique_data
                    techniques_output[tech_id]["subTechniques"] = {}
                else:
                    # Parent already exists (from sub-techniques), update with direct detection data
                    techniques_output[tech_id]["count"] = technique_data["count"]
                    techniques_output[tech_id]["sources"] = technique_data["sources"]
                    
                    if technique_data["lastSeen"]:
                        if not techniques_output[tech_id]["lastSeen"] or \
                           technique_data["lastSeen"] > techniques_output[tech_id]["lastSeen"]:
                            techniques_output[tech_id]["lastSeen"] = technique_data["lastSeen"]
                    
                    # Update severity with direct detection severity
                    severity_order = ["none", "low", "medium", "high", "critical"]
                    if severity_order.index(unified_severity) > severity_order.index(techniques_output[tech_id]["severity"]):
                        techniques_output[tech_id]["severity"] = unified_severity
        
        # Calculate severity counts AFTER building the hierarchy
        # Sum up event counts by severity from parent techniques only (not sub-techniques)
        # Also convert sources set to list for JSON serialization
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0
        }
        
        for tech_id, tech_data in techniques_output.items():
            # Convert sources set to list
            if isinstance(tech_data["sources"], set):
                tech_data["sources"] = list(tech_data["sources"])
            
            # Only count parent-level techniques (ones without dots are parents)
            if "." not in tech_id:
                # Add the event count for this technique to its severity bucket
                severity_counts[tech_data["severity"]] += tech_data["count"]
        
        # Format CrowdStrike-specific output
        crowdstrike_output = {}
        if request.includeCrowdStrikeSpecific:
            for method, stats in crowdstrike_specific.items():
                crowdstrike_output[method] = {
                    "count": stats["count"],
                    "name": stats["name"],
                    "lastSeen": stats["last_seen"].isoformat() if stats["last_seen"] else None
                }
        
        return {
            "total": total_events,
            "techniques": techniques_output,
            "severityCounts": severity_counts,
            "crowdStrikeSpecific": crowdstrike_output if request.includeCrowdStrikeSpecific else None,
            "dateRange": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            }
        }
    
    except Exception as e:
        logger.error(f"Error in technique-aggregate-stats: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching technique aggregate stats: {str(e)}")
    
# ===================================
# Endpoint 3: Search/List Events (Matrix View tab)
# ===================================

@app.post("/api/postgres/search", summary="Search detections with filters")
async def search_detections(
    request: SearchRequest,
    db: Session = Depends(get_db)
):
    """
    Search detections with filters for tactic, severity, and text search.
    Supports both MITRE ATT&CK and CrowdStrike IDs with automatic normalization.
    """
    try:
        # Build base query
        query = db.query(Rtarf)
        
        # Apply tactic filter with normalization
        if request.tactic and request.tactic != "all":
            normalized_tactic = normalize_tactic_id(request.tactic)
            
            # Build reverse mapping to search for CrowdStrike IDs when MITRE ID is provided
            reverse_mapping = {v: k for k, v in CROWDSTRIKE_TACTIC_MAPPING.items()}
            cs_tactic = reverse_mapping.get(normalized_tactic) if normalized_tactic else None
            
            tactic_conditions = []
            search_tactics = [request.tactic]
            
            # Add normalized tactic if different
            if normalized_tactic and normalized_tactic != request.tactic:
                search_tactics.append(normalized_tactic)
            
            # Add CrowdStrike equivalent if exists
            if cs_tactic and cs_tactic not in search_tactics:
                search_tactics.append(cs_tactic)
            
            # Search in both Palo-XSIAM and CrowdStrike fields
            for tactic_id in search_tactics:
                try:
                    # Palo-XSIAM tactics
                    if Rtarf.mitre_tactics_ids_and_names is not None:
                        tactic_conditions.append(
                            func.jsonb_array_length(
                                func.jsonb_path_query_array(
                                    Rtarf.mitre_tactics_ids_and_names,
                                    f'$[*] ? (@ like_regex "{tactic_id}" flag "i")'
                                )
                            ) > 0
                        )
                    
                    # CrowdStrike tactics
                    if Rtarf.crowdstrike_tactics_ids is not None:
                        tactic_conditions.append(
                            func.jsonb_array_length(
                                func.jsonb_path_query_array(
                                    Rtarf.crowdstrike_tactics_ids,
                                    f'$[*] ? (@ like_regex "{tactic_id}" flag "i")'
                                )
                            ) > 0
                        )
                except Exception as e:
                    logger.warning(f"JSONB path query failed for tactic {tactic_id}, using fallback: {e}")
            
            # Fallback: text search
            if not tactic_conditions:
                for tactic_id in search_tactics:
                    tactic_conditions.extend([
                        func.cast(Rtarf.mitre_tactics_ids_and_names, str).ilike(f'%{tactic_id}%'),
                        func.cast(Rtarf.crowdstrike_tactics_ids, str).ilike(f'%{tactic_id}%')
                    ])
            
            if tactic_conditions:
                query = query.filter(or_(*tactic_conditions))
        
        # Apply severity filter
        if request.severity and request.severity != "all":
            severity_conditions = []
            
            # Map severity to CrowdStrike format
            severity_mapping = {
                "critical": ["critical", "5", "high", "4"],
                "high": ["high", "4"],
                "medium": ["medium", "3"],
                "low": ["low", "2", "informational", "1"]
            }
            
            search_severities = severity_mapping.get(request.severity.lower(), [request.severity])
            
            # Check both Palo-XSIAM and CrowdStrike severity fields
            for sev in search_severities:
                if Rtarf.severity is not None:
                    severity_conditions.append(
                        func.lower(Rtarf.severity).like(f'%{sev.lower()}%')
                    )
                if Rtarf.crowdstrike_severity is not None:
                    severity_conditions.append(
                        func.lower(Rtarf.crowdstrike_severity).like(f'%{sev.lower()}%')
                    )
            
            if severity_conditions:
                query = query.filter(or_(*severity_conditions))
        
        # Apply text search
        if request.search:
            search_term = f"%{request.search}%"
            search_conditions = [
                Rtarf.description.ilike(search_term),
                Rtarf.crowdstrike_event_name.ilike(search_term),
                Rtarf.crowdstrike_event_objective.ilike(search_term),
                func.cast(Rtarf.mitre_techniques_ids_and_names, str).ilike(search_term),
                func.cast(Rtarf.crowdstrike_techniques, str).ilike(search_term),
                func.cast(Rtarf.alert_categories, str).ilike(search_term)
            ]
            query = query.filter(or_(*search_conditions))
        
        # Get total count before pagination
        total_count = query.count()
        
        # Apply pagination
        offset = (request.page - 1) * request.size
        results = query.order_by(Rtarf.timestamp.desc()).offset(offset).limit(request.size).all()
        
        # Process results with normalization
        processed_results = []
        for record in results:
            # Get normalized tactics and techniques
            tactics = get_all_tactic_ids_from_record(record)
            techniques = get_all_technique_ids_from_record(record)
            
            # Determine primary source
            source_type = "unknown"
            if record.crowdstrike_techniques_ids or record.crowdstrike_tactics_ids:
                source_type = "crowdstrike"
            elif record.mitre_techniques_ids_and_names or record.mitre_tactics_ids_and_names:
                source_type = "palo-xsiam"
            elif record.suricata_classification:
                source_type = "suricata"
            
            processed_results.append({
                "id": record.id,
                "eventId": record.event_id,
                "description": record.description or record.crowdstrike_event_name or "No description",
                "severity": record.crowdstrike_severity or record.severity or "unknown",
                "timestamp": record.timestamp.isoformat() if record.timestamp else None,
                "tactics": tactics,  # Already normalized to MITRE
                "techniques": techniques,  # Includes both MITRE and CrowdStrike
                "sourceType": source_type,
                "alertCategories": record.alert_categories,
                "crowdStrikeObjective": record.crowdstrike_event_objective,
                "suricataClassification": record.suricata_classification
            })
        
        return {
            "total": total_count,
            "page": request.page,
            "size": request.size,
            "totalPages": (total_count + request.size - 1) // request.size,
            "results": processed_results
        }
    
    except Exception as e:
        logger.error(f"Error in search: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error searching detections: {str(e)}")


# ===================================
# Endpoint 4: Top Techniques (Analytic Tab)
# ===================================

from fastapi import HTTPException
from sqlalchemy import and_, or_, func

@app.post("/api/postgres/top-techniques", summary="Get top N most detected techniques")
async def get_top_techniques(
    request: TopTechniquesRequest,
    db: Session = Depends(get_db)
):
    try:
        start_date, end_date = parse_date_range(None, request.dayRange)

        # Step 1: base query
        query = db.query(Rtarf).filter(
            and_(
                Rtarf.timestamp >= start_date,
                Rtarf.timestamp <= end_date
            )
        )

        # Step 2: filter by tactic if provided
        if request.tactic and request.tactic != "all":
            query = query.filter(
                or_(
                    func.cast(Rtarf.mitre_tactics_ids_and_names, str).like(f'%{request.tactic}%'),
                    func.cast(Rtarf.crowdstrike_tactics_ids, str).like(f'%{request.tactic}%')
                )
            )

        records = query.all()
                # Step 3: count only unique technique IDs per event (use normalization helper)
        technique_counts = {}
        total_events = len(records)

        for record in records:
            # Use existing normalization helper so CST IDs and names that map to MITRE are included
            normalized_techniques = get_all_technique_ids_from_record(record)

            # Keep only real MITRE IDs and dedupe per record
            unique_techs = {t for t in normalized_techniques if t and isinstance(t, str) and t.startswith("T")}

            # count each technique only once per record
            for tech in unique_techs:
                technique_counts[tech] = technique_counts.get(tech, 0) + 1

        # Step 4: sort correctly by count (descending), tie-breaker by technique id
        sorted_techniques = sorted(
            technique_counts.items(),
            key=lambda x: (-x[1], x[0])  # primary: count desc, secondary: tech id asc
        )[:request.limit]

        # Step 5: format output (percentage relative to total_events)
        results = []
        for tech_id, count in sorted_techniques:
            percentage = round((count / total_events * 100), 2) if total_events else 0.0
            results.append({
                "technique_id": tech_id,
                "count": count,
                "percentage": percentage
            })

        return {
            "techniques": results,
            "total_events": total_events,
            "time_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            }
        }


    except Exception as e:
        logger.error(f"Error in top-techniques: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching top techniques: {str(e)}")


# ===================================
# Summary Stat (Analytic Tab)
# ===================================

def extract_tactic_id(tactic_str: str) -> str:
    # แปลง string เป็น tactic ID เช่น TA0001
    return tactic_str.split(":")[0] if tactic_str else "unknown"

@app.post("/api/postgres/summary_stats", summary="Get detailed summary stats")
async def get_summary_stats(
    request: StatsRequest,
    db: Session = Depends(get_db)
):
    try:
        start_date, end_date = parse_date_range(None, request.dayRange)

        # Base query
        base_query = db.query(Rtarf).filter(Rtarf.timestamp.between(start_date, end_date))

        # Apply filters
        if request.search:
            pattern = f"%{request.search}%"
            base_query = base_query.filter(
                or_(
                    Rtarf.description.ilike(pattern),
                    func.cast(Rtarf.alert_categories, String).ilike(pattern),
                    func.cast(Rtarf.mitre_tactics_ids_and_names, String).ilike(pattern),
                    func.cast(Rtarf.mitre_techniques_ids_and_names, String).ilike(pattern)
                )
            )

        if request.tactic and request.tactic != "all":
            base_query = base_query.filter(
                or_(
                    func.cast(Rtarf.mitre_tactics_ids_and_names, String).like(f"%{request.tactic}%"),
                    func.cast(Rtarf.crowdstrike_tactics_ids, String).like(f"%{request.tactic}%")
                )
            )

        if request.severity and request.severity != "all":
            base_query = base_query.filter(Rtarf.severity == request.severity)

        # Total events
        total = base_query.count()

        # Severity Grouping
        severity_expr = func.lower(func.coalesce(Rtarf.severity, Rtarf.crowdstrike_severity)).label("severity")
        severity_counts = (
            db.query(severity_expr, func.count(Rtarf.id))
            .filter(Rtarf.timestamp.between(start_date, end_date))
            .group_by(severity_expr)
            .all()
        )

        severity_dict = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev, count in severity_counts:
            if sev in severity_dict:
                severity_dict[sev] = count

        # Process Tactics
        tactics_map = {}
        for record in base_query.all():
            sources = getattr(record, "sources", {}) or {}
            all_tactics = []

            if record.mitre_tactics_ids_and_names:
                all_tactics += record.mitre_tactics_ids_and_names
            if record.crowdstrike_tactics_ids:
                all_tactics += record.crowdstrike_tactics_ids

            for raw in all_tactics:
                tid = extract_tactic_id(raw)

                # Extract readable name if possible: "TA0004 - Privilege Escalation" → "Privilege Escalation"
                if " - " in raw:
                    tname = raw.split(" - ", 1)[1]
                else:
                    tname = tid  # if only "TA0004" or "CSTA0004"

                if tid not in tactics_map:
                    tactics_map[tid] = {
                        "id": tid,
                        "name": tname,
                        "count": 0,
                        "sources": {}
                    }

                tactics_map[tid]["count"] += 1

                # Aggregate source counts
                for src_key, src_value in sources.items():
                    tactics_map[tid]["sources"][src_key] = tactics_map[tid]["sources"].get(src_key, 0) + src_value

        tactics_array = sorted(tactics_map.values(), key=lambda x: x["count"], reverse=True)

        # Overall Sources summary
        sources_dict = {}
        for record in base_query.all():
            record_sources = getattr(record, "sources", {}) or {}
            for k, v in record_sources.items():
                sources_dict[k] = sources_dict.get(k, 0) + v

        return {
            "total": total,
            "critical": severity_dict["critical"],
            "high": severity_dict["high"],
            "medium": severity_dict["medium"],
            "low": severity_dict["low"],
            "tactics": tactics_array,
            "sources": sources_dict
        }

    except Exception as e:
        logger.exception("Failed to fetch summary stats")
        raise HTTPException(status_code=500, detail=str(e))

    

# ===================================
# Helper function for debugging
# ===================================

def analyze_crowdstrike_techniques(db: Session, limit: int = 100) -> Dict:
    """
    Analyze CrowdStrike techniques in the database to find unmapped CST IDs
    Useful for discovering new CST IDs that need mapping
    
    Args:
        db: Database session
        limit: Number of records to analyze
    
    Returns:
        Dictionary with analysis results
    """
    records = db.query(Rtarf).filter(
        Rtarf.crowdstrike_techniques_ids.isnot(None)
    ).limit(limit).all()
    
    cst_ids = set()
    technique_names = set()
    mappings = {}
    
    for record in records:
        if record.crowdstrike_techniques_ids:
            ids = record.crowdstrike_techniques_ids if isinstance(record.crowdstrike_techniques_ids, list) else []
            for tid in ids:
                tid_str = str(tid)
                if tid_str.startswith("CST"):
                    cst_ids.add(tid_str)
        
        if hasattr(record, 'crowdstrike_techniques') and record.crowdstrike_techniques:
            names = record.crowdstrike_techniques if isinstance(record.crowdstrike_techniques, list) else []
            for name in names:
                technique_names.add(str(name))
        
        # Try to match IDs with names
        if record.crowdstrike_techniques_ids and hasattr(record, 'crowdstrike_techniques') and record.crowdstrike_techniques:
            ids = record.crowdstrike_techniques_ids if isinstance(record.crowdstrike_techniques_ids, list) else []
            names = record.crowdstrike_techniques if isinstance(record.crowdstrike_techniques, list) else []
            if len(ids) == len(names):
                for i, tid in enumerate(ids):
                    if str(tid).startswith("CST"):
                        mappings[str(tid)] = str(names[i])
    
    # Find unmapped CST IDs
    unmapped_cst = [cst for cst in cst_ids if cst not in CROWDSTRIKE_TECHNIQUE_ID_MAPPING]
    unmapped_names = [name for name in technique_names if name not in CROWDSTRIKE_TECHNIQUE_NAME_MAPPING]
    
    return {
        "total_records_analyzed": len(records),
        "unique_cst_ids": list(cst_ids),
        "unique_technique_names": list(technique_names),
        "cst_to_name_mappings": mappings,
        "unmapped_cst_ids": unmapped_cst,
        "unmapped_technique_names": unmapped_names
    }
    
# ===================================
# Cyber Kill Chain Mapping
# ===================================

# 7 Phases of Cyber Kill Chain (Lockheed Martin)
KILL_CHAIN_PHASES = {
    "reconnaissance": {
        "name": "Reconnaissance",
        "name_th": "การสอดแนม",
        "description": "Research, identification and selection of targets"
    },
    "weaponization": {
        "name": "Weaponization", 
        "name_th": "การสร้างอาวุธ",
        "description": "Pairing remote access malware with exploit into a deliverable payload"
    },
    "delivery": {
        "name": "Delivery",
        "name_th": "การส่งมอบ",
        "description": "Transmission of weapon to the targeted environment"
    },
    "exploitation": {
        "name": "Exploitation",
        "name_th": "การโจมตี",
        "description": "After the weapon is delivered, exploitation triggers intruders' code"
    },
    "installation": {
        "name": "Installation",
        "name_th": "การติดตั้ง",
        "description": "Installation of a remote access trojan or backdoor"
    },
    "command_control": {
        "name": "Command & Control",
        "name_th": "การสั่งการและควบคุม",
        "description": "Command channel for remote manipulation of the victim"
    },
    "actions_objectives": {
        "name": "Actions on Objectives",
        "name_th": "การดำเนินการตามเป้าหมาย",
        "description": "Intruders accomplish their original goals"
    }
}

KEYWORD_TO_KILLCHAIN = {
    "reconnaissance": [
        "reconnaissance", "scan detected via zone protection profile", "vulnerability", 
        "attacker methodology", "suspicious activity", 
        "intel detection", "explore", "spyware detected via anti-spyware profile", "anomaly", "detectoin of a network scan",
        "possible social engineering attempted", "a client was using an unsual port",
        "access to potentially vulnerable"
    ],
    "weaponization": [
        "weaponization", "malware", "ransomware", 
        "known malware", "wildfire analysis", "exploit kit activity detected",
        "executable code was detected"
    ],
    "delivery": [
        "delivery", "flood detected", "ips", "initial access",
        "ondemandscan", "falcon detection method", "flood detected via zone protection profile",
        "ondemandscanmlfileanlysislow","ondemandscanmlfileanlysismedium", "ondemandscanmlfileanlysishigh",
        "clouddetect-onwritemacrokestrelxmlhigh", "potentially bad traffic", "possibly unwanted program detected",
        "web appilcation attack"
    ],
    "exploitation": [
        "exploitation", "execution", "infiltration", 
        "antivirus", "blocked exploit", "ngav", "gain access",
        "initial access", "impact", "a network trojan was detected", "attempted administrator privilege gain",
        "attempted user privilege gain", "executable code was detected"
    ],
    "installation": [
        "installation", "persistence", "defense evasion",
        "privilege escalation", "establish persistence", "keep access",
        "successful administrator privilege gain", "device retrieving extrnal ip address detected",
        "crypto currency mining activity detected"
    ],
    "command_control": [
        "command and control", "lateral movement",
        "overwatch detection", "contact controlled systems",
        "domain observed used for c2 detected", "malware command and control activity detected"
    ],
    "actions_objectives": [
        "actions on objectives", "credential access", 
        "credential theft", "collection", "exfiltration",
        "impact", "evade detection", "follow through",
        "discovery", "attempted information leak", "large scale information leak",
        "information leak", "potential corporate privacy violation",
        "attempted denial of service", "detection of a denial of service attack"
    ]
}

# MITRE ATT&CK Tactics to Cyber Kill Chain Phase Mapping
MITRE_TO_KILLCHAIN = {
    "TA0043": "reconnaissance",      # Reconnaissance
    "TA0042": "weaponization",       # Resource Development
    "TA0001": "delivery",            # Initial Access
    "TA0002": "exploitation",        # Execution
    "TA0003": "installation",        # Persistence
    "TA0004": "exploitation",        # Privilege Escalation
    "TA0005": "installation",        # Defense Evasion
    "TA0006": "exploitation",        # Credential Access
    "TA0007": "reconnaissance",      # Discovery (post-compromise recon)
    "TA0008": "command_control",     # Lateral Movement
    "TA0009": "actions_objectives",  # Collection
    "TA0011": "command_control",     # Command and Control
    "TA0010": "actions_objectives",  # Exfiltration
    "TA0040": "actions_objectives",  # Impact
}

# MITRE Tactic Names (for display)
TACTIC_MAP = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Sample MITRE Technique to Tactics mapping (subset - extend as needed)
TECHNIQUE_TO_TACTICS = {
    "T1071": ["TA0011"],  # Application Layer Protocol -> C2
    "T1036": ["TA0005"],  # Masquerading -> Defense Evasion
    "T1055": ["TA0004", "TA0005"],  # Process Injection -> Priv Esc, Defense Evasion
    "T1059": ["TA0002"],  # Command and Scripting Interpreter -> Execution
    "T1059.001": ["TA0002"],  # PowerShell -> Execution
    "T1105": ["TA0011"],  # Ingress Tool Transfer -> C2
    "T1129": ["TA0002"],  # Shared Modules -> Execution
    "T1202": ["TA0002"],  # Indirect Command Execution -> Execution
    "T1219": ["TA0011"],  # Remote Access Software -> C2
    "T1486": ["TA0040"],  # Data Encrypted for Impact -> Impact
    "T1490": ["TA0040"],  # Inhibit System Recovery -> Impact
    "T1547.001": ["TA0003", "TA0004"],  # Registry Run Keys -> Persistence, Priv Esc
    "T1562.001": ["TA0005"],  # Disable or Modify Tools -> Defense Evasion
}

ALL_AVAILABLE_TECHNIQUES_PER_PHASE = {
    "reconnaissance": 29,  # Mapped from Reconnaissance (TA0043) and Discovery (TA0007)
    "weaponization": 17,   # Mapped from Resource Development (TA0042)
    "delivery": 20,        # Mapped from Initial Access (TA0001)
    "exploitation": 230,   # Mapped from Execution (TA0002), Priv Escalation (TA0004), Credential Access (TA0006)
    "installation": 101,   # Mapped from Persistence (TA0003) and Defense Evasion (TA0005)
    "command_control": 53, # Mapped from C2 (TA0011) and Lateral Movement (TA0008)
    "actions_objectives": 83, # Mapped from Collection (TA0009), Exfiltration (TA0010), Impact (TA0040)
}

def match_keyword_to_phase(text: str) -> Optional[str]:
    """
    Match text content to Kill Chain phase based on keywords
    
    Args:
        text: Text to search for keywords (from alert_categories, event names, etc.)
    
    Returns:
        Phase ID if match found, None otherwise
    """
    if not text:
        return None
    
    text_lower = text.lower()
    
    # Search through each phase's keywords
    for phase_id, keywords in KEYWORD_TO_KILLCHAIN.items():
        for keyword in keywords:
            if keyword.lower() in text_lower:
                return phase_id
    
    return None


def get_phases_from_record(record: Rtarf) -> Set[str]:
    """
    Extract all Kill Chain phases that apply to a record
    Uses keyword matching only from:
    1. Palo-XSIAM alert_categories
    2. CrowdStrike event_name
    3. CrowdStrike event_objective
    
    Args:
        record: Rtarf database record
    
    Returns:
        Set of phase IDs that apply to this record
    """
    phases = set()
    
    # Method 1: Check Palo-XSIAM alert categories
    if record.alert_categories:
        try:
            categories = record.alert_categories if isinstance(record.alert_categories, list) else []
            for category in categories:
                phase_id = match_keyword_to_phase(str(category))
                if phase_id:
                    phases.add(phase_id)
        except Exception as e:
            logger.warning(f"Error parsing alert_categories: {e}")
    
    # Method 2: Check CrowdStrike event name
    if record.crowdstrike_event_name:
        phase_id = match_keyword_to_phase(record.crowdstrike_event_name)
        if phase_id:
            phases.add(phase_id)
    
    # Method 3: Check CrowdStrike event objective
    if record.crowdstrike_event_objective:
        phase_id = match_keyword_to_phase(record.crowdstrike_event_objective)
        if phase_id:
            phases.add(phase_id)
    
    return phases

def get_technique_tactics(technique_id: str) -> List[str]:
    """Get MITRE tactics for a technique"""
    return TECHNIQUE_TO_TACTICS.get(technique_id, [])

def get_technique_name_from_id(technique_id: str) -> str:
    """Get technique name from ID (lookup from mapping or return ID)"""
    technique_names = {
        "T1071": "Application Layer Protocol",
        "T1036": "Masquerading",
        "T1055": "Process Injection",
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1105": "Ingress Tool Transfer",
        "T1129": "Shared Modules",
        "T1202": "Indirect Command Execution",
        "T1219": "Remote Access Software",
        "T1486": "Data Encrypted for Impact",
        "T1490": "Inhibit System Recovery",
        "T1547.001": "Registry Run Keys / Startup Folder",
        "T1562.001": "Disable or Modify Tools",
    }
    return technique_names.get(technique_id, technique_id)

# ===================================
# Request/Response Models
# ===================================

class KillChainRequest(BaseModel):
    dayRange: int = 7
    search: Optional[str] = None
    tactic: Optional[str] = "all"
    severity: Optional[str] = "all"


class TechniqueInPhase(BaseModel):
    technique_id: str
    technique_name: str
    count: int
    sources: Dict[str, int]
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None

class DetectionSource(BaseModel):
    """Information about a detection source (alert category or event name)"""
    source_text: str
    count: int
    source_type: str  # 'alert_category', 'event_name', or 'event_objective'

class PhaseCoverage(BaseModel):
    phase_id: str
    phase_name: str
    phase_name_th: str
    total_detections: int
    sources: Dict[str, int]  # Source type distribution (crowdstrike, palo-xsiam, suricata)
    detection_methods: List[str]  # Keywords/categories that triggered this phase
    top_detection_sources: List[DetectionSource]  # Top specific sources


class CyberKillChainResponse(BaseModel):
    phases: List[PhaseCoverage]
    total_detections: int
    time_range: Dict[str, str]
    active_phases: int
    methodology: str


# ===================================
# Endpoint: PostgreSQL Cyber Kill Chain
# ===================================

@app.post("/api/postgres/cyber-kill-chain", 
          summary="Get Cyber Kill Chain coverage from PostgreSQL (7 phases) - Keyword Mapping Only",
          response_model=CyberKillChainResponse)
async def get_postgres_cyber_kill_chain(
    request: KillChainRequest,
    db: Session = Depends(get_db)
):
    """
    Cyber Kill Chain endpoint using KEYWORD MAPPING ONLY.
    
    Maps detections to the Cyber Kill Chain methodology (7 phases) using keyword matching from:
    1. Palo-XSIAM alert_categories
    2. CrowdStrike crowdstrike_event_name
    3. CrowdStrike crowdstrike_event_objective
    
    MITRE techniques and tactics are NOT used for phase mapping.
    
    Example request:
    {
        "dayRange": 7,
        "search": null,
        "tactic": "all",
        "severity": "all"
    }
    
    Returns Cyber Kill Chain with 7 phases:
    1. Reconnaissance (การสอดแนม)
    2. Weaponization (การสร้างอาวุธ)
    3. Delivery (การส่งมอบ)
    4. Exploitation (การโจมตี)
    5. Installation (การติดตั้ง)
    6. Command & Control (การสั่งการและควบคุม)
    7. Actions on Objectives (การดำเนินการตามเป้าหมาย)
    """
    try:
        # Calculate time range
        start_date, end_date = parse_date_range(None, request.dayRange)
        
        # Build base query
        query = db.query(Rtarf).filter(
            and_(
                Rtarf.timestamp >= start_date,
                Rtarf.timestamp <= end_date
            )
        )
        
        # Apply search filter
        if request.search:
            search_pattern = f"%{request.search}%"
            query = query.filter(
                or_(
                    Rtarf.description.ilike(search_pattern),
                    Rtarf.crowdstrike_event_name.ilike(search_pattern),
                    Rtarf.crowdstrike_event_objective.ilike(search_pattern),
                    func.cast(Rtarf.alert_categories, str).ilike(search_pattern)
                )
            )
        
        # Apply severity filter
        if request.severity and request.severity != "all":
            severity_mapping = {
                "critical": ["critical", "5", "high", "4"],
                "high": ["high", "4"],
                "medium": ["medium", "3"],
                "low": ["low", "2", "informational", "1"]
            }
            search_severities = severity_mapping.get(request.severity.lower(), [request.severity])
            
            severity_conditions = []
            for sev in search_severities:
                severity_conditions.extend([
                    func.lower(Rtarf.severity).like(f'%{sev.lower()}%'),
                    func.lower(Rtarf.crowdstrike_severity).like(f'%{sev.lower()}%')
                ])
            
            if severity_conditions:
                query = query.filter(or_(*severity_conditions))
        
        # Fetch all matching records
        records = query.all()
        
        # Initialize kill chain structure
        kill_chain = {}
        for phase_id, phase_data in KILL_CHAIN_PHASES.items():
            kill_chain[phase_id] = {
                "phase_id": phase_id,
                "phase_name": phase_data["name"],
                "phase_name_th": phase_data["name_th"],
                "total_detections": 0,
                "sources": {},
                "detection_methods": set(),  # Track which keywords triggered
                "detection_sources": {}  # Track specific sources (alert_categories, event_name, etc.)
            }
        
        # Total detections is the number of unique records found
        total_detections = len(records)
        
        # Process each record
        for record in records:
            phases_for_record = get_phases_from_record(record)
            
            if not phases_for_record:
                continue
            
            # Determine source type
            source_type = "unknown"
            if record.crowdstrike_event_name or record.crowdstrike_event_objective:
                source_type = "crowdstrike"
            elif record.alert_categories:
                source_type = "palo-xsiam"
            elif record.suricata_classification:
                source_type = "suricata"
            
            # Collect detection methods from this record
            detection_sources_for_record = []
            
            if record.alert_categories:
                try:
                    cats = record.alert_categories if isinstance(record.alert_categories, list) else []
                    for cat in cats:
                        cat_str = str(cat)
                        detection_sources_for_record.append(("alert_category", cat_str))
                except:
                    pass
            
            if record.crowdstrike_event_name:
                detection_sources_for_record.append(("event_name", record.crowdstrike_event_name))
            
            if record.crowdstrike_event_objective:
                detection_sources_for_record.append(("event_objective", record.crowdstrike_event_objective))
            
            # Process each phase this record belongs to
            for phase_id in phases_for_record:
                kill_chain[phase_id]["total_detections"] += 1
                kill_chain[phase_id]["sources"][source_type] = \
                    kill_chain[phase_id]["sources"].get(source_type, 0) + 1
                
                # Track detection methods (for display)
                for source_type_name, source_text in detection_sources_for_record[:3]:
                    kill_chain[phase_id]["detection_methods"].add(source_text)
                    
                    # Track specific detection sources with counts
                    source_key = f"{source_type_name}:{source_text}"
                    if source_key not in kill_chain[phase_id]["detection_sources"]:
                        kill_chain[phase_id]["detection_sources"][source_key] = {
                            "source_text": source_text,
                            "count": 0,
                            "source_type": source_type_name
                        }
                    kill_chain[phase_id]["detection_sources"][source_key]["count"] += 1
        
        # Format results for each phase
        phases_coverage = []
        phase_order = [
            "reconnaissance", "weaponization", "delivery", "exploitation",
            "installation", "command_control", "actions_objectives"
        ]
        
        for phase_id in phase_order:
            phase_data = kill_chain[phase_id]
            
            # Get top detection sources
            sorted_sources = sorted(
                phase_data["detection_sources"].values(),
                key=lambda x: x["count"],
                reverse=True
            )[:10]
            
            phases_coverage.append({
                "phase_id": phase_id,
                "phase_name": phase_data["phase_name"],
                "phase_name_th": phase_data["phase_name_th"],
                "total_detections": phase_data["total_detections"],
                "sources": phase_data["sources"],
                "detection_methods": list(phase_data["detection_methods"])[:10],
                "top_detection_sources": sorted_sources
            })
        
        return {
            "phases": phases_coverage,
            "total_detections": total_detections,
            "time_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "active_phases": len([p for p in phases_coverage if p["total_detections"] > 0]),
            "methodology": "Cyber Kill Chain (Keyword Mapping Only)"
        }
        
    except Exception as e:
        logger.error(f"Error in cyber-kill-chain: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error mapping Cyber Kill Chain: {str(e)}")


# ===================================
# Health Check
# ===================================

@app.get("/", summary="Health Check")
async def root():
    """Check if API is running"""
    return {
        "status": "ok",
        "message": "MITRE ATT&CK PostgreSQL API",
        "endpoints": [
            "/api/postgres/technique-stats",
            "/api/postgres/stats",
            "/api/postgres/search",
            "/api/postgres/top-techniques"
        ],
        "data_source": "PostgreSQL"
    }

@app.get("/api/postgres/health", summary="Database Health Check")
async def health_check(db: Session = Depends(get_db)):
    """Check database connectivity and record count"""
    try:
        total_records = db.query(func.count(Rtarf.id)).scalar()
        latest_record = db.query(func.max(Rtarf.timestamp)).scalar()
        
        return {
            "status": "healthy",
            "database": "connected",
            "total_records": total_records,
            "latest_record": latest_record.isoformat() if latest_record else None
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database health check failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "postgres_api:app",
        host="0.0.0.0",
        port=8001,
        reload=True
    )