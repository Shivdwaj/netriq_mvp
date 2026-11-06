"""
indexes.py
Comprehensive Indexing & Data Lifecycle Management for NetrIQ's 12 Core Entities:
1. organizations   - Customer organisations
2. users           - User accounts
3. roles           - Access permissions
4. sensors         - Registered network sensors
5. sensor_health   - Sensor operational status (TTL: 7 days)
6. network_events  - Normalised events (TTL: 30 days, indexed: src_ip, dst_ip, ts, event_type, sensor_id)
7. detection_rules - Detection configurations
8. alerts          - Individual detection results (TTL: 90 days)
9. incidents       - Correlated investigations
10. incident_events - Events linked to incidents (join entity)
11. evidence       - Supporting evidence references (TTL: 14 days, external PCAP sha256)
12. audit_logs     - User and administrative actions

Implementation Decisions:
- Tenant isolation: compound indexes prefix with tenant_id.
- UTC timestamps indexed for high-efficiency time-range queries.
- High-volume collections enforce TTL expiration for automated data minimisation.
"""

import os
import pymongo
from backend.database.database import DatabaseManager
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# --- Retention Policies (in days) ---
EVENT_RETENTION_DAYS = int(os.getenv("EVENT_RETENTION_DAYS", "30"))
EVENT_TTL_SECONDS = EVENT_RETENTION_DAYS * 86400

ALERT_RETENTION_DAYS = int(os.getenv("ALERT_RETENTION_DAYS", os.getenv("THREAT_RETENTION_DAYS", "90")))
ALERT_TTL_SECONDS = ALERT_RETENTION_DAYS * 86400

SENSOR_HEALTH_RETENTION_DAYS = int(os.getenv("SENSOR_HEALTH_RETENTION_DAYS", "7"))
SENSOR_HEALTH_TTL_SECONDS = SENSOR_HEALTH_RETENTION_DAYS * 86400

EVIDENCE_RETENTION_DAYS = int(os.getenv("EVIDENCE_RETENTION_DAYS", "14"))
EVIDENCE_TTL_SECONDS = EVIDENCE_RETENTION_DAYS * 86400

PREDICTION_RETENTION_DAYS = int(os.getenv("PREDICTION_RETENTION_DAYS", "30"))
PREDICTION_TTL_SECONDS = PREDICTION_RETENTION_DAYS * 86400


async def ensure_indexes():
    """
    Creates necessary indexes for performance, multi-tenant isolation,
    and automatic TTL data lifecycle management across all 12 entities.
    """
    db = DatabaseManager.get_db()
    if db is None:
        logger.error("Cannot ensure indexes: Database not connected.")
        return

    logger.info("Ensuring database indexes for all 12 NetrIQ entities...")

    try:
        # ======================================================================
        # 1. ORGANIZATIONS
        # ======================================================================
        orgs_coll = db["organizations"]
        await orgs_coll.create_index([("tenant_id", pymongo.ASCENDING)], unique=True, name="idx_org_tenant_id")
        await orgs_coll.create_index([("slug", pymongo.ASCENDING)], unique=True, name="idx_org_slug")

        # ======================================================================
        # 2. USERS
        # ======================================================================
        users_coll = db["users"]
        await users_coll.create_index([("email", pymongo.ASCENDING)], unique=True, name="idx_users_email_unique")
        await users_coll.create_index([("tenant_id", pymongo.ASCENDING), ("username", pymongo.ASCENDING)], name="idx_users_tenant_username")
        await users_coll.create_index([("tenant_id", pymongo.ASCENDING), ("role", pymongo.ASCENDING)], name="idx_users_tenant_role")

        # ======================================================================
        # 3. ROLES
        # ======================================================================
        roles_coll = db["roles"]
        await roles_coll.create_index([("tenant_id", pymongo.ASCENDING), ("role_name", pymongo.ASCENDING)], unique=True, name="idx_roles_tenant_name")

        # ======================================================================
        # 4. SENSORS
        # ======================================================================
        sensors_coll = db["sensors"]
        await sensors_coll.create_index([("tenant_id", pymongo.ASCENDING), ("sensor_id", pymongo.ASCENDING)], unique=True, name="idx_sensors_tenant_sensor_id")
        await sensors_coll.create_index([("api_key_hash", pymongo.ASCENDING)], name="idx_sensors_api_key_hash")
        await sensors_coll.create_index([("tenant_id", pymongo.ASCENDING), ("status", pymongo.ASCENDING)], name="idx_sensors_tenant_status")

        # ======================================================================
        # 5. SENSOR_HEALTH (TTL: 7 days)
        # ======================================================================
        health_coll = db["sensor_health"]
        await health_coll.create_index([
            ("tenant_id", pymongo.ASCENDING),
            ("sensor_id", pymongo.ASCENDING),
            ("timestamp", pymongo.DESCENDING)
        ], name="idx_sensor_health_query")

        if SENSOR_HEALTH_TTL_SECONDS > 0:
            await health_coll.create_index([("timestamp", pymongo.ASCENDING)], expireAfterSeconds=SENSOR_HEALTH_TTL_SECONDS, name="idx_sensor_health_ttl")

        # ======================================================================
        # 6. NETWORK_EVENTS (High Volume - TTL: 30 days)
        # Indexed: source_ip, destination_ip, timestamp, event_type, sensor_id
        # ======================================================================
        for coll_name in ["network_events", "events"]:
            events_coll = db[coll_name]
            await events_coll.create_index([("tenant_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name=f"idx_{coll_name}_tenant_ts")
            await events_coll.create_index([("tenant_id", pymongo.ASCENDING), ("source_ip", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name=f"idx_{coll_name}_src_ip")
            await events_coll.create_index([("tenant_id", pymongo.ASCENDING), ("destination_ip", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name=f"idx_{coll_name}_dst_ip")
            await events_coll.create_index([("tenant_id", pymongo.ASCENDING), ("sensor_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name=f"idx_{coll_name}_sensor_id")
            await events_coll.create_index([("tenant_id", pymongo.ASCENDING), ("event_type", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name=f"idx_{coll_name}_event_type")
            await events_coll.create_index([
                ("tenant_id", pymongo.ASCENDING),
                ("source_ip", pymongo.ASCENDING),
                ("destination_ip", pymongo.ASCENDING),
                ("timestamp", pymongo.DESCENDING)
            ], name=f"idx_{coll_name}_flow_compound")

            if EVENT_TTL_SECONDS > 0:
                await events_coll.create_index([("created_at", pymongo.ASCENDING)], expireAfterSeconds=EVENT_TTL_SECONDS, name=f"idx_{coll_name}_ttl")

        # ======================================================================
        # 7. DETECTION_RULES
        # ======================================================================
        rules_coll = db["detection_rules"]
        await rules_coll.create_index([("tenant_id", pymongo.ASCENDING), ("rule_id", pymongo.ASCENDING)], unique=True, name="idx_rules_tenant_rule_id")
        await rules_coll.create_index([("tenant_id", pymongo.ASCENDING), ("enabled", pymongo.ASCENDING)], name="idx_rules_tenant_enabled")
        await rules_coll.create_index([("tenant_id", pymongo.ASCENDING), ("engine", pymongo.ASCENDING)], name="idx_rules_tenant_engine")

        # ======================================================================
        # 8. ALERTS (High Volume - TTL: 90 days)
        # Indexed: source_ip, destination_ip, timestamp, severity, sensor_id
        # ======================================================================
        for coll_name in ["alerts", "threats"]:
            alerts_coll = db[coll_name]
            await alerts_coll.create_index([("tenant_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name=f"idx_{coll_name}_tenant_ts")
            await alerts_coll.create_index([("tenant_id", pymongo.ASCENDING), ("severity", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name=f"idx_{coll_name}_severity")
            await alerts_coll.create_index([("tenant_id", pymongo.ASCENDING), ("source_ip", pymongo.ASCENDING)], name=f"idx_{coll_name}_src_ip")
            await alerts_coll.create_index([("tenant_id", pymongo.ASCENDING), ("destination_ip", pymongo.ASCENDING)], name=f"idx_{coll_name}_dst_ip")
            await alerts_coll.create_index([("tenant_id", pymongo.ASCENDING), ("sensor_id", pymongo.ASCENDING)], name=f"idx_{coll_name}_sensor_id")
            await alerts_coll.create_index([("tenant_id", pymongo.ASCENDING), ("event_id", pymongo.ASCENDING)], name=f"idx_{coll_name}_event_id")

            if ALERT_TTL_SECONDS > 0:
                await alerts_coll.create_index([("timestamp", pymongo.ASCENDING)], expireAfterSeconds=ALERT_TTL_SECONDS, name=f"idx_{coll_name}_ttl")

        # ======================================================================
        # 9. INCIDENTS
        # ======================================================================
        incidents_coll = db["incidents"]
        await incidents_coll.create_index([
            ("tenant_id", pymongo.ASCENDING),
            ("status", pymongo.ASCENDING),
            ("created_at", pymongo.DESCENDING)
        ], name="idx_incidents_status_queue")
        await incidents_coll.create_index([("tenant_id", pymongo.ASCENDING), ("severity", pymongo.ASCENDING)], name="idx_incidents_severity")
        await incidents_coll.create_index([("tenant_id", pymongo.ASCENDING), ("src_ip", pymongo.ASCENDING)], name="idx_incidents_src_ip")

        # ======================================================================
        # 10. INCIDENT_EVENTS (Join Entity)
        # ======================================================================
        inc_events_coll = db["incident_events"]
        await inc_events_coll.create_index([("tenant_id", pymongo.ASCENDING), ("incident_id", pymongo.ASCENDING)], name="idx_inc_events_incident_id")
        await inc_events_coll.create_index([("tenant_id", pymongo.ASCENDING), ("event_id", pymongo.ASCENDING)], name="idx_inc_events_event_id")
        await inc_events_coll.create_index([("tenant_id", pymongo.ASCENDING), ("alert_id", pymongo.ASCENDING)], name="idx_inc_events_alert_id")

        # ======================================================================
        # 11. EVIDENCE (Supporting evidence & external PCAP references - TTL: 14 days)
        # ======================================================================
        evidence_coll = db["evidence"]
        await evidence_coll.create_index([("tenant_id", pymongo.ASCENDING), ("incident_id", pymongo.ASCENDING)], name="idx_evidence_incident_id")
        await evidence_coll.create_index([("file_hash_sha256", pymongo.ASCENDING)], name="idx_evidence_sha256_integrity")
        await evidence_coll.create_index([("tenant_id", pymongo.ASCENDING), ("sensor_id", pymongo.ASCENDING)], name="idx_evidence_sensor_id")

        if EVIDENCE_TTL_SECONDS > 0:
            await evidence_coll.create_index([("expires_at", pymongo.ASCENDING)], expireAfterSeconds=0, name="idx_evidence_ttl")

        # ======================================================================
        # 12. AUDIT_LOGS
        # ======================================================================
        audit_coll = db["audit_logs"]
        await audit_coll.create_index([("tenant_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name="idx_audit_tenant_ts")
        await audit_coll.create_index([("tenant_id", pymongo.ASCENDING), ("user_id", pymongo.ASCENDING), ("timestamp", pymongo.DESCENDING)], name="idx_audit_user_ts")
        await audit_coll.create_index([("tenant_id", pymongo.ASCENDING), ("action", pymongo.ASCENDING)], name="idx_audit_action")

        # ======================================================================
        # PREDICTIONS & IDEMPOTENCY
        # ======================================================================
        if PREDICTION_TTL_SECONDS > 0:
            pred_coll = db["predictions"]
            await pred_coll.create_index([("created_at", pymongo.ASCENDING)], expireAfterSeconds=PREDICTION_TTL_SECONDS, name="idx_predictions_ttl")

        idemp_coll = db["idempotency"]
        await idemp_coll.create_index([("key", pymongo.ASCENDING)], unique=True, name="idx_idempotency_key")
        await idemp_coll.create_index([("created_at", pymongo.ASCENDING)], expireAfterSeconds=86400, name="idx_idempotency_ttl_24h")

        logger.info("All 12 NetrIQ entity indexes and TTL policies ensured successfully.")

    except Exception as e:
        logger.error(f"Failed to ensure indexes: {e}")
