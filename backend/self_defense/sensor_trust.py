"""
backend/self_defense/sensor_trust.py

Sensor Trust Engine (STE) for NetrIQ Stage 2 Self-Defense.
Maintains continuous mathematical trust scoring across edge sensors:
1. Dynamic trust score T_s in [0.0, 1.0] partitioned by tenant.
2. Anomaly detection: heartbeat jitter, missed intervals, clock drift, volume spikes/drops.
3. Bounded penalties avoiding single-incident condemnation.
4. Gradual trust recovery for consecutive healthy behavior.
5. Persistent database storage surviving backend restarts.
6. Multi-tenant isolation ensuring Tenant A cannot impact Tenant B.
"""

import os
import time
import asyncio
import statistics
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict

from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    TrustTier,
    SensorAnomalyType,
    SensorAnomalyEvent,
    SensorTrustScore,
    get_utc_now_timestamp,
    get_utc_now_iso,
)

logger = get_logger(__name__)

# Penalties and thresholds
PENALTY_CLOCK_DRIFT = 0.10
PENALTY_MISSED_HEARTBEAT = 0.10
PENALTY_JITTER = 0.05
PENALTY_VOLUME_ANOMALY = 0.08
PENALTY_INVALID_REPORT = 0.05
MAX_SINGLE_HEARTBEAT_PENALTY = 0.25  # Safeguard: never dock more than 0.25 in one heartbeat
RECOVERY_INCREMENT = 0.02            # Gradual recovery per consecutive healthy heartbeat

CLOCK_DRIFT_THRESHOLD_SECONDS = 5.0
DEFAULT_EXPECTED_INTERVAL_SECONDS = 30.0
MISSED_INTERVAL_MULTIPLIER = 2.5
JITTER_STDEV_THRESHOLD = 15.0


class SensorTrustEngine:
    """
    Sensor Trust Engine (STE).
    Evaluates sensor health, consistency, and telemetry frequency.
    Produces a continuous trust score without directly revoking credentials
    (revocation is managed by the Autonomous Response Controller in Step 6).
    """

    def __init__(self, sensors_repository=None, audit_ledger_instance=None):
        self._repo = sensors_repository
        self._audit = audit_ledger_instance
        self._locks: Dict[Tuple[str, str], asyncio.Lock] = defaultdict(asyncio.Lock)
        self._trust_cache: Dict[Tuple[str, str], SensorTrustScore] = {}
        self._volume_history: Dict[Tuple[str, str], List[int]] = defaultdict(list)

    def _get_repo(self):
        if self._repo is not None:
            return self._repo
        from backend.database.collections import sensors_repo
        return sensors_repo

    def _get_audit(self):
        if self._audit is not None:
            return self._audit
        from backend.self_defense.audit_ledger import audit_ledger
        return audit_ledger

    def _compute_tier(self, score: float) -> TrustTier:
        if score >= 0.80:
            return TrustTier.TRUSTED
        elif score >= 0.50:
            return TrustTier.SUSPICIOUS
        else:
            return TrustTier.UNTRUSTED

    async def get_or_create_trust_score(self, sensor_id: str, tenant_id: str) -> SensorTrustScore:
        """
        Retrieves the trust score for a sensor, checking memory cache first,
        then database persistence, or initializing to 1.0 for newly registered sensors.
        """
        cache_key = (tenant_id, sensor_id)
        if cache_key in self._trust_cache:
            return self._trust_cache[cache_key]

        repo = self._get_repo()
        try:
            docs = await repo.list(filter_query={"sensor_id": sensor_id, "tenant_id": tenant_id}, limit=1)
            if not docs and tenant_id == "global":
                docs = await repo.list(filter_query={"sensor_id": sensor_id}, limit=1)

            if docs and docs[0].get("trust_state"):
                raw_state = docs[0]["trust_state"]
                score_obj = SensorTrustScore(**raw_state)
                self._trust_cache[cache_key] = score_obj
                return score_obj
            elif docs and "trust_score" in docs[0]:
                raw_score = float(docs[0]["trust_score"])
                score_obj = SensorTrustScore(
                    sensor_id=sensor_id,
                    tenant_id=tenant_id,
                    trust_score=raw_score,
                    trust_tier=self._compute_tier(raw_score),
                    observation_count=int(docs[0].get("packets_processed", 0)),
                )
                self._trust_cache[cache_key] = score_obj
                return score_obj
        except Exception as e:
            logger.warning(f"[SensorTrustEngine] Could not read persisted trust state for {sensor_id}: {e}")

        # Brand new sensor defaults to 1.0 (Trusted)
        score_obj = SensorTrustScore(
            sensor_id=sensor_id,
            tenant_id=tenant_id,
            trust_score=1.0,
            trust_tier=TrustTier.TRUSTED,
            observation_count=0,
            consecutive_healthy=0,
        )
        self._trust_cache[cache_key] = score_obj
        return score_obj

    async def _persist_state(self, state: SensorTrustScore) -> None:
        """Persists the trust score and history into the database."""
        repo = self._get_repo()
        try:
            payload = {
                "trust_score": state.trust_score,
                "trust_tier": state.trust_tier.value,
                "trust_state": state.model_dump(),
                "updated_at": state.updated_at,
            }
            # Update sensor record by composite or sensor_id
            if hasattr(repo, "collection") and hasattr(repo.collection, "update_one"):
                await repo.collection.update_one(
                    {"sensor_id": state.sensor_id, "tenant_id": state.tenant_id},
                    {"$set": payload},
                    upsert=True
                )
        except Exception as e:
            logger.error(f"[SensorTrustEngine] Failed to persist trust state for {state.sensor_id}: {e}")

    async def evaluate_heartbeat(
        self,
        sensor_id: str,
        tenant_id: str,
        heartbeat_data: Dict[str, Any],
        reported_timestamp: Optional[float] = None,
    ) -> SensorTrustScore:
        """
        Evaluates a heartbeat submission:
        - Checks clock drift against reported_timestamp.
        - Checks interval jitter and missed heartbeats.
        - Validates metric consistency.
        - Applies bounded penalties or gradual recovery.
        - Strictly partitioned by tenant_id.
        """
        cache_key = (tenant_id, sensor_id)
        async with self._locks[cache_key]:
            state = await self.get_or_create_trust_score(sensor_id, tenant_id)
            now = get_utc_now_timestamp()
            now_iso = get_utc_now_iso()
            anomalies: List[SensorAnomalyEvent] = []
            previous_tier = state.trust_tier

            state.observation_count += 1

            # 1. Clock Drift Evaluation
            if reported_timestamp is not None:
                drift = abs(now - float(reported_timestamp))
                if drift > CLOCK_DRIFT_THRESHOLD_SECONDS:
                    anomalies.append(
                        SensorAnomalyEvent(
                            anomaly_type=SensorAnomalyType.CLOCK_DRIFT,
                            penalty=PENALTY_CLOCK_DRIFT,
                            description=f"Clock drift detected: {drift:.2f}s exceeds threshold ({CLOCK_DRIFT_THRESHOLD_SECONDS}s)",
                            details={"drift_seconds": drift, "reported": reported_timestamp, "backend": now},
                        )
                    )

            # 2. Heartbeat Regularity & Jitter Evaluation
            if state.last_heartbeat_timestamp is not None:
                interval = now - state.last_heartbeat_timestamp
                state.heartbeat_intervals.append(interval)
                # Keep rolling window of last 10 intervals
                if len(state.heartbeat_intervals) > 10:
                    state.heartbeat_intervals = state.heartbeat_intervals[-10:]

                # Check missed heartbeat
                expected_interval = (
                    statistics.mean(state.heartbeat_intervals[:-1])
                    if len(state.heartbeat_intervals) > 2
                    else DEFAULT_EXPECTED_INTERVAL_SECONDS
                )
                if interval > (expected_interval * MISSED_INTERVAL_MULTIPLIER) or interval > 75.0:
                    anomalies.append(
                        SensorAnomalyEvent(
                            anomaly_type=SensorAnomalyType.MISSED_HEARTBEAT,
                            penalty=PENALTY_MISSED_HEARTBEAT,
                            description=f"Missed heartbeat detected: interval {interval:.2f}s exceeds expected ({expected_interval:.2f}s)",
                            details={"interval_seconds": interval, "expected_interval": expected_interval},
                        )
                    )

                # Check jitter (variance) if we have sufficient samples
                if len(state.heartbeat_intervals) >= 4:
                    stdev = statistics.stdev(state.heartbeat_intervals)
                    if stdev > JITTER_STDEV_THRESHOLD:
                        anomalies.append(
                            SensorAnomalyEvent(
                                anomaly_type=SensorAnomalyType.HEARTBEAT_JITTER,
                                penalty=PENALTY_JITTER,
                                description=f"Excessive heartbeat jitter: standard deviation {stdev:.2f}s exceeds threshold ({JITTER_STDEV_THRESHOLD}s)",
                                details={"stdev": stdev, "intervals": state.heartbeat_intervals},
                            )
                        )

            # 3. Metric Inconsistency Evaluation
            cpu = float(heartbeat_data.get("cpu_usage_pct", 0.0) or 0.0)
            mem = float(heartbeat_data.get("memory_usage_mb", 0.0) or 0.0)
            drops = int(heartbeat_data.get("kernel_drops_count", 0) or 0)
            packets = int(heartbeat_data.get("packets_processed", 0) or 0)

            if cpu < 0.0 or cpu > 100.0 or mem < 0.0 or drops < 0 or packets < 0:
                anomalies.append(
                    SensorAnomalyEvent(
                        anomaly_type=SensorAnomalyType.INVALID_REPORT,
                        penalty=PENALTY_INVALID_REPORT,
                        description="Inconsistent or impossible telemetry metric values reported",
                        details={"cpu": cpu, "mem": mem, "drops": drops, "packets": packets},
                    )
                )

            # 4. Score Computation: Bounded Penalty vs Gradual Recovery
            if anomalies:
                total_penalty = sum(a.penalty for a in anomalies)
                # Safeguard: cap penalty per single evaluation to prevent single-incident condemnation
                capped_penalty = min(total_penalty, MAX_SINGLE_HEARTBEAT_PENALTY)
                new_score = max(0.0, round(state.trust_score - capped_penalty, 4))
                state.trust_score = new_score
                state.consecutive_healthy = 0
                state.recent_anomalies.extend(anomalies)
                if len(state.recent_anomalies) > 20:
                    state.recent_anomalies = state.recent_anomalies[-20:]
            else:
                state.consecutive_healthy += 1
                # Gradual recovery
                new_score = min(1.0, round(state.trust_score + RECOVERY_INCREMENT, 4))
                state.trust_score = new_score

            # 5. State & Tier Update
            state.trust_tier = self._compute_tier(state.trust_score)
            state.last_heartbeat_timestamp = now
            state.updated_at = now
            state.updated_at_iso = now_iso
            self._trust_cache[cache_key] = state

            # 6. Audit Logging on Tier Demotion
            if previous_tier == TrustTier.TRUSTED and state.trust_tier in (TrustTier.SUSPICIOUS, TrustTier.UNTRUSTED):
                try:
                    audit = self._get_audit()
                    await audit.append_entry(
                        action="SENSOR_TRUST_DEGRADED",
                        resource_type="sensor",
                        resource_id=sensor_id,
                        tenant_id=tenant_id,
                        details={
                            "previous_tier": previous_tier.value,
                            "new_tier": state.trust_tier.value,
                            "trust_score": state.trust_score,
                            "anomaly_count": len(anomalies),
                            "reasons": [a.description for a in anomalies],
                        },
                    )
                except Exception as audit_err:
                    logger.warning(f"[SensorTrustEngine] Could not record trust degradation to audit log: {audit_err}")

            # 7. Persist to storage
            await self._persist_state(state)
            return state

    async def record_telemetry_batch(
        self, sensor_id: str, tenant_id: str, batch_size: int
    ) -> SensorTrustScore:
        """
        Tracks flow telemetry batch volumes. Detects sudden volume spikes or drops
        after establishing a baseline.
        """
        cache_key = (tenant_id, sensor_id)
        async with self._locks[cache_key]:
            state = await self.get_or_create_trust_score(sensor_id, tenant_id)
            history = self._volume_history[cache_key]
            now = get_utc_now_timestamp()

            if len(history) >= 5:
                mean_vol = statistics.mean(history)
                # Volume spike: > 4.5x rolling mean
                if batch_size > (mean_vol * 4.5) and batch_size > 100:
                    penalty = PENALTY_VOLUME_ANOMALY
                    state.trust_score = max(0.0, round(state.trust_score - penalty, 4))
                    state.trust_tier = self._compute_tier(state.trust_score)
                    state.recent_anomalies.append(
                        SensorAnomalyEvent(
                            anomaly_type=SensorAnomalyType.VOLUME_SPIKE,
                            penalty=penalty,
                            description=f"Sudden telemetry volume surge: batch_size={batch_size} vs rolling mean={mean_vol:.1f}",
                            details={"batch_size": batch_size, "mean_volume": mean_vol},
                        )
                    )
                    await self._persist_state(state)
                # Volume collapse during active monitoring
                elif batch_size == 0 and mean_vol > 50:
                    penalty = PENALTY_VOLUME_ANOMALY
                    state.trust_score = max(0.0, round(state.trust_score - penalty, 4))
                    state.trust_tier = self._compute_tier(state.trust_score)
                    state.recent_anomalies.append(
                        SensorAnomalyEvent(
                            anomaly_type=SensorAnomalyType.VOLUME_DROP,
                            penalty=penalty,
                            description=f"Sudden telemetry collapse: batch_size=0 vs expected {mean_vol:.1f}",
                            details={"batch_size": batch_size, "mean_volume": mean_vol},
                        )
                    )
                    await self._persist_state(state)

            history.append(batch_size)
            if len(history) > 20:
                self._volume_history[cache_key] = history[-20:]

            return state

    async def record_invalid_report(
        self, sensor_id: str, tenant_id: str, reason: str, details: Optional[Dict[str, Any]] = None
    ) -> SensorTrustScore:
        """
        Records an invalid submission (e.g. malformed payload, signature error, bad headers).
        Applies a bounded penalty.
        """
        cache_key = (tenant_id, sensor_id)
        async with self._locks[cache_key]:
            state = await self.get_or_create_trust_score(sensor_id, tenant_id)
            state.trust_score = max(0.0, round(state.trust_score - PENALTY_INVALID_REPORT, 4))
            state.trust_tier = self._compute_tier(state.trust_score)
            state.consecutive_healthy = 0
            state.recent_anomalies.append(
                SensorAnomalyEvent(
                    anomaly_type=SensorAnomalyType.INVALID_REPORT,
                    penalty=PENALTY_INVALID_REPORT,
                    description=reason,
                    details=details or {},
                )
            )
            state.updated_at = get_utc_now_timestamp()
            state.updated_at_iso = get_utc_now_iso()
            await self._persist_state(state)
            return state


# Global singleton instance
sensor_trust_engine = SensorTrustEngine()
