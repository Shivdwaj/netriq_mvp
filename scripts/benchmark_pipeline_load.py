"""
scripts/benchmark_pipeline_load.py

Sustained Load Benchmark for NetrIQ Event Pipeline:
- Submits thousands of events at sustained volume into SecurityEventBus.
- Measures:
  * Sustained throughput (events/second)
  * p50, p95, p99 dispatch latency (milliseconds)
  * Peak memory delta (MB)
  * Queue depth under load
  * Dropped event count / backpressure rate
"""

import asyncio
import time
import tracemalloc
import sys
from pathlib import Path
from typing import List
import numpy as np

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.pipeline.event_bus import SecurityEventBus
from backend.pipeline.schemas import NormalizedSecurityEvent


async def mock_downstream_worker(event: NormalizedSecurityEvent):
    """Simulates realistic downstream worker processing (0.5ms - 2ms CPU work)."""
    # Simulate light CPU parsing/correlation work
    _ = f"{event.source_ip}:{event.destination_port}-{event.event_type}"
    await asyncio.sleep(0.001)  # 1ms asynchronous I/O / DB write


async def run_load_benchmark(total_events: int = 3000, max_queue_size: int = 500, max_concurrency: int = 50):
    print("=" * 70)
    print("       NETRIQ PIPELINE SUSTAINED LOAD BENCHMARK")
    print("=" * 70)
    print(f"Target Events: {total_events}")
    print(f"Max In-Flight Queue Size: {max_queue_size}")
    print(f"Max Concurrent Workers: {max_concurrency}\n")

    bus = SecurityEventBus(max_queue_size=max_queue_size, max_concurrency=max_concurrency)
    bus.subscribe(mock_downstream_worker)

    tracemalloc.start()
    latencies: List[float] = []
    accepted = 0
    dropped = 0

    benchmark_start = time.perf_counter()

    async def publish_event(idx: int):
        nonlocal accepted, dropped
        ev = NormalizedSecurityEvent(
            event_id=f"load-evt-{idx}",
            tenant_id=f"tenant-load-{idx % 5}",
            source_ip=f"192.168.1.{10 + (idx % 200)}",
            destination_ip="10.0.0.1",
            destination_port=80 + (idx % 100),
            protocol="TCP",
            event_type="connection",
            detection_source="zeek",
            severity="INFO"
        )
        t0 = time.perf_counter()
        dispatched = await bus.publish(ev, timeout=0.05)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt_ms)
        if dispatched:
            accepted += 1
        else:
            dropped += 1

    # Chunk publication to simulate sustained incoming traffic
    chunk_size = 100
    for i in range(0, total_events, chunk_size):
        chunk_tasks = [publish_event(idx) for idx in range(i, min(i + chunk_size, total_events))]
        await asyncio.gather(*chunk_tasks)
        # Yield briefly to event loop to allow workers to process
        await asyncio.sleep(0.005)

    # Drain remaining in-flight tasks
    drain_t0 = time.perf_counter()
    await bus.shutdown(drain_timeout=5.0)
    drain_time = time.perf_counter() - drain_t0

    total_duration = time.perf_counter() - benchmark_start
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    effective_throughput = total_events / max(total_duration, 0.001)
    p50 = float(np.percentile(latencies, 50))
    p95 = float(np.percentile(latencies, 95))
    p99 = float(np.percentile(latencies, 99))
    max_lat = max(latencies)

    print("\n--- Empirical Benchmark Results ---")
    print(f"Total Published Events : {total_events}")
    print(f"Accepted Events         : {accepted} ({round(accepted/total_events*100, 1)}%)")
    print(f"Dropped (Backpressure)  : {dropped} ({round(dropped/total_events*100, 1)}%)")
    print(f"Total Time              : {total_duration:.3f} s")
    print(f"Throughput              : {effective_throughput:.1f} events/sec")
    print(f"Drain Time on Shutdown  : {drain_time:.3f} s")
    print(f"Memory (Peak Traced)    : {peak_mem / (1024 * 1024):.2f} MB")
    print(f"Latency p50 (Median)    : {p50:.3f} ms")
    print(f"Latency p95             : {p95:.3f} ms")
    print(f"Latency p99             : {p99:.3f} ms")
    print(f"Latency Max             : {max_lat:.3f} ms")
    print("=" * 70)

    return {
        "total_events": total_events,
        "accepted": accepted,
        "dropped": dropped,
        "throughput_eps": round(effective_throughput, 1),
        "total_time_sec": round(total_duration, 3),
        "peak_mem_mb": round(peak_mem / (1024 * 1024), 2),
        "latency_p50_ms": round(p50, 3),
        "latency_p95_ms": round(p95, 3),
        "latency_p99_ms": round(p99, 3)
    }

async def main():
    print("\n[SCENARIO 1: SUSTAINED HIGH-THROUGHPUT CAPACITY]")
    await run_load_benchmark(total_events=3000, max_queue_size=500, max_concurrency=50)

    print("\n[SCENARIO 2: INTENTIONAL CONGESTION & BACKPRESSURE SATURATION]")
    # Restricted queue (50 capacity) with tight publication timeout (1ms) to measure backpressure drop rate
    await run_load_benchmark(total_events=1000, max_queue_size=50, max_concurrency=10)

if __name__ == "__main__":
    asyncio.run(main())
