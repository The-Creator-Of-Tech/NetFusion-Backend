import os
import time
import pytest
from netfusion_collectors.threat_intelligence.cache import (
    MemoryCache,
    PersistentCache,
    ThreatIntelCache,
)


def test_memory_cache_basic():
    cache = MemoryCache(default_ttl=2)
    cache.set("key1", {"data": "value1"})

    val = cache.get("key1")
    assert val == {"data": "value1"}

    assert cache.invalidate("key1") is True
    assert cache.get("key1") is None


def test_memory_cache_ttl():
    cache = MemoryCache(default_ttl=1)
    cache.set("short_key", "value", ttl=1)

    assert cache.get("short_key") == "value"
    time.sleep(1.1)
    assert cache.get("short_key") is None


def test_persistent_cache_basic(temp_cache_dir):
    db_path = os.path.join(temp_cache_dir, "test_cache.db")
    pc = PersistentCache(db_path=db_path, default_ttl=3600)

    pc.set(
        key="abuseipdb:ipv4:1.1.1.1",
        value={"is_threat": True, "score": 95},
        provider="abuseipdb",
        ioc_type="ipv4",
        ioc_value="1.1.1.1",
    )

    retrieved = pc.get("abuseipdb:ipv4:1.1.1.1")
    assert retrieved is not None
    assert retrieved["is_threat"] is True
    assert retrieved["score"] == 95


def test_persistent_cache_invalidation(temp_cache_dir):
    db_path = os.path.join(temp_cache_dir, "test_cache.db")
    pc = PersistentCache(db_path=db_path)

    pc.set("key1", "val1", provider="provA")
    pc.set("key2", "val2", provider="provA")
    pc.set("key3", "val3", provider="provB")

    assert pc.invalidate_provider("provA") == 2
    assert pc.get("key1") is None
    assert pc.get("key2") is None
    assert pc.get("key3") == "val3"


def test_unified_threat_intel_cache(temp_cache_dir):
    db_path = os.path.join(temp_cache_dir, "unified.db")
    cache = ThreatIntelCache(db_path=db_path, default_ttl=100, negative_ttl=10)

    # Provider isolation check
    cache.set("virustotal", "IPv4", "8.8.8.8", {"threat": False}, is_negative=True)
    cache.set("abuseipdb", "IPv4", "8.8.8.8", {"threat": True}, is_negative=False)

    vt_res = cache.get("virustotal", "IPv4", "8.8.8.8")
    abuse_res = cache.get("abuseipdb", "IPv4", "8.8.8.8")

    assert vt_res["threat"] is False
    assert abuse_res["threat"] is True

    # Hit ratio check
    assert cache.hit_ratio() == 1.0

    cache.get("unknown_provider", "IPv4", "9.9.9.9")
    assert cache.hit_ratio() < 1.0
