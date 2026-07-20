"""
Integration tests for Backup/Restore Manager and Performance Validation Suite.
"""

import pytest
import os
import tempfile
from netfusion_platform.backup import BackupManager
from netfusion_platform.performance import PlatformPerformanceSuite


def test_backup_and_recovery():
    with tempfile.TemporaryDirectory() as tmpdir:
        bm = BackupManager(backup_root=tmpdir)
        
        # Test config backup
        config_backup = bm.backup_configuration()
        assert config_backup.exists()

        # Test dummy DB backup
        dummy_db = os.path.join(tmpdir, "test.db")
        open(dummy_db, "w").write("DB_DATA")
        
        db_backup = bm.backup_database(dummy_db)
        assert db_backup.exists()

        target_restored = os.path.join(tmpdir, "restored.db")
        bm.restore_database(str(db_backup), target_restored)
        assert open(target_restored).read() == "DB_DATA"


def test_performance_benchmarks():
    suite = PlatformPerformanceSuite()
    
    # Timeline benchmark
    res_timeline = suite.benchmark_large_timeline(event_count=50)
    assert res_timeline.item_count == 50
    assert res_timeline.duration_seconds >= 0.0

    # High IOC volume benchmark
    res_ioc = suite.benchmark_high_ioc_volume(ioc_count=50)
    assert res_ioc.item_count == 50
    assert res_ioc.throughput_items_per_sec > 0.0
