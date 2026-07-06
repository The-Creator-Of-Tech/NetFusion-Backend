import api
from api.router import root_router, asset_router

# Check all asset routes registered
print("=== Asset router routes ===")
for r in asset_router.routes:
    print(f"  {sorted(r.methods)} {r.path}")

print()
print("=== Root router full paths ===")
for r in root_router.routes:
    print(f"  {sorted(getattr(r, 'methods', []))} {r.path}")

# Verify all 6 endpoints are present
asset_paths = {r.path for r in asset_router.routes}
expected = {"/assets", "/assets/statistics", "/assets/{assetId}"}
for p in expected:
    assert p in asset_paths, f"Missing path: {p}"
print("\nAll expected paths present: OK")

# Verify HTTP methods
methods_by_path = {}
for r in asset_router.routes:
    methods_by_path.setdefault(r.path, set()).update(r.methods or [])

assert "GET"    in methods_by_path.get("/assets", set())
assert "POST"   in methods_by_path.get("/assets", set())
assert "GET"    in methods_by_path.get("/assets/{assetId}", set())
assert "PUT"    in methods_by_path.get("/assets/{assetId}", set())
assert "DELETE" in methods_by_path.get("/assets/{assetId}", set())
assert "GET"    in methods_by_path.get("/assets/statistics", set())
print("All methods correct: OK")

# Functional tests via direct endpoint calls
from api.investigation.asset_router import _reset_store
from api.investigation.asset_router import (
    create_asset, get_asset, list_assets,
    delete_asset, update_asset, get_asset_statistics,
)
from api.investigation.asset_models import CreateAssetRequest, UpdateAssetRequest

_reset_store()

# Create
body = CreateAssetRequest(assetId="aa:bb:cc:dd:ee:ff", hostname="test-host", vendor="Cisco", currentIp="192.168.1.1")
resp = create_asset(body)
assert resp.success == True, f"create failed: {resp}"
assert resp.data["assetId"] == "aa:bb:cc:dd:ee:ff"
print("create_asset: OK")

# Duplicate → 409
resp2 = create_asset(body)
assert resp2.success == False
assert resp2.data.errorCode == "CONFLICT"
print("create_asset duplicate: OK (CONFLICT)")

# Create with empty assetId → 422
bad = CreateAssetRequest(assetId="   ")
resp_bad = create_asset(bad)
assert resp_bad.success == False
assert resp_bad.data.errorCode == "VALIDATION_ERROR"
print("create_asset empty assetId: OK (VALIDATION_ERROR)")

# Get existing
resp3 = get_asset("aa:bb:cc:dd:ee:ff")
assert resp3.success == True
assert resp3.data["hostname"] == "test-host"
print("get_asset existing: OK")

# Get missing → 404
resp4 = get_asset("nonexistent-id")
assert resp4.success == False
assert resp4.data.errorCode == "NOT_FOUND"
print("get_asset missing: OK (NOT_FOUND)")

# List
resp5 = list_assets()
assert resp5.success == True
assert resp5.data["total"] == 1
print("list_assets: OK")

# List with vendor filter
resp5b = list_assets(vendor="Cisco")
assert resp5b.data["total"] == 1
resp5c = list_assets(vendor="Unknown")
assert resp5c.data["total"] == 0
print("list_assets with filter: OK")

# Statistics
resp6 = get_asset_statistics()
assert resp6.success == True
assert resp6.data["totalAssets"] == 1
assert resp6.data["activeAssets"] == 1
print("get_asset_statistics: OK")

# Update hostname
upd = UpdateAssetRequest(hostname="updated-host")
resp7 = update_asset("aa:bb:cc:dd:ee:ff", upd)
assert resp7.success == True
assert resp7.data["hostname"] == "updated-host"
print("update_asset: OK")

# Update missing → 404
resp8 = update_asset("no-such", upd)
assert resp8.success == False
assert resp8.data.errorCode == "NOT_FOUND"
print("update_asset missing: OK (NOT_FOUND)")

# Update with no fields → 422
empty_upd = UpdateAssetRequest()
resp9 = update_asset("aa:bb:cc:dd:ee:ff", empty_upd)
assert resp9.success == False
assert resp9.data.errorCode == "VALIDATION_ERROR"
print("update_asset empty body: OK (VALIDATION_ERROR)")

# Delete
resp10 = delete_asset("aa:bb:cc:dd:ee:ff")
assert resp10.success == True
assert resp10.data is None
print("delete_asset: OK")

# Delete missing → 404
resp11 = delete_asset("aa:bb:cc:dd:ee:ff")
assert resp11.success == False
assert resp11.data.errorCode == "NOT_FOUND"
print("delete_asset missing: OK (NOT_FOUND)")

# List after delete → 0
resp12 = list_assets()
assert resp12.data["total"] == 0
print("list_assets after delete: OK")

# Test AssetResponse model fields
_reset_store()
b2 = CreateAssetRequest(
    assetId="mac-full",
    macAddress="00:11:22:33:44:55",
    hostname="fullhost",
    deviceName="MyDevice",
    vendor="Cisco",
    operatingSystem="Linux",
    currentIp="10.0.0.1",
    currentStatus="active",
    notes=["note1"],
    metadata={"k": "v"},
)
resp_full = create_asset(b2)
d = resp_full.data
assert d["macAddress"]       == "00:11:22:33:44:55"
assert d["hostname"]         == "fullhost"
assert d["deviceName"]       == "MyDevice"
assert d["vendor"]           == "Cisco"
assert d["operatingSystem"]  == "Linux"
assert d["currentIp"]        == "10.0.0.1"
assert d["currentStatus"]    == "active"
assert d["notes"]            == ["note1"]
assert d["metadata"]         == {"k": "v"}
assert d["currentRiskScore"] == 0
assert d["packetCount"]      == 0
print("AssetResponse full fields: OK")

# Statistics with multiple assets
b3 = CreateAssetRequest(assetId="ext-1", currentStatus="external", vendor="Cisco")
b4 = CreateAssetRequest(assetId="ext-2", currentStatus="external", vendor="Apple")
create_asset(b3)
create_asset(b4)
stats_resp = get_asset_statistics()
sd = stats_resp.data
assert sd["totalAssets"]    == 3
assert sd["activeAssets"]   == 1
assert sd["externalAssets"] == 2
assert "Cisco" in sd["vendorCounts"]
assert sd["vendorCounts"]["Cisco"] == 2
assert "active"   in sd["statusCounts"]
assert "external" in sd["statusCounts"]
print("get_asset_statistics multi-asset: OK")

print("\nALL CHECKS PASSED")
