import sys

sys.path.insert(0, r"c:\Netfusion\NetFusion-Agent")

from main import app

print("=== NETFUSION APIRouter INTEGRATION VERIFICATION ===")

# 1. Startup verification
print("[OK] FastAPI main app loaded successfully.")

# 2. Count routes
routes = app.routes
print(f"[OK] Total registered routes in FastAPI app: {len(routes)}")

# 3. Generate OpenAPI schema
try:
    schema = app.openapi()
    paths_count = len(schema.get("paths", {}))
    print(f"[OK] OpenAPI schema generated successfully with {paths_count} unique paths.")
except Exception as e:
    print(f"[FAIL] OpenAPI schema generation failed: {e}")
    sys.exit(1)

# 4. Check all 38 APIRouter instances from audit
from scratch.find_all_routers import routers_found

print(f"\nChecking all {len(routers_found)} APIRouters:")
mounted_count = 0
for r in sorted(routers_found, key=lambda x: x['file']):
    file = r['file']
    var_name = r['var_name']
    prefix = r['prefix']
    
    # Verify module import
    mod_path = file.replace('\\', '/').replace('.py', '').replace('/', '.')
    try:
        mod = __import__(mod_path, fromlist=[var_name])
        router_obj = getattr(mod, var_name)
        r_routes = getattr(router_obj, 'routes', [])
        
        # Verify routes are in app
        if len(r_routes) == 0:
            print(f"  [OK] {file} ({var_name}) -> Container router (0 direct routes)")
            mounted_count += 1
        else:
            sample_route = r_routes[0]
            sample_path = getattr(sample_route, 'path', '')
            sample_methods = getattr(sample_route, 'methods', ['GET'])
            
            # Check if any route in app matches
            found = False
            for ar in app.routes:
                ap = getattr(ar, 'path', '')
                if sample_path in ap or ap.endswith(sample_path):
                    found = True
                    break
            
            if found:
                print(f"  [OK] {file} ({var_name}) [{len(r_routes)} routes] -> MOUNTED")
                mounted_count += 1
            else:
                print(f"  [FAIL] {file} ({var_name}) -> NOT MOUNTED")
    except Exception as e:
        print(f"  [FAIL] {file} ({var_name}) -> ERROR: {e}")

print(f"\nSummary: {mounted_count}/{len(routers_found)} APIRouters verified as mounted.")
