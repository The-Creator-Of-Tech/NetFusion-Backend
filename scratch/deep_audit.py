import sys
import importlib

sys.path.insert(0, r"c:\Netfusion\NetFusion-Agent")

from main import app
from scratch.find_all_routers import routers_found

# Get all route paths currently registered in main app
app_routes = set()
for r in app.routes:
    path = getattr(r, "path", "")
    methods = getattr(r, "methods", set())
    for m in methods:
        app_routes.add((m, path))

print(f"Total endpoints registered in app: {len(app_routes)}\n")

results = []

for r in routers_found:
    file = r['file']
    var_name = r['var_name']
    prefix = r['prefix']
    tags = r['tags']
    line = r['line']

    # Convert file path to module path
    mod_path = file.replace('\\', '/').replace('.py', '').replace('/', '.')
    
    try:
        mod = importlib.import_module(mod_path)
        router_obj = getattr(mod, var_name, None)
        if router_obj is None:
            results.append({
                'file': file,
                'var': var_name,
                'status': 'var_not_found',
                'route_count': 0,
                'mounted_count': 0
            })
            continue

        # Find routes in router_obj
        r_routes = getattr(router_obj, 'routes', [])
        
        # Check how many of router's endpoints exist in app_routes
        mounted_count = 0
        total_in_router = 0
        unmounted_samples = []

        for route in r_routes:
            path = getattr(route, 'path', '')
            methods = getattr(route, 'methods', set())
            for m in methods:
                total_in_router += 1
                # Note: if router is mounted at root or with prefix or inside root_router (/api/v2),
                # check if (m, path) or (m, "/api/v2" + path) or prefix matches
                found = False
                if (m, path) in app_routes or (m, f"/api/v2{path}") in app_routes:
                    found = True
                else:
                    # check any app_route ending with path
                    for am, ap in app_routes:
                        if am == m and (ap == path or ap.endswith(path)):
                            found = True
                            break
                if found:
                    mounted_count += 1
                else:
                    unmounted_samples.append(f"{m} {path}")

        results.append({
            'file': file,
            'var': var_name,
            'prefix': prefix,
            'tags': tags,
            'total_routes': len(r_routes),
            'total_methods': total_in_router,
            'mounted_methods': mounted_count,
            'unmounted_samples': unmounted_samples[:3]
        })

    except Exception as e:
        results.append({
            'file': file,
            'var': var_name,
            'status': f'import_error: {e}',
            'route_count': 0,
            'mounted_count': 0
        })

print(f"{'FILE':<55} | {'VAR':<25} | {'ROUTES':<7} | {'MOUNTED':<7} | STATUS")
print("-" * 115)
for res in sorted(results, key=lambda x: x['file']):
    status = "OK"
    if 'status' in res:
        status = res['status']
    elif res['total_methods'] > 0 and res['mounted_methods'] == 0:
        status = "NOT MOUNTED"
    elif res['mounted_methods'] < res['total_methods']:
        status = f"PARTIAL ({res['mounted_methods']}/{res['total_methods']})"
    else:
        status = "MOUNTED"
    
    print(f"{res['file']:<55} | {res['var']:<25} | {res.get('total_routes',0):<7} | {res.get('mounted_methods',0):<7} | {status}")
    if res.get('unmounted_samples'):
        print(f"   Unmounted samples: {res['unmounted_samples']}")
