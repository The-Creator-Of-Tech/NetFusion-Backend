import sys
from collections import defaultdict
sys.path.insert(0, r"c:\Netfusion\NetFusion-Agent")

from main import app

routes = []
for r in app.routes:
    path = getattr(r, "path", str(r))
    methods = getattr(r, "methods", ["GET"])
    name = getattr(r, "name", "")
    routes.append((path, sorted(list(methods)), name))

grouped = defaultdict(list)
for path, methods, name in routes:
    prefix = path.split('/')[1] if len(path.split('/')) > 1 else 'root'
    grouped[prefix].append((path, ', '.join(methods), name))

with open(r"c:\Netfusion\NetFusion-Agent\scratch\all_routes.txt", "w") as f:
    for prefix in sorted(grouped.keys()):
        f.write(f"=== {prefix} ({len(grouped[prefix])} routes) ===\n")
        for path, methods, name in sorted(grouped[prefix]):
            f.write(f"  {path} [{methods}] -> {name}\n")
        f.write("\n")

print("Saved all routes to c:\\Netfusion\\NetFusion-Agent\\scratch\\all_routes.txt")
