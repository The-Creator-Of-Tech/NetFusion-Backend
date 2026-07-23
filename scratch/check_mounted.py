import sys
sys.path.insert(0, r"c:\Netfusion\NetFusion-Agent")

from main import app

print("Inspecting app.routes...")
mounted_paths = set()
for r in app.routes:
    path = getattr(r, "path", str(r))
    methods = getattr(r, "methods", ["GET"])
    mounted_paths.add(path)

print(f"Total routes currently in main:app: {len(app.routes)}")

# Check specific prefixes
prefixes_to_check = [
    "/reasoning",
    "/api/v2/reasoning",
    "/intelligence",
    "/api/v2/intelligence",
    "/investigations",
    "/api/v2/investigations",
    "/graph",
    "/api/v2/graph",
    "/intelligence/identity",
    "/intelligence/epss"
]

for p in prefixes_to_check:
    matching = [path for path in mounted_paths if path.startswith(p)]
    print(f"Prefix '{p}': {len(matching)} endpoints matching")
    for m in matching[:5]:
        print(f"   -> {m}")
