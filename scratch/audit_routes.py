import importlib
import os
import sys
import inspect

sys.path.insert(0, r"c:\Netfusion\NetFusion-Agent")

from main import app

routes = []
for r in app.routes:
    path = getattr(r, "path", str(r))
    methods = getattr(r, "methods", ["GET"])
    name = getattr(r, "name", "")
    routes.append((path, sorted(list(methods)), name))

print(f"Total routes in FastAPI app: {len(routes)}")
for path, methods, name in sorted(routes):
    print(f"{path} [{', '.join(methods)}] -> {name}")
