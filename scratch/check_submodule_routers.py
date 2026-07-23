import os
import sys

sys.path.insert(0, r"c:\Netfusion\NetFusion-Agent")

# Check modules in netfusion_intelligence, netfusion_investigation, netfusion_ai, netfusion_workflow, netfusion_platform

def inspect_router(mod_path):
    try:
        mod = __import__(mod_path, fromlist=['router', 'app'])
        r = getattr(mod, 'router', getattr(mod, 'app', None))
        if r:
            routes = [getattr(x, 'path', str(x)) for x in getattr(r, 'routes', [])]
            return len(routes), routes
    except Exception as e:
        return f"Error: {e}", []
    return "No router found", []

modules = [
    "netfusion_investigation.lifecycle.api",
    "netfusion_intelligence.graph.api",
    "netfusion_intelligence.analytics.epss.api",
    "netfusion_intelligence.feeds.kev.api",
    "netfusion_intelligence.feeds.capec.api",
    "netfusion_intelligence.feeds.cwe.api",
    "netfusion_ai.reasoning.api",
    "netfusion_platform.api.app",
]

for m in modules:
    res, r_list = inspect_router(m)
    print(f"Module {m}: {res}")
    if isinstance(r_list, list) and r_list:
        print(f"   First 3 routes: {r_list[:3]}")
