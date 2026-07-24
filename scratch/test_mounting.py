import sys
sys.path.insert(0, r"c:\Netfusion\NetFusion-Agent")

from fastapi import FastAPI
from main import app as main_app

from netfusion_ai.reasoning.api import router as atre_reasoning_router
from netfusion_intelligence.api.routes import router as intelligence_router
from netfusion_investigation.lifecycle.api import router as investigation_lifecycle_router

print("Initial main_app route count:", len(main_app.routes))

# Try mounting them
main_app.include_router(atre_reasoning_router)
main_app.include_router(intelligence_router)
main_app.include_router(investigation_lifecycle_router)

print("Mounted main_app route count:", len(main_app.routes))

# Generate openapi schema
openapi_schema = main_app.openapi()
print("OpenAPI schema generated successfully!")
print("OpenAPI title:", openapi_schema.get("info", {}).get("title"))
print("Total paths in OpenAPI schema:", len(openapi_schema.get("paths", {})))
