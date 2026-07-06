"""Application configuration loaded from environment variables."""

import os

from dotenv import load_dotenv

load_dotenv()

PRISMA_API_BASE_URL = os.getenv("PRISMA_API_BASE_URL", "http://localhost:4000")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
NMAP_COMMAND = "nmap"

PRISMA_REQUEST_TIMEOUT = 20
PRISMA_DETECTIVE_TIMEOUT = 5

# Maximum number of EvidenceRecords sent per batch-insert request.
# The Node endpoint handles hash-based dedup and insert in one transaction.
# Tune via environment variable; default 200 is safe for SQLite.
EVIDENCE_BATCH_CHUNK_SIZE = int(os.getenv("EVIDENCE_BATCH_CHUNK_SIZE", "200"))

# Batch sizes for Relationship persistence.
# Tune via environment variables; defaults are safe for SQLite.
RELATIONSHIP_BATCH_CHUNK_SIZE         = int(os.getenv("RELATIONSHIP_BATCH_CHUNK_SIZE", "100"))
RELATIONSHIP_EVIDENCE_BATCH_CHUNK_SIZE = int(os.getenv("RELATIONSHIP_EVIDENCE_BATCH_CHUNK_SIZE", "200"))
