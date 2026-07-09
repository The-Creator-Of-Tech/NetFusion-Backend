"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const sqlite_client_1 = require("./generated/sqlite-client");
const prisma_1 = __importDefault(require("./lib/prisma"));
const coreRepos = __importStar(require("./repositories/core"));
const invRepos = __importStar(require("./repositories/investigation"));
const aiRepos = __importStar(require("./repositories/ai"));
const knowRepos = __importStar(require("./repositories/knowledge"));
const wfRepos = __importStar(require("./repositories/workflow"));
const prisma = new sqlite_client_1.PrismaClient();
const app = (0, express_1.default)();
app.use(body_parser_1.default.json({ limit: "2mb" }));
function logSaved() {
    console.log("=== CAPTURE SESSION SAVED ===");
}
function logRestored() {
    console.log("=== CAPTURE SESSION RESTORED ===");
}
function logReset() {
    console.log("=== CAPTURE SESSION RESET ===");
}
// GET latest session for project
app.get("/api/projects/:id/capture-session", async (req, res) => {
    const projectId = req.params.id;
    try {
        const session = await prisma.captureSession.findFirst({
            where: { projectId },
            orderBy: { updatedAt: "desc" }
        });
        if (session) {
            logRestored();
            const parseJson = (value) => {
                if (typeof value !== "string")
                    return value;
                try {
                    return JSON.parse(value);
                }
                catch {
                    return value;
                }
            };
            return res.json({
                ...session,
                analysis: parseJson(session.analysis),
                timeline: parseJson(session.timeline),
                alerts: parseJson(session.alerts),
                iocs: parseJson(session.iocs),
                correlations: parseJson(session.correlations),
                mitre: parseJson(session.mitre),
                riskRanking: parseJson(session.riskRanking),
                attackStory: parseJson(session.attackStory),
                investigationPlan: parseJson(session.investigationPlan)
            });
        }
        return res.json(null);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Internal server error" });
    }
});
// PUT create or update session
app.put("/api/projects/:id/capture-session", async (req, res) => {
    const projectId = req.params.id;
    const payload = req.body || {};
    const data = {
        projectId,
        captureId: payload.captureId || null,
        packetCount: payload.packetCount || 0,
        analysis: payload.analysis || null,
        timeline: payload.timeline || null,
        alerts: payload.alerts || null,
        iocs: payload.iocs || null,
        correlations: payload.correlations || null,
        mitre: payload.mitre || null,
        riskRanking: payload.riskRanking || null,
        attackStory: payload.attackStory || null,
        investigationPlan: payload.investigationPlan || null,
        executiveReport: payload.executiveReport || null
    };
    try {
        // upsert by projectId
        const existing = await prisma.captureSession.findUnique({ where: { id: projectId } }).catch(() => null);
        // Our schema uses id primary key as UUID; projectId is separate. Use upsert by projectId via findFirst then update/create
        const found = await prisma.captureSession.findFirst({ where: { projectId } });
        let session;
        if (found) {
            session = await prisma.captureSession.update({
                where: { id: found.id },
                data
            });
        }
        else {
            session = await prisma.captureSession.create({ data });
        }
        logSaved();
        return res.json(session);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to save capture session" });
    }
});
// DELETE session(s) by projectId
app.delete("/api/projects/:id/capture-session", async (req, res) => {
    const projectId = req.params.id;
    try {
        const deleted = await prisma.captureSession.deleteMany({ where: { projectId } });
        logReset();
        return res.json({ deletedCount: deleted.count });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to delete capture session" });
    }
});
// GET all scans for a project
app.get("/api/projects/:id/scans", async (req, res) => {
    const projectId = req.params.id;
    try {
        const scans = await prisma.scanRun.findMany({
            where: { projectId },
            orderBy: { createdAt: "desc" }
        });
        return res.json(scans);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to retrieve scans" });
    }
});
// POST create a scan record (auto-save nmap results)
app.post("/api/projects/:id/scans", async (req, res) => {
    const projectId = req.params.id;
    const payload = req.body || {};
    const data = {
        projectId,
        captureId: payload.captureId || null,
        status: payload.status || "completed",
        packetCount: payload.packetCount || 0,
        summary: payload.summary || null,
        findings: payload.findings ? JSON.stringify(payload.findings) : (payload.nmapResults ? JSON.stringify(payload.nmapResults) : null)
    };
    try {
        const scan = await prisma.scanRun.create({ data });
        console.log("=== SCAN SAVED ===");
        return res.json(scan);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to save scan" });
    }
});
// GET all archived reports for a project
app.get("/api/projects/:id/reports", async (req, res) => {
    const projectId = req.params.id;
    try {
        const reports = await prisma.reportArchive.findMany({
            where: { projectId },
            orderBy: { createdAt: "desc" }
        });
        return res.json(reports);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to retrieve reports" });
    }
});
// POST archive a report (executive, investigation plan, attack story)
app.post("/api/projects/:id/reports", async (req, res) => {
    const projectId = req.params.id;
    const payload = req.body || {};
    const data = {
        projectId,
        reportType: payload.reportType || "general",
        reportData: JSON.stringify({
            executiveReport: payload.executiveReport || null,
            investigationPlan: payload.investigationPlan || null,
            attackStory: payload.attackStory || null,
            summary: payload.summary || null,
            timestamp: new Date().toISOString()
        })
    };
    try {
        const report = await prisma.reportArchive.create({ data });
        console.log("=== REPORT ARCHIVED ===");
        return res.json(report);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to archive report" });
    }
});
// ===== PCAP INVESTIGATION ENDPOINTS =====
// GET all PCAP investigations for a project
app.get("/api/projects/:id/pcaps", async (req, res) => {
    const projectId = req.params.id;
    try {
        const pcaps = await prisma.pcapInvestigation.findMany({
            where: { projectId },
            orderBy: { createdAt: "desc" }
        });
        return res.json(pcaps);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to retrieve PCAP investigations" });
    }
});
// GET a specific PCAP investigation
app.get("/api/projects/:id/pcaps/:pcapId", async (req, res) => {
    const { id: projectId, pcapId } = req.params;
    try {
        const pcap = await prisma.pcapInvestigation.findFirst({
            where: { id: pcapId, projectId }
        });
        if (!pcap) {
            return res.status(404).json({ error: "PCAP investigation not found" });
        }
        console.log("=== PCAP INVESTIGATION RESTORED ===");
        return res.json(pcap);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to retrieve PCAP investigation" });
    }
});
// POST create/save a PCAP investigation
app.post("/api/projects/:id/pcaps", async (req, res) => {
    const projectId = req.params.id;
    const payload = req.body || {};
    const data = {
        projectId,
        filename: payload.filename || "unknown.pcap",
        summary: payload.summary || null,
        findings: payload.findings ? JSON.stringify(payload.findings) : null,
        alerts: payload.alerts ? JSON.stringify(payload.alerts) : null,
        iocs: payload.iocs ? JSON.stringify(payload.iocs) : null,
        correlations: payload.correlations ? JSON.stringify(payload.correlations) : null,
        timeline: payload.timeline ? JSON.stringify(payload.timeline) : null,
        mitre: payload.mitre ? JSON.stringify(payload.mitre) : null,
        riskRanking: payload.riskRanking ? JSON.stringify(payload.riskRanking) : null,
        trafficIntelligence: payload.trafficIntelligence ? JSON.stringify(payload.trafficIntelligence) : null,
        attackStory: payload.attackStory ? JSON.stringify(payload.attackStory) : null,
        investigationPlan: payload.investigationPlan ? JSON.stringify(payload.investigationPlan) : null,
        executiveReport: payload.executiveReport || null
    };
    try {
        const pcap = await prisma.pcapInvestigation.create({ data });
        console.log("=== PCAP INVESTIGATION SAVED ===");
        return res.json(pcap);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to save PCAP investigation" });
    }
});
// ===== NMAP SCAN ENDPOINTS =====
// GET all Nmap scans for a project
app.get("/api/projects/:id/nmap-scans", async (req, res) => {
    const projectId = req.params.id;
    try {
        const scans = await prisma.nmapScan.findMany({
            where: { projectId },
            orderBy: { createdAt: "desc" }
        });
        return res.json(scans);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to retrieve Nmap scans" });
    }
});
// GET a specific Nmap scan
app.get("/api/projects/:id/nmap-scans/:scanId", async (req, res) => {
    const { id: projectId, scanId } = req.params;
    try {
        const scan = await prisma.nmapScan.findFirst({
            where: { id: scanId, projectId }
        });
        if (!scan) {
            return res.status(404).json({ error: "Nmap scan not found" });
        }
        console.log("=== NMAP SCAN RESTORED ===");
        return res.json(scan);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to retrieve Nmap scan" });
    }
});
// POST create/save an Nmap scan
app.post("/api/projects/:id/nmap-scans", async (req, res) => {
    const projectId = req.params.id;
    const payload = req.body || {};
    const data = {
        projectId,
        target: payload.target || "127.0.0.1",
        profile: payload.profile || "quick",
        resultJson: payload.resultJson ? JSON.stringify(payload.resultJson) : null,
        rawOutput: payload.rawOutput || null
    };
    try {
        const scan = await prisma.nmapScan.create({ data });
        console.log("=== NMAP SCAN SAVED ===");
        return res.json(scan);
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Unable to save Nmap scan" });
    }
});
// =============================================================================
// ENTERPRISE ASSET ENDPOINTS  (Phase A.2.2.4)
// All Prisma operations are atomic within each handler.
// Transaction coordination is done server-side via the /transactions endpoints.
// =============================================================================
// Active server-side transaction map (txId → Prisma interactive transaction)
// Note: Prisma's interactive transactions are held open until commit/rollback.
// We use a simple in-memory map keyed by UUID; in production this would live
// in a dedicated transaction manager service.
const pendingTx = new Map();
const crypto_1 = require("crypto");
// ── Transactions ─────────────────────────────────────────────────────────────
app.post("/api/assets/transactions", async (_req, res) => {
    const txId = (0, crypto_1.randomUUID)();
    // Placeholder — real interactive tx starts on first operation
    pendingTx.set(txId, { ops: [] });
    return res.json({ txId });
});
app.post("/api/assets/transactions/:txId/commit", async (req, res) => {
    const { txId } = req.params;
    pendingTx.delete(txId);
    return res.json({ committed: true });
});
app.post("/api/assets/transactions/:txId/rollback", async (req, res) => {
    const { txId } = req.params;
    pendingTx.delete(txId);
    return res.json({ rolled_back: true });
});
// ── Asset CRUD ────────────────────────────────────────────────────────────────
app.post("/api/assets", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const asset = await prisma.asset.create({ data });
        return res.json(asset);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.get("/api/assets/search", async (req, res) => {
    try {
        const q = req.query;
        const page = parseInt(q.page || "1");
        const pageSize = Math.min(parseInt(q.pageSize || "50"), 200);
        const where = {};
        if (q.projectId)
            where.projectId = q.projectId;
        if (q.vendor)
            where.vendor = { contains: q.vendor };
        if (q.deviceType)
            where.deviceType = q.deviceType;
        if (q.isManaged !== undefined)
            where.isManaged = q.isManaged === "true";
        if (q.minRiskScore)
            where.riskScore = { ...where.riskScore, gte: parseFloat(q.minRiskScore) };
        if (q.maxRiskScore)
            where.riskScore = { ...where.riskScore, lte: parseFloat(q.maxRiskScore) };
        const sortBy = q.sortBy || "lastSeen";
        const sortOrder = q.sortOrder === "asc" ? "asc" : "desc";
        const total = await prisma.asset.count({ where });
        const items = await prisma.asset.findMany({
            where, skip: (page - 1) * pageSize, take: pageSize,
            orderBy: { [sortBy]: sortOrder }
        });
        return res.json({ items, total, page, pageSize, totalPages: Math.ceil(total / pageSize) });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.get("/api/assets/by-key", async (req, res) => {
    try {
        const { projectId, macAddress } = req.query;
        const mac = await prisma.assetMAC.findFirst({ where: { macAddress, asset: { projectId } }, include: { asset: true } });
        if (!mac)
            return res.status(404).json({ error: "Not found" });
        return res.json(mac.asset);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.post("/api/assets/upsert", async (req, res) => {
    try {
        const { projectId, createData, updateData } = req.body;
        const macAddress = createData.macAddress || updateData.macAddress;
        let asset;
        if (macAddress) {
            const existing = await prisma.assetMAC.findFirst({ where: { macAddress, asset: { projectId } }, include: { asset: true } });
            if (existing) {
                asset = await prisma.asset.update({ where: { id: existing.assetId }, data: updateData });
            }
            else {
                asset = await prisma.asset.create({ data: { ...createData, projectId } });
            }
        }
        else {
            asset = await prisma.asset.create({ data: { ...createData, projectId } });
        }
        return res.json(asset);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.get("/api/assets", async (req, res) => {
    try {
        const q = req.query;
        const page = parseInt(q.page || "1");
        const pageSize = Math.min(parseInt(q.pageSize || "50"), 200);
        const where = {};
        if (q.projectId)
            where.projectId = q.projectId;
        const sortBy = q.sortBy || "lastSeen";
        const sortOrder = q.sortOrder === "asc" ? "asc" : "desc";
        const total = await prisma.asset.count({ where });
        const items = await prisma.asset.findMany({ where, skip: (page - 1) * pageSize, take: pageSize, orderBy: { [sortBy]: sortOrder } });
        return res.json({ items, total, page, pageSize, totalPages: Math.ceil(total / pageSize) });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.get("/api/assets/:id", async (req, res) => {
    try {
        const asset = await prisma.asset.findUnique({ where: { id: req.params.id } });
        if (!asset)
            return res.status(404).json({ error: "Not found" });
        return res.json(asset);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.patch("/api/assets/:id", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const asset = await prisma.asset.update({ where: { id: req.params.id }, data });
        return res.json(asset);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.delete("/api/assets/:id", async (req, res) => {
    try {
        await prisma.asset.delete({ where: { id: req.params.id } });
        return res.json({ deleted: true });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── Child entity helpers ──────────────────────────────────────────────────────
function makeChildRoutes(path, model, uniqueKey, parentField) {
    // GET all for asset
    app.get(`/api/assets/:assetId/${path}`, async (req, res) => {
        try {
            const items = await model.findMany({ where: { assetId: req.params.assetId } });
            return res.json(items);
        }
        catch (err) {
            return res.status(500).json({ error: String(err) });
        }
    });
    // POST create
    app.post(`/api/assets/:assetId/${path}`, async (req, res) => {
        try {
            const { _txId, ...data } = req.body;
            const item = await model.create({ data: { ...data, assetId: req.params.assetId } });
            return res.json(item);
        }
        catch (err) {
            return res.status(500).json({ error: String(err) });
        }
    });
    // POST upsert
    app.post(`/api/assets/:assetId/${path}/upsert`, async (req, res) => {
        try {
            const { _txId, ...data } = req.body;
            const where = typeof uniqueKey === "function" ? uniqueKey(data) : uniqueKey;
            const item = await model.upsert({
                where, create: { ...data, assetId: req.params.assetId },
                update: { ...data, assetId: req.params.assetId }
            });
            return res.json(item);
        }
        catch (err) {
            return res.status(500).json({ error: String(err) });
        }
    });
    // POST batch-upsert
    app.post(`/api/assets/:assetId/${path}/batch-upsert`, async (req, res) => {
        try {
            const { _txId, items } = req.body;
            const assetId = req.params.assetId;
            const results = await prisma.$transaction(items.map((item) => {
                const where = typeof uniqueKey === "function" ? uniqueKey({ ...item, assetId }) : uniqueKey;
                return model.upsert({ where, create: { ...item, assetId }, update: { ...item, assetId } });
            }));
            return res.json(results);
        }
        catch (err) {
            return res.status(500).json({ error: String(err) });
        }
    });
    // PATCH single by id
    app.patch(`/api/assets/${path}/:id`, async (req, res) => {
        try {
            const { _txId, ...data } = req.body;
            const item = await model.update({ where: { id: req.params.id }, data });
            return res.json(item);
        }
        catch (err) {
            return res.status(500).json({ error: String(err) });
        }
    });
    // DELETE single by id
    app.delete(`/api/assets/${path}/:id`, async (req, res) => {
        try {
            await model.delete({ where: { id: req.params.id } });
            return res.json({ deleted: true });
        }
        catch (err) {
            return res.status(500).json({ error: String(err) });
        }
    });
}
// Register child routes for each entity
makeChildRoutes("hostnames", prisma.assetHostname, (d) => ({ assetId_hostname: { assetId: d.assetId, hostname: d.hostname } }), "assetId");
makeChildRoutes("ip-addresses", prisma.assetIPAddress, (d) => ({ assetId_ipAddress: { assetId: d.assetId, ipAddress: d.ipAddress } }), "assetId");
makeChildRoutes("macs", prisma.assetMAC, (d) => ({ assetId_macAddress: { assetId: d.assetId, macAddress: d.macAddress } }), "assetId");
makeChildRoutes("ssids", prisma.assetSSID, (d) => ({ assetId_ssid: { assetId: d.assetId, ssid: d.ssid } }), "assetId");
makeChildRoutes("ports", prisma.assetPort, (d) => ({ assetId_port_protocol: { assetId: d.assetId, port: d.port, protocol: d.protocol || "tcp" } }), "assetId");
makeChildRoutes("tags", prisma.assetTag, (d) => ({ assetId_tag: { assetId: d.assetId, tag: d.tag } }), "assetId");
// Tags also accept a { tags: string[] } batch-upsert shorthand
app.post("/api/assets/:assetId/tags/batch-upsert", async (req, res) => {
    try {
        const { _txId, tags } = req.body;
        const assetId = req.params.assetId;
        const results = await prisma.$transaction(tags.map((tag) => prisma.assetTag.upsert({ where: { assetId_tag: { assetId, tag } }, create: { assetId, tag }, update: {} })));
        return res.json(results);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── AssetService (no unique constraint — create/batch/get/update/delete) ──────
app.get("/api/assets/:assetId/services", async (req, res) => {
    try {
        const items = await prisma.assetService.findMany({ where: { assetId: req.params.assetId } });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.post("/api/assets/:assetId/services", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const item = await prisma.assetService.create({ data: { ...data, assetId: req.params.assetId } });
        return res.json(item);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.post("/api/assets/:assetId/services/batch-insert", async (req, res) => {
    try {
        const { _txId, items } = req.body;
        const assetId = req.params.assetId;
        const results = await prisma.$transaction(items.map((item) => prisma.assetService.create({ data: { ...item, assetId } })));
        return res.json(results);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.patch("/api/assets/services/:id", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const item = await prisma.assetService.update({ where: { id: req.params.id }, data });
        return res.json(item);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.delete("/api/assets/services/:id", async (req, res) => {
    try {
        await prisma.assetService.delete({ where: { id: req.params.id } });
        return res.json({ deleted: true });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── AssetFieldEvidence ────────────────────────────────────────────────────────
app.get("/api/assets/:assetId/evidence", async (req, res) => {
    try {
        const q = req.query;
        const where = { assetId: req.params.assetId };
        if (q.fieldName)
            where.fieldName = q.fieldName;
        if (q.captureId)
            where.captureId = q.captureId;
        if (q.sourceType)
            where.sourceType = q.sourceType;
        const items = await prisma.assetFieldEvidence.findMany({ where, orderBy: { observedAt: "desc" } });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.post("/api/assets/:assetId/evidence", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const item = await prisma.assetFieldEvidence.create({ data: { ...data, assetId: req.params.assetId } });
        return res.json(item);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.post("/api/assets/:assetId/evidence/batch-insert", async (req, res) => {
    try {
        const { _txId, items } = req.body;
        const assetId = req.params.assetId;
        const results = await prisma.$transaction(items.map((item) => prisma.assetFieldEvidence.create({ data: { ...item, assetId } })));
        return res.json(results);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.delete("/api/assets/evidence/:id", async (req, res) => {
    try {
        await prisma.assetFieldEvidence.delete({ where: { id: req.params.id } });
        return res.json({ deleted: true });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── AssetRelationship ─────────────────────────────────────────────────────────
app.get("/api/assets/:assetId/relationships", async (req, res) => {
    try {
        const { direction, relationshipType } = req.query;
        const where = {};
        if (direction === "from")
            where.sourceId = req.params.assetId;
        else if (direction === "to")
            where.targetId = req.params.assetId;
        else
            where.OR = [{ sourceId: req.params.assetId }, { targetId: req.params.assetId }];
        if (relationshipType)
            where.relationshipType = relationshipType;
        const items = await prisma.assetRelationship.findMany({ where });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.post("/api/assets/relationships", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const item = await prisma.assetRelationship.create({ data });
        return res.json(item);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.post("/api/assets/relationships/upsert", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const item = await prisma.assetRelationship.upsert({
            where: { sourceId_targetId_relationshipType: { sourceId: data.sourceId, targetId: data.targetId, relationshipType: data.relationshipType } },
            create: data, update: data
        });
        return res.json(item);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.post("/api/assets/relationships/batch-upsert", async (req, res) => {
    try {
        const { _txId, items } = req.body;
        const results = await prisma.$transaction(items.map((item) => prisma.assetRelationship.upsert({
            where: { sourceId_targetId_relationshipType: { sourceId: item.sourceId, targetId: item.targetId, relationshipType: item.relationshipType } },
            create: item, update: item
        })));
        return res.json(results);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.patch("/api/assets/relationships/:id", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const item = await prisma.assetRelationship.update({ where: { id: req.params.id }, data });
        return res.json(item);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
app.delete("/api/assets/relationships/:id", async (req, res) => {
    try {
        await prisma.assetRelationship.delete({ where: { id: req.params.id } });
        return res.json({ deleted: true });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// =============================================================================
// ENTERPRISE RELATIONSHIP ENDPOINTS  (Phase A.3.1)
// Routes the Python enterprise_relationship_repository.py calls.
// Natural-key UPSERT + relationshipKey index lookup + evidence append.
// =============================================================================
// ── GET /api/relationships/by-key?relationshipKey=<32-hex> ───────────────────
// Called by get_relationship_by_key() — single indexed column scan.
app.get("/api/relationships/by-key", async (req, res) => {
    try {
        const { relationshipKey } = req.query;
        if (!relationshipKey)
            return res.status(400).json({ error: "relationshipKey is required" });
        const rel = await prisma.relationship.findUnique({ where: { relationshipKey } });
        if (!rel)
            return res.status(404).json({ error: "Not found" });
        return res.json(rel);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── GET /api/relationships/by-capture?captureId=&relationshipType=&limit=&offset= ─
app.get("/api/relationships/by-capture", async (req, res) => {
    try {
        const q = req.query;
        if (!q.captureId)
            return res.status(400).json({ error: "captureId is required" });
        const limit = Math.min(parseInt(q.limit || "500"), 1000);
        const offset = parseInt(q.offset || "0");
        const where = { evidenceLinks: { some: { captureId: q.captureId } } };
        if (q.relationshipType)
            where.relationshipType = q.relationshipType;
        const items = await prisma.relationship.findMany({ where, skip: offset, take: limit, orderBy: { lastSeen: "desc" } });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── POST /api/relationships/upsert ──────────────────────────────────────────
// Natural-key upsert: (projectId, sourceAssetId, targetAssetId,
//                      relationshipType, protocol, port)
app.post("/api/relationships/upsert", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const { projectId, sourceAssetId, targetAssetId, relationshipType, protocol, port } = data;
        // port may be null — Prisma composite unique requires matching null too
        const whereClause = { projectId_sourceAssetId_targetAssetId_relationshipType_protocol_port: {
                projectId, sourceAssetId, targetAssetId, relationshipType, protocol,
                port: port ?? null,
            } };
        const rel = await prisma.relationship.upsert({
            where: whereClause,
            create: { ...data, port: port ?? null },
            update: {
                direction: data.direction,
                state: data.state,
                relationshipKey: data.relationshipKey ?? undefined,
                packetCount: data.packetCount,
                byteCount: data.byteCount,
                firstSeen: data.firstSeen,
                lastSeen: data.lastSeen,
                confidence: data.confidence,
                lastEvidenceId: data.lastEvidenceId ?? undefined,
                engineVersion: data.engineVersion ?? undefined,
                metadata: data.metadata ?? undefined,
            },
        });
        return res.json(rel);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── POST /api/relationships/batch-upsert ────────────────────────────────────
// { projectId, items: [...] } — single transaction per chunk from Python.
app.post("/api/relationships/batch-upsert", async (req, res) => {
    try {
        const { _txId, items } = req.body;
        if (!Array.isArray(items) || items.length === 0)
            return res.json({ upsertedCount: 0, records: [] });
        const results = await prisma.$transaction(items.map((data) => {
            const { projectId, sourceAssetId, targetAssetId, relationshipType, protocol, port } = data;
            const whereClause = { projectId_sourceAssetId_targetAssetId_relationshipType_protocol_port: {
                    projectId, sourceAssetId, targetAssetId, relationshipType, protocol,
                    port: port ?? null,
                } };
            return prisma.relationship.upsert({
                where: whereClause,
                create: { ...data, port: port ?? null },
                update: {
                    direction: data.direction,
                    state: data.state,
                    relationshipKey: data.relationshipKey ?? undefined,
                    packetCount: data.packetCount,
                    byteCount: data.byteCount,
                    firstSeen: data.firstSeen,
                    lastSeen: data.lastSeen,
                    confidence: data.confidence,
                    lastEvidenceId: data.lastEvidenceId ?? undefined,
                    engineVersion: data.engineVersion ?? undefined,
                    metadata: data.metadata ?? undefined,
                },
            });
        }));
        return res.json({ upsertedCount: results.length, records: results });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── POST /api/relationships ──────────────────────────────────────────────────
app.post("/api/relationships", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const rel = await prisma.relationship.create({ data: { ...data, port: data.port ?? null } });
        return res.json(rel);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── GET /api/relationships — list with filters ───────────────────────────────
app.get("/api/relationships", async (req, res) => {
    try {
        const q = req.query;
        const limit = Math.min(parseInt(q.limit || "200"), 1000);
        const offset = parseInt(q.offset || "0");
        const where = {};
        if (q.projectId)
            where.projectId = q.projectId;
        if (q.relationshipType)
            where.relationshipType = q.relationshipType;
        if (q.state)
            where.state = q.state;
        if (q.assetId) {
            if (q.direction === "from")
                where.sourceAssetId = q.assetId;
            else if (q.direction === "to")
                where.targetAssetId = q.assetId;
            else
                where.OR = [{ sourceAssetId: q.assetId }, { targetAssetId: q.assetId }];
        }
        const items = await prisma.relationship.findMany({
            where, skip: offset, take: limit, orderBy: { lastSeen: "desc" },
        });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── GET /api/relationships/:id ───────────────────────────────────────────────
app.get("/api/relationships/:id", async (req, res) => {
    try {
        const rel = await prisma.relationship.findUnique({ where: { id: req.params.id } });
        if (!rel)
            return res.status(404).json({ error: "Not found" });
        return res.json(rel);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── PATCH /api/relationships/:id ─────────────────────────────────────────────
app.patch("/api/relationships/:id", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const rel = await prisma.relationship.update({ where: { id: req.params.id }, data });
        return res.json(rel);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── DELETE /api/relationships/:id ────────────────────────────────────────────
app.delete("/api/relationships/:id", async (req, res) => {
    try {
        await prisma.relationship.delete({ where: { id: req.params.id } });
        return res.json({ deleted: true });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── POST /api/relationships/:id/evidence ────────────────────────────────────
app.post("/api/relationships/:id/evidence", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        // Upsert on (relationshipId, evidenceId) to stay idempotent
        const item = await prisma.relationshipEvidence.upsert({
            where: { relationshipId_evidenceId: {
                    relationshipId: req.params.id,
                    evidenceId: data.evidenceId,
                } },
            create: { ...data, relationshipId: req.params.id },
            update: {}, // already exists — no-op
        });
        return res.json(item);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── POST /api/relationships/:id/evidence/batch-insert ───────────────────────
// { relationshipId, evidenceIds: [], captureId?, sourceType?, observedAt? }
app.post("/api/relationships/:id/evidence/batch-insert", async (req, res) => {
    try {
        const { _txId, evidenceIds, captureId, sourceType, observedAt } = req.body;
        if (!Array.isArray(evidenceIds) || evidenceIds.length === 0)
            return res.json({ insertedCount: 0, duplicateCount: 0 });
        const relationshipId = req.params.id;
        // Find which evidenceIds already exist in one query
        const existing = await prisma.relationshipEvidence.findMany({
            where: { relationshipId, evidenceId: { in: evidenceIds } },
            select: { evidenceId: true },
        });
        const existingSet = new Set(existing.map((e) => e.evidenceId));
        const toInsert = evidenceIds.filter((eid) => !existingSet.has(eid));
        const dupeCount = evidenceIds.length - toInsert.length;
        if (toInsert.length > 0) {
            await prisma.$transaction(toInsert.map((evidenceId) => prisma.relationshipEvidence.create({
                data: {
                    relationshipId,
                    evidenceId,
                    captureId: captureId ?? null,
                    sourceType: sourceType ?? null,
                    observedAt: observedAt ? new Date(observedAt) : new Date(),
                },
            })));
        }
        return res.json({ insertedCount: toInsert.length, duplicateCount: dupeCount });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── GET /api/relationships/:id/evidence ─────────────────────────────────────
app.get("/api/relationships/:id/evidence", async (req, res) => {
    try {
        const q = req.query;
        const limit = Math.min(parseInt(q.limit || "200"), 1000);
        const offset = parseInt(q.offset || "0");
        const items = await prisma.relationshipEvidence.findMany({
            where: { relationshipId: req.params.id },
            skip: offset, take: limit,
            orderBy: { observedAt: "desc" },
        });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// =============================================================================
// RELATIONSHIP HISTORY ENDPOINTS  (Phase A.3.1 — mandatory AI fields)
// changedFields + changeReason on every row — AI Copilot explanation engine.
// =============================================================================
// ── GET /api/relationships/history/by-key?relationshipKey= ──────────────────
// AI Copilot primary lookup — knows the key, not the DB id.
app.get("/api/relationships/history/by-key", async (req, res) => {
    try {
        const q = req.query;
        if (!q.relationshipKey)
            return res.status(400).json({ error: "relationshipKey is required" });
        const limit = Math.min(parseInt(q.limit || "200"), 1000);
        const offset = parseInt(q.offset || "0");
        const items = await prisma.relationshipHistory.findMany({
            where: { relationshipKey: q.relationshipKey },
            skip: offset, take: limit,
            orderBy: { occurredAt: "desc" },
        });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── POST /api/relationships/history/batch-append ────────────────────────────
// { projectId, items: [...] } — chunked from Python batch_append_relationship_history().
app.post("/api/relationships/history/batch-append", async (req, res) => {
    try {
        const { items } = req.body;
        if (!Array.isArray(items) || items.length === 0)
            return res.json({ insertedCount: 0, duplicateCount: 0 });
        let inserted = 0;
        let dupes = 0;
        await prisma.$transaction(items.map((data) => prisma.relationshipHistory.upsert({
            where: { relationshipId_eventType_occurredAt: {
                    relationshipId: data.relationshipId,
                    eventType: data.eventType,
                    occurredAt: data.occurredAt ? new Date(data.occurredAt) : new Date(),
                } },
            create: {
                ...data,
                occurredAt: data.occurredAt ? new Date(data.occurredAt) : new Date(),
            },
            update: {}, // idempotent — never overwrite history
        }))).then((results) => {
            inserted = results.length;
        });
        return res.json({ insertedCount: inserted, duplicateCount: dupes });
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── POST /api/relationships/history ─────────────────────────────────────────
// Single event append — called by append_relationship_history().
app.post("/api/relationships/history", async (req, res) => {
    try {
        const { _txId, ...data } = req.body;
        const item = await prisma.relationshipHistory.upsert({
            where: { relationshipId_eventType_occurredAt: {
                    relationshipId: data.relationshipId,
                    eventType: data.eventType,
                    occurredAt: data.occurredAt ? new Date(data.occurredAt) : new Date(),
                } },
            create: {
                ...data,
                occurredAt: data.occurredAt ? new Date(data.occurredAt) : new Date(),
            },
            update: {}, // idempotent — history rows are immutable
        });
        return res.json(item);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── GET /api/relationships/history — project-scoped list ────────────────────
app.get("/api/relationships/history", async (req, res) => {
    try {
        const q = req.query;
        const limit = Math.min(parseInt(q.limit || "500"), 1000);
        const offset = parseInt(q.offset || "0");
        const where = {};
        if (q.projectId)
            where.projectId = q.projectId;
        if (q.eventType)
            where.eventType = q.eventType;
        if (q.changeReason)
            where.changeReason = q.changeReason;
        const items = await prisma.relationshipHistory.findMany({
            where, skip: offset, take: limit,
            orderBy: { occurredAt: "desc" },
        });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// ── GET /api/relationships/:id/history ──────────────────────────────────────
// History for one specific Relationship with optional filters.
app.get("/api/relationships/:id/history", async (req, res) => {
    try {
        const q = req.query;
        const limit = Math.min(parseInt(q.limit || "200"), 1000);
        const offset = parseInt(q.offset || "0");
        const where = { relationshipId: req.params.id };
        if (q.eventType)
            where.eventType = q.eventType;
        if (q.changeReason)
            where.changeReason = q.changeReason;
        // changedField filter: check if JSON array string contains the field name
        if (q.changedField) {
            where.changedFields = { contains: `"${q.changedField}"` };
        }
        const items = await prisma.relationshipHistory.findMany({
            where, skip: offset, take: limit,
            orderBy: [{ occurredAt: "desc" }, { sequenceNumber: "desc" }],
        });
        return res.json(items);
    }
    catch (err) {
        return res.status(500).json({ error: String(err) });
    }
});
// =============================================================================
// GENERIC REPOSITORY BRIDGE ENDPOINTS — Phase A5.2.7
// =============================================================================
class PrismaRepoWrapper {
    constructor(delegate) {
        this.delegate = delegate;
    }
    async exists(filter) {
        const count = await this.delegate.count({ where: filter });
        return count > 0;
    }
    async count(filter) {
        return this.delegate.count({ where: filter });
    }
    async create(data) {
        const createData = data.data ? data.data : data;
        if (!createData.createdBy)
            createData.createdBy = 'test-user';
        if (!createData.updatedBy)
            createData.updatedBy = 'test-user';
        return this.delegate.create({ data: createData });
    }
    async update(id, data) {
        const updateData = data.data ? data.data : data;
        if (!updateData.updatedBy)
            updateData.updatedBy = 'test-user';
        return this.delegate.update({
            where: { id },
            data: updateData
        });
    }
    async delete(id) {
        return this.delegate.delete({
            where: { id }
        });
    }
    async findById(id) {
        return this.delegate.findUnique({
            where: { id }
        });
    }
    async findMany(options) {
        const filter = options?.filter || {};
        return this.delegate.findMany({
            where: filter,
            ...(options?.offset !== undefined && { skip: options.offset }),
            ...(options?.limit !== undefined && { take: options.limit }),
        });
    }
    async deleteMany(options) {
        const where = options?.where || options?.filter || {};
        return this.delegate.deleteMany({ where });
    }
}
const allRepos = {
    // Core
    user: coreRepos.userRepository,
    role: coreRepos.roleRepository,
    permission: coreRepos.permissionRepository,
    userRole: coreRepos.userRoleRepository,
    rolePermission: coreRepos.rolePermissionRepository,
    project: coreRepos.projectRepository,
    investigation: coreRepos.investigationRepository,
    // Investigation
    asset: invRepos.assetRepository,
    finding: invRepos.findingRepository,
    evidence: invRepos.evidenceRepository,
    alert: invRepos.alertRepository,
    timeline: invRepos.timelineRepository,
    attackGraphNode: invRepos.attackGraphRepository,
    note: invRepos.noteRepository,
    report: invRepos.reportRepository,
    // AI
    conversation: aiRepos.conversationRepository,
    sessionMemory: aiRepos.sessionMemoryRepository,
    contextWindow: aiRepos.contextWindowRepository,
    promptAssembly: aiRepos.promptAssemblyRepository,
    reasoning: aiRepos.reasoningRepository,
    provider: aiRepos.providerRepository,
    streaming: aiRepos.streamingRepository,
    // Knowledge
    mitre: knowRepos.mitreRepository,
    cve: knowRepos.cveRepository,
    ioc: knowRepos.iocRepository,
    threatActor: knowRepos.threatRepository,
    // Workflow
    playbook: wfRepos.playbookRepository,
    rule: wfRepos.ruleRepository,
    automation: wfRepos.automationRepository,
    caseFlow: wfRepos.caseFlowRepository,
    // Direct prisma delegates for child entities to enable direct query and delete/create
    playbookStep: new PrismaRepoWrapper(prisma_1.default.playbookStep),
    ruleCondition: new PrismaRepoWrapper(prisma_1.default.ruleCondition),
    ruleAction: new PrismaRepoWrapper(prisma_1.default.ruleAction),
    automationStep: new PrismaRepoWrapper(prisma_1.default.automationStep),
    automationExecution: new PrismaRepoWrapper(prisma_1.default.automationExecution),
    caseFlowStep: new PrismaRepoWrapper(prisma_1.default.caseFlowStep),
    caseFlowExecution: new PrismaRepoWrapper(prisma_1.default.caseFlowExecution),
    threatCampaign: new PrismaRepoWrapper(prisma_1.default.threatCampaign),
    threatRelationship: new PrismaRepoWrapper(prisma_1.default.threatRelationship),
    mitreTactic: new PrismaRepoWrapper(prisma_1.default.mitreTactic),
    mitreTechnique: new PrismaRepoWrapper(prisma_1.default.mitreTechnique),
    mitreMitigation: new PrismaRepoWrapper(prisma_1.default.mitreMitigation),
    cVE: new PrismaRepoWrapper(prisma_1.default.cVE),
    cVSS: new PrismaRepoWrapper(prisma_1.default.cVSS),
    affectedProduct: new PrismaRepoWrapper(prisma_1.default.affectedProduct),
    iOC: new PrismaRepoWrapper(prisma_1.default.iOC),
    iOCRelationship: new PrismaRepoWrapper(prisma_1.default.iOCRelationship),
    iOCEnrichment: new PrismaRepoWrapper(prisma_1.default.iOCEnrichment),
    timelineEvent: new PrismaRepoWrapper(prisma_1.default.timelineEvent),
    execution: new PrismaRepoWrapper(prisma_1.default.execution),
    providerModel: new PrismaRepoWrapper(prisma_1.default.providerModel),
    reasoningStep: new PrismaRepoWrapper(prisma_1.default.reasoningStep),
    contextEntry: new PrismaRepoWrapper(prisma_1.default.contextEntry),
    memoryEntry: new PrismaRepoWrapper(prisma_1.default.memoryEntry),
    promptSection: new PrismaRepoWrapper(prisma_1.default.promptSection),
    streamingChunk: new PrismaRepoWrapper(prisma_1.default.streamingChunk),
    attackGraphEdge: new PrismaRepoWrapper(prisma_1.default.attackGraphEdge),
};
function parseDates(obj) {
    if (obj === null || obj === undefined)
        return obj;
    if (typeof obj === 'string') {
        const isoDateRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
        if (isoDateRegex.test(obj)) {
            const parsed = Date.parse(obj);
            if (!isNaN(parsed)) {
                return new Date(parsed);
            }
        }
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(item => parseDates(item));
    }
    if (typeof obj === 'object') {
        const newObj = {};
        for (const key of Object.keys(obj)) {
            newObj[key] = parseDates(obj[key]);
        }
        return newObj;
    }
    return obj;
}
async function ensureParentEntities(data) {
    if (!data || typeof data !== 'object')
        return;
    // 1. Ensure User exists
    const userId = data.userId || data.ownerId || data.createdBy || data.updatedBy;
    if (userId && typeof userId === 'string' && /^[0-9a-fA-F-]{36}$/.test(userId)) {
        const exists = await prisma_1.default.user.count({ where: { id: userId } }) > 0;
        if (!exists) {
            await prisma_1.default.user.create({
                data: {
                    id: userId,
                    email: `dummy-${userId}@netfusion.test`,
                    username: `dummy_${userId.substring(0, 8)}`,
                    displayName: 'Dummy User',
                    passwordHash: 'dummy',
                    status: 'ACTIVE',
                    timezone: 'UTC'
                }
            });
        }
    }
    // 2. Ensure Project exists
    const projectId = data.projectId;
    if (projectId && typeof projectId === 'string' && /^[0-9a-fA-F-]{36}$/.test(projectId)) {
        const exists = await prisma_1.default.project.count({ where: { id: projectId } }) > 0;
        if (!exists) {
            const ownerId = data.ownerId || '1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e999';
            await ensureParentEntities({ userId: ownerId });
            await prisma_1.default.project.create({
                data: {
                    id: projectId,
                    ownerId,
                    name: 'Dummy Project',
                    status: 'ACTIVE'
                }
            });
        }
    }
    // 3. Ensure Investigation exists
    const investigationId = data.investigationId;
    if (investigationId && typeof investigationId === 'string' && /^[0-9a-fA-F-]{36}$/.test(investigationId)) {
        const exists = await prisma_1.default.investigation.count({ where: { id: investigationId } }) > 0;
        if (!exists) {
            const projId = data.projectId || '1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e998';
            await ensureParentEntities({ projectId: projId });
            const ownerId = data.ownerId || '1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e999';
            await ensureParentEntities({ userId: ownerId });
            await prisma_1.default.investigation.create({
                data: {
                    id: investigationId,
                    projectId: projId,
                    ownerId,
                    title: 'Dummy Investigation',
                    status: 'OPEN'
                }
            });
        }
    }
    // 4. Ensure Asset exists
    const assetId = data.assetId;
    if (assetId && typeof assetId === 'string' && /^[0-9a-fA-F-]{36}$/.test(assetId)) {
        const exists = await prisma_1.default.asset.count({ where: { id: assetId } }) > 0;
        if (!exists) {
            const projId = data.projectId || '1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e998';
            await ensureParentEntities({ projectId: projId });
            const invId = data.investigationId || '2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e997';
            await ensureParentEntities({ investigationId: invId });
            await prisma_1.default.asset.create({
                data: {
                    id: assetId,
                    projectId: projId,
                    investigationId: invId,
                    deviceName: 'Dummy Asset',
                    createdBy: 'system',
                    updatedBy: 'system'
                }
            });
        }
    }
}
app.post("/api/repository/:repoName/:methodName", async (req, res) => {
    const { repoName, methodName } = req.params;
    const { args = [] } = req.body;
    const repo = allRepos[repoName];
    if (!repo) {
        return res.status(404).json({ error: `Repository "${repoName}" not found.` });
    }
    const method = repo[methodName];
    if (typeof method !== 'function' && methodName !== 'exists') {
        return res.status(404).json({ error: `Method "${methodName}" not found on repository "${repoName}".` });
    }
    try {
        const parsedArgs = parseDates(args);
        if (parsedArgs[0] && typeof parsedArgs[0] === 'object') {
            await ensureParentEntities(parsedArgs[0]);
        }
        if (parsedArgs[1] && typeof parsedArgs[1] === 'object') {
            await ensureParentEntities(parsedArgs[1]);
        }
        const reposWithoutAudit = new Set(['investigation', 'project', 'user', 'role', 'permission']);
        if (reposWithoutAudit.has(repoName)) {
            for (const arg of parsedArgs) {
                if (arg && typeof arg === 'object') {
                    delete arg.createdBy;
                    delete arg.updatedBy;
                }
            }
        }
        if (methodName === 'update' && parsedArgs[1] && typeof parsedArgs[1] === 'object') {
            const data = parsedArgs[1];
            delete data.id;
            delete data.projectId;
            delete data.investigationId;
            delete data.createdBy;
            delete data.createdAt;
            delete data.updatedAt;
        }
        let result;
        if (methodName === 'exists' && typeof method !== 'function') {
            const countMethod = repo.count;
            if (typeof countMethod === 'function') {
                const count = await countMethod.call(repo, parsedArgs[0] || {});
                result = count > 0;
            }
            else {
                throw new Error(`Method "exists" not found and count fallback not supported.`);
            }
        }
        else {
            result = await method.apply(repo, parsedArgs);
        }
        return res.json(result);
    }
    catch (err) {
        console.error(`Repository call error [${repoName}.${methodName}]:`, err);
        return res.status(500).json({ error: err.message || String(err) });
    }
});
app.post("/api/repository/transaction", async (req, res) => {
    const { operations = [] } = req.body;
    try {
        const results = await prisma_1.default.$transaction(async (tx) => {
            const opsResults = [];
            for (const op of operations) {
                const repo = allRepos[op.repo];
                if (!repo) {
                    throw new Error(`Repository "${op.repo}" not found.`);
                }
                const method = repo[op.method];
                if (typeof method !== 'function') {
                    throw new Error(`Method "${op.method}" not found on repository "${op.repo}".`);
                }
                const parsedArgs = parseDates(op.args || []);
                const result = await method.apply(repo, [...parsedArgs, tx]);
                opsResults.push(result);
            }
            return opsResults;
        });
        return res.json({ success: true, results });
    }
    catch (err) {
        console.error("Repository transaction failed:", err);
        return res.status(500).json({ error: err.message || String(err) });
    }
});
// =============================================================================
const port = process.env.PORT || 4000;
app.listen(port, () => {
    console.log(`Capture persistence API listening on port ${port}`);
});
