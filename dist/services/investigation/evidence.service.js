"use strict";
/**
 * EvidenceService — Phase A5.3.3
 * ================================
 * Business logic for Evidence lifecycle: integrity checks, duplicate
 * detection via hash, metadata extraction, and cross-entity association.
 */
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
exports.EvidenceService = void 0;
const crypto = __importStar(require("crypto"));
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const investigation_1 = require("../../repositories/investigation");
const timeline_service_1 = require("./timeline.service");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class EvidenceService extends BaseService_1.BaseService {
    constructor(evidenceRepo = investigation_1.evidenceRepository, timelineSvc = new timeline_service_1.TimelineService()) {
        super();
        this.evidenceRepo = evidenceRepo;
        this.timelineSvc = timelineSvc;
    }
    // ── Attach file / PCAP ────────────────────────────────────────────────────
    async attachFile(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'fieldName', 'fieldValue', 'sourceType', 'createdBy']);
        const runInTx = async (transaction) => {
            const hash = await this.calculateHash(data.fieldValue);
            const dup = await this.isDuplicate(hash, data.investigationId, transaction);
            if (dup)
                throw new Error(`Duplicate evidence: identical content hash already recorded.`);
            const evidence = await this.evidenceRepo.create({
                ...data,
                type: data.type ?? 'FILE',
                metadata: { ...(data.metadata ?? {}), hash },
            }, transaction);
            await this.timelineSvc.record({
                projectId: evidence.projectId, investigationId: evidence.investigationId,
                title: 'Evidence File Attached', description: `File evidence "${evidence.fieldName}" added.`,
                type: 'EVIDENCE_ADDED', createdBy: data.createdBy,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('EvidenceAttached', { evidence });
            return evidence;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async attachPcap(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'fieldName', 'fieldValue', 'sourceType', 'createdBy']);
        const runInTx = async (transaction) => {
            const hash = await this.calculateHash(data.fieldValue);
            const dup = await this.isDuplicate(hash, data.investigationId, transaction);
            if (dup)
                throw new Error(`Duplicate PCAP evidence: same capture already recorded.`);
            const evidence = await this.evidenceRepo.create({
                ...data, type: 'PACKET',
                metadata: { ...(data.metadata ?? {}), hash },
            }, transaction);
            await this.timelineSvc.recordCapture(evidence.projectId, evidence.investigationId, evidence.id, data.createdBy, transaction);
            await EventPublisher_1.eventPublisher.publish('EvidenceAttached', { evidence });
            return evidence;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Hash helpers ──────────────────────────────────────────────────────────
    async calculateHash(content) {
        return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    }
    async verifyHash(evidenceId, expectedHash, tx) {
        this.validateUuid(evidenceId, 'evidenceId');
        const ev = await this.evidenceRepo.findById(evidenceId, tx);
        if (!ev || ev.deletedAt)
            throw new Error(`Evidence "${evidenceId}" not found.`);
        const storedHash = ev.metadata?.hash;
        if (!storedHash)
            return false;
        return storedHash === expectedHash;
    }
    async isDuplicate(hash, investigationId, tx) {
        const results = await this.evidenceRepo.findByHash(hash, tx);
        return results.some(e => e.investigationId === investigationId && !e.deletedAt);
    }
    // ── Associations ──────────────────────────────────────────────────────────
    async associateAsset(evidenceId, assetId, actor, tx) {
        this.validateUuid(evidenceId, 'evidenceId');
        this.validateUuid(assetId, 'assetId');
        const runInTx = async (transaction) => {
            const ev = await this.evidenceRepo.findById(evidenceId, transaction);
            if (!ev || ev.deletedAt)
                throw new Error(`Evidence "${evidenceId}" not found.`);
            const updated = await this.evidenceRepo.update(evidenceId, { assetId, updatedBy: actor }, transaction);
            await this.timelineSvc.record({
                projectId: ev.projectId, investigationId: ev.investigationId,
                title: 'Evidence Linked to Asset', description: `Evidence ${evidenceId} linked to asset ${assetId}.`,
                type: 'EVIDENCE_ADDED', createdBy: actor,
            }, transaction);
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async associateFinding(evidenceId, findingId, actor, tx) {
        this.validateUuid(evidenceId, 'evidenceId');
        this.validateUuid(findingId, 'findingId');
        const runInTx = async (transaction) => {
            const ev = await this.evidenceRepo.findById(evidenceId, transaction);
            if (!ev || ev.deletedAt)
                throw new Error(`Evidence "${evidenceId}" not found.`);
            const updated = await this.evidenceRepo.update(evidenceId, { findingId, updatedBy: actor }, transaction);
            await this.timelineSvc.record({
                projectId: ev.projectId, investigationId: ev.investigationId,
                title: 'Evidence Linked to Finding', description: `Evidence ${evidenceId} linked to finding ${findingId}.`,
                type: 'EVIDENCE_ADDED', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('EvidenceAttached', { evidenceId, findingId });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read ─────────────────────────────────────────────────────────────────
    async getByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.evidenceRepo.findByInvestigation(investigationId, tx);
    }
    async getByAsset(assetId, tx) {
        this.validateUuid(assetId, 'assetId');
        return this.evidenceRepo.findByAsset(assetId, tx);
    }
}
exports.EvidenceService = EvidenceService;
