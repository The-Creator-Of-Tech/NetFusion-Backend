"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditLogRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class AuditLogRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('auditLog');
    }
}
exports.AuditLogRepository = AuditLogRepository;
