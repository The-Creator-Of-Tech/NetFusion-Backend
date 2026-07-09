"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseService = void 0;
class BaseService {
    logInfo(message, ...args) {
        console.log(`[INFO] [${this.constructor.name}] ${message}`, ...args);
    }
    logWarn(message, ...args) {
        console.warn(`[WARN] [${this.constructor.name}] ${message}`, ...args);
    }
    logError(message, ...args) {
        console.error(`[ERROR] [${this.constructor.name}] ${message}`, ...args);
    }
    getUtcNow() {
        return new Date();
    }
    validateUuid(uuidStr, fieldName) {
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        if (!uuidRegex.test(uuidStr)) {
            throw new Error(`Validation failed: ${fieldName} with value "${uuidStr}" is not a valid UUID.`);
        }
    }
    validateRequired(data, fields) {
        const missing = [];
        for (const f of fields) {
            if (data[f] === undefined || data[f] === null || data[f] === '') {
                missing.push(f);
            }
        }
        if (missing.length > 0) {
            throw new Error(`Validation failed: Missing required field(s): ${missing.join(', ')}`);
        }
    }
}
exports.BaseService = BaseService;
