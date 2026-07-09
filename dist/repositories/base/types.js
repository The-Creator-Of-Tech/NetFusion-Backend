"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RepositoryError = void 0;
/**
 * Custom Error class representing errors thrown inside the repository layer.
 */
class RepositoryError extends Error {
    constructor(message, code, originalError) {
        super(message);
        this.code = code;
        this.originalError = originalError;
        this.name = 'RepositoryError';
        Object.setPrototypeOf(this, new.target.prototype);
    }
}
exports.RepositoryError = RepositoryError;
