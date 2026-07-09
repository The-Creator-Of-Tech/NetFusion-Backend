"use strict";
/**
 * BaseApplicationService.ts — Phase A5.4.1
 * ==========================================
 * Abstract base for every orchestrator in the Application Layer.
 *
 * Provides:
 *  - Correlation ID generation and propagation
 *  - Structured logging with context
 *  - Event publishing delegation to ApplicationEventPublisher
 *  - Retry helpers with exponential back-off
 *  - Error mapping (domain → orchestration errors)
 *  - Execution timing / performance tracking
 *  - Distributed operation context (OperationContext)
 *  - Cancellation support (AbortSignal compatible)
 *  - Workflow state tracking
 *  - Compensating transaction helpers
 *
 * Constraints:
 *  - MUST NOT import or reference any repository directly
 *  - May only call Service Layer methods
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseApplicationService = exports.OrchestrationNotFoundError = exports.OrchestrationValidationError = exports.OrchestrationError = exports.CompensatingRegistry = void 0;
exports.createOperationContext = createOperationContext;
const crypto_1 = require("crypto");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
function createOperationContext(actor, opts) {
    return {
        correlationId: (0, crypto_1.randomUUID)(),
        actor,
        startedAt: new Date(),
        ...opts,
    };
}
class CompensatingRegistry {
    constructor() {
        this.stack = [];
    }
    register(label, fn) {
        this.stack.push({ label, fn });
    }
    async rollback(logger) {
        // Execute in LIFO order
        const reversed = [...this.stack].reverse();
        for (const entry of reversed) {
            try {
                logger(`[Compensate] Rolling back: ${entry.label}`);
                await entry.fn();
            }
            catch (e) {
                logger(`[Compensate] WARNING — rollback step "${entry.label}" failed: ${e?.message ?? e}`);
            }
        }
        this.stack = [];
    }
    clear() {
        this.stack = [];
    }
}
exports.CompensatingRegistry = CompensatingRegistry;
// ─────────────────────────────────────────────────────────────────────────────
// Orchestration errors
// ─────────────────────────────────────────────────────────────────────────────
class OrchestrationError extends Error {
    constructor(message, correlationId, code, cause) {
        super(message);
        this.correlationId = correlationId;
        this.code = code;
        this.cause = cause;
        this.name = 'OrchestrationError';
    }
}
exports.OrchestrationError = OrchestrationError;
class OrchestrationValidationError extends OrchestrationError {
    constructor(message, correlationId, cause) {
        super(message, correlationId, 'VALIDATION_ERROR', cause);
        this.name = 'OrchestrationValidationError';
    }
}
exports.OrchestrationValidationError = OrchestrationValidationError;
class OrchestrationNotFoundError extends OrchestrationError {
    constructor(resource, id, correlationId) {
        super(`${resource} "${id}" not found.`, correlationId, 'NOT_FOUND');
        this.name = 'OrchestrationNotFoundError';
    }
}
exports.OrchestrationNotFoundError = OrchestrationNotFoundError;
// ─────────────────────────────────────────────────────────────────────────────
// Base class
// ─────────────────────────────────────────────────────────────────────────────
class BaseApplicationService {
    constructor(serviceName) {
        this.serviceName = serviceName ?? this.constructor.name;
    }
    // ── Correlation ID ────────────────────────────────────────────────────────
    generateCorrelationId() {
        return (0, crypto_1.randomUUID)();
    }
    // ── Logging ───────────────────────────────────────────────────────────────
    log(level, ctx, message, extra) {
        const prefix = `[${level}] [${this.serviceName}] [corr:${ctx.correlationId}]`;
        const payload = extra ? JSON.stringify(extra) : '';
        if (level === 'ERROR')
            console.error(`${prefix} ${message}`, payload);
        else if (level === 'WARN')
            console.warn(`${prefix} ${message}`, payload);
        else
            console.log(`${prefix} ${message}`, payload);
    }
    logInfo(ctx, message, extra) {
        this.log('INFO', ctx, message, extra);
    }
    logWarn(ctx, message, extra) {
        this.log('WARN', ctx, message, extra);
    }
    logError(ctx, message, extra) {
        this.log('ERROR', ctx, message, extra);
    }
    // ── Timing ────────────────────────────────────────────────────────────────
    elapsed(ctx) {
        return Date.now() - ctx.startedAt.getTime();
    }
    logTiming(ctx, operation) {
        this.logInfo(ctx, `${operation} completed in ${this.elapsed(ctx)}ms`);
    }
    // ── Cancellation ──────────────────────────────────────────────────────────
    checkCancellation(ctx) {
        if (ctx.signal?.aborted) {
            throw new OrchestrationError('Operation was cancelled.', ctx.correlationId, 'CANCELLED');
        }
    }
    // ── Validation helpers ────────────────────────────────────────────────────
    validateUuid(value, fieldName, ctx) {
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        if (!uuidRegex.test(value)) {
            throw new OrchestrationValidationError(`${fieldName} "${value}" is not a valid UUID.`, ctx.correlationId);
        }
    }
    validateRequired(data, fields, ctx) {
        const missing = fields.filter(f => data[f] === undefined || data[f] === null || data[f] === '');
        if (missing.length > 0) {
            throw new OrchestrationValidationError(`Missing required field(s): ${missing.join(', ')}`, ctx.correlationId);
        }
    }
    // ── Error mapping ─────────────────────────────────────────────────────────
    mapError(err, ctx) {
        if (err instanceof OrchestrationError)
            return err;
        if (err instanceof Error) {
            const msg = err.message.toLowerCase();
            if (msg.includes('not found')) {
                return new OrchestrationNotFoundError('Resource', '', ctx.correlationId);
            }
            if (msg.includes('validation failed') || msg.includes('missing required')) {
                return new OrchestrationValidationError(err.message, ctx.correlationId, err);
            }
            return new OrchestrationError(err.message, ctx.correlationId, 'SERVICE_ERROR', err);
        }
        return new OrchestrationError(String(err), ctx.correlationId, 'UNKNOWN_ERROR');
    }
    // ── Retry ─────────────────────────────────────────────────────────────────
    async withRetry(ctx, label, fn, opts = {}) {
        const maxAttempts = opts.maxAttempts ?? 3;
        const initialDelay = opts.initialDelayMs ?? 100;
        const factor = opts.factor ?? 2;
        const nonRetryable = opts.nonRetryable ?? ['validation failed', 'not found', 'invalid uuid'];
        let attempt = 0;
        let lastErr;
        while (attempt < maxAttempts) {
            this.checkCancellation(ctx);
            try {
                return await fn();
            }
            catch (e) {
                lastErr = e;
                const msg = (e?.message ?? '').toLowerCase();
                const isNonRetryable = nonRetryable.some(s => msg.includes(s));
                if (isNonRetryable || attempt + 1 >= maxAttempts) {
                    break;
                }
                const delay = initialDelay * Math.pow(factor, attempt);
                this.logWarn(ctx, `${label} attempt ${attempt + 1} failed, retrying in ${delay}ms`, { error: msg });
                await new Promise(r => setTimeout(r, delay));
            }
            attempt++;
        }
        throw this.mapError(lastErr, ctx);
    }
    // ── Event publishing ──────────────────────────────────────────────────────
    async publishEvent(name, ctx, payload) {
        await ApplicationEvents_1.appEventPublisher.publish(name, {
            correlationId: ctx.correlationId,
            timestamp: new Date(),
            actor: ctx.actor,
            ...payload,
        });
    }
    // ── Compensating transaction wrapper ─────────────────────────────────────
    /**
     * Runs `fn` with a fresh CompensatingRegistry.
     * On any error the registry is rolled back in LIFO order,
     * then the original error (re-wrapped as OrchestrationError) is re-thrown.
     */
    async withCompensation(ctx, fn) {
        const compensation = new CompensatingRegistry();
        try {
            return await fn(compensation);
        }
        catch (err) {
            this.logError(ctx, 'Operation failed, executing compensating actions', {
                error: err instanceof Error ? err.message : String(err),
            });
            await compensation.rollback((msg) => this.logWarn(ctx, msg));
            throw this.mapError(err, ctx);
        }
    }
    // ── Workflow state helper ─────────────────────────────────────────────────
    trackState(current, next, ctx) {
        this.logInfo(ctx, `Workflow state: ${current} → ${next}`);
        return next;
    }
}
exports.BaseApplicationService = BaseApplicationService;
