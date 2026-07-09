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

import { randomUUID } from 'crypto';
import { appEventPublisher, AppEventName } from '../events/ApplicationEvents';

// ─────────────────────────────────────────────────────────────────────────────
// Operation Context
// ─────────────────────────────────────────────────────────────────────────────

export interface OperationContext {
  correlationId: string;
  actor: string;
  projectId?: string;
  investigationId?: string;
  startedAt: Date;
  metadata?: Record<string, any>;
  /** Cancellation signal — orchestrators should check this during long loops */
  signal?: AbortSignal;
}

export function createOperationContext(
  actor: string,
  opts?: Partial<Omit<OperationContext, 'correlationId' | 'startedAt'>>,
): OperationContext {
  return {
    correlationId: randomUUID(),
    actor,
    startedAt: new Date(),
    ...opts,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Compensating action registry
// ─────────────────────────────────────────────────────────────────────────────

export type CompensatingAction = () => Promise<void>;

export class CompensatingRegistry {
  private stack: Array<{ label: string; fn: CompensatingAction }> = [];

  register(label: string, fn: CompensatingAction): void {
    this.stack.push({ label, fn });
  }

  async rollback(logger: (msg: string) => void): Promise<void> {
    // Execute in LIFO order
    const reversed = [...this.stack].reverse();
    for (const entry of reversed) {
      try {
        logger(`[Compensate] Rolling back: ${entry.label}`);
        await entry.fn();
      } catch (e: any) {
        logger(`[Compensate] WARNING — rollback step "${entry.label}" failed: ${e?.message ?? e}`);
      }
    }
    this.stack = [];
  }

  clear(): void {
    this.stack = [];
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Workflow state
// ─────────────────────────────────────────────────────────────────────────────

export type WorkflowState = 'IDLE' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'CANCELLED' | 'COMPENSATING';

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration errors
// ─────────────────────────────────────────────────────────────────────────────

export class OrchestrationError extends Error {
  constructor(
    message: string,
    public readonly correlationId: string,
    public readonly code?: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'OrchestrationError';
  }
}

export class OrchestrationValidationError extends OrchestrationError {
  constructor(message: string, correlationId: string, cause?: unknown) {
    super(message, correlationId, 'VALIDATION_ERROR', cause);
    this.name = 'OrchestrationValidationError';
  }
}

export class OrchestrationNotFoundError extends OrchestrationError {
  constructor(resource: string, id: string, correlationId: string) {
    super(`${resource} "${id}" not found.`, correlationId, 'NOT_FOUND');
    this.name = 'OrchestrationNotFoundError';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Retry helper
// ─────────────────────────────────────────────────────────────────────────────

export interface RetryOptions {
  maxAttempts?: number;
  initialDelayMs?: number;
  factor?: number;
  /** List of error substrings that should NOT be retried */
  nonRetryable?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Base class
// ─────────────────────────────────────────────────────────────────────────────

export abstract class BaseApplicationService {
  protected readonly serviceName: string;

  constructor(serviceName?: string) {
    this.serviceName = serviceName ?? this.constructor.name;
  }

  // ── Correlation ID ────────────────────────────────────────────────────────

  protected generateCorrelationId(): string {
    return randomUUID();
  }

  // ── Logging ───────────────────────────────────────────────────────────────

  protected log(level: 'INFO' | 'WARN' | 'ERROR', ctx: OperationContext, message: string, extra?: Record<string, any>): void {
    const prefix = `[${level}] [${this.serviceName}] [corr:${ctx.correlationId}]`;
    const payload = extra ? JSON.stringify(extra) : '';
    if (level === 'ERROR') console.error(`${prefix} ${message}`, payload);
    else if (level === 'WARN') console.warn(`${prefix} ${message}`, payload);
    else console.log(`${prefix} ${message}`, payload);
  }

  protected logInfo(ctx: OperationContext, message: string, extra?: Record<string, any>): void {
    this.log('INFO', ctx, message, extra);
  }

  protected logWarn(ctx: OperationContext, message: string, extra?: Record<string, any>): void {
    this.log('WARN', ctx, message, extra);
  }

  protected logError(ctx: OperationContext, message: string, extra?: Record<string, any>): void {
    this.log('ERROR', ctx, message, extra);
  }

  // ── Timing ────────────────────────────────────────────────────────────────

  protected elapsed(ctx: OperationContext): number {
    return Date.now() - ctx.startedAt.getTime();
  }

  protected logTiming(ctx: OperationContext, operation: string): void {
    this.logInfo(ctx, `${operation} completed in ${this.elapsed(ctx)}ms`);
  }

  // ── Cancellation ──────────────────────────────────────────────────────────

  protected checkCancellation(ctx: OperationContext): void {
    if (ctx.signal?.aborted) {
      throw new OrchestrationError(
        'Operation was cancelled.',
        ctx.correlationId,
        'CANCELLED',
      );
    }
  }

  // ── Validation helpers ────────────────────────────────────────────────────

  protected validateUuid(value: string, fieldName: string, ctx: OperationContext): void {
    const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
    if (!uuidRegex.test(value)) {
      throw new OrchestrationValidationError(
        `${fieldName} "${value}" is not a valid UUID.`,
        ctx.correlationId,
      );
    }
  }

  protected validateRequired(data: Record<string, any>, fields: string[], ctx: OperationContext): void {
    const missing = fields.filter(f => data[f] === undefined || data[f] === null || data[f] === '');
    if (missing.length > 0) {
      throw new OrchestrationValidationError(
        `Missing required field(s): ${missing.join(', ')}`,
        ctx.correlationId,
      );
    }
  }

  // ── Error mapping ─────────────────────────────────────────────────────────

  protected mapError(err: unknown, ctx: OperationContext): OrchestrationError {
    if (err instanceof OrchestrationError) return err;
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

  protected async withRetry<T>(
    ctx: OperationContext,
    label: string,
    fn: () => Promise<T>,
    opts: RetryOptions = {},
  ): Promise<T> {
    const maxAttempts = opts.maxAttempts ?? 3;
    const initialDelay = opts.initialDelayMs ?? 100;
    const factor = opts.factor ?? 2;
    const nonRetryable = opts.nonRetryable ?? ['validation failed', 'not found', 'invalid uuid'];

    let attempt = 0;
    let lastErr: unknown;

    while (attempt < maxAttempts) {
      this.checkCancellation(ctx);
      try {
        return await fn();
      } catch (e: any) {
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

  protected async publishEvent(
    name: AppEventName,
    ctx: OperationContext,
    payload: Record<string, any>,
  ): Promise<void> {
    await appEventPublisher.publish(name, {
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
  protected async withCompensation<T>(
    ctx: OperationContext,
    fn: (compensation: CompensatingRegistry) => Promise<T>,
  ): Promise<T> {
    const compensation = new CompensatingRegistry();
    try {
      return await fn(compensation);
    } catch (err: unknown) {
      this.logError(ctx, 'Operation failed, executing compensating actions', {
        error: err instanceof Error ? err.message : String(err),
      });
      await compensation.rollback((msg) => this.logWarn(ctx, msg));
      throw this.mapError(err, ctx);
    }
  }

  // ── Workflow state helper ─────────────────────────────────────────────────

  protected trackState(current: WorkflowState, next: WorkflowState, ctx: OperationContext): WorkflowState {
    this.logInfo(ctx, `Workflow state: ${current} → ${next}`);
    return next;
  }
}
