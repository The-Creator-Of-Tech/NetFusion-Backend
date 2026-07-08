import { eventPublisher } from './EventPublisher';

export abstract class BaseService {
  protected logInfo(message: string, ...args: any[]): void {
    console.log(`[INFO] [${this.constructor.name}] ${message}`, ...args);
  }

  protected logWarn(message: string, ...args: any[]): void {
    console.warn(`[WARN] [${this.constructor.name}] ${message}`, ...args);
  }

  protected logError(message: string, ...args: any[]): void {
    console.error(`[ERROR] [${this.constructor.name}] ${message}`, ...args);
  }

  protected getUtcNow(): Date {
    return new Date();
  }

  protected validateUuid(uuidStr: string, fieldName: string): void {
    const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
    if (!uuidRegex.test(uuidStr)) {
      throw new Error(`Validation failed: ${fieldName} with value "${uuidStr}" is not a valid UUID.`);
    }
  }

  protected validateRequired(data: Record<string, any>, fields: string[]): void {
    const missing: string[] = [];
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
