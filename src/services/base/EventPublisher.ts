export type EventCallback = (data: any) => void | Promise<void>;

export class EventPublisher {
  private static instance: EventPublisher;
  private listeners: Map<string, EventCallback[]> = new Map();

  private constructor() {}

  public static getInstance(): EventPublisher {
    if (!EventPublisher.instance) {
      EventPublisher.instance = new EventPublisher();
    }
    return EventPublisher.instance;
  }

  public subscribe(event: string, callback: EventCallback): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  }

  public unsubscribe(event: string, callback: EventCallback): void {
    if (!this.listeners.has(event)) return;
    const list = this.listeners.get(event)!;
    const index = list.indexOf(callback);
    if (index !== -1) {
      list.splice(index, 1);
    }
  }

  public async publish(event: string, data: any): Promise<void> {
    const list = this.listeners.get(event) || [];
    for (const callback of list) {
      try {
        await callback(data);
      } catch (err) {
        console.error(`Error in event listener for ${event}:`, err);
      }
    }
  }

  public clearAll(): void {
    this.listeners.clear();
  }
}

export const eventPublisher = EventPublisher.getInstance();
