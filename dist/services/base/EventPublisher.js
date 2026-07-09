"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.eventPublisher = exports.EventPublisher = void 0;
class EventPublisher {
    constructor() {
        this.listeners = new Map();
    }
    static getInstance() {
        if (!EventPublisher.instance) {
            EventPublisher.instance = new EventPublisher();
        }
        return EventPublisher.instance;
    }
    subscribe(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }
        this.listeners.get(event).push(callback);
    }
    unsubscribe(event, callback) {
        if (!this.listeners.has(event))
            return;
        const list = this.listeners.get(event);
        const index = list.indexOf(callback);
        if (index !== -1) {
            list.splice(index, 1);
        }
    }
    async publish(event, data) {
        const list = this.listeners.get(event) || [];
        for (const callback of list) {
            try {
                await callback(data);
            }
            catch (err) {
                console.error(`Error in event listener for ${event}:`, err);
            }
        }
    }
    clearAll() {
        this.listeners.clear();
    }
}
exports.EventPublisher = EventPublisher;
exports.eventPublisher = EventPublisher.getInstance();
