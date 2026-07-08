/**
 * AI Services — Phase A5.3.4
 * ============================
 * Re-exports all AI domain services and their singleton instances.
 */

export { ConversationService }   from './conversation.service';
export { SessionMemoryService }  from './session-memory.service';
export { ContextWindowService }  from './context-window.service';
export { PromptAssemblyService } from './prompt-assembly.service';
export { ReasoningService }      from './reasoning.service';
export { ExecutionService }      from './execution.service';
export { ProviderService }       from './provider.service';
export { StreamingService }      from './streaming.service';

import { ConversationService }   from './conversation.service';
import { SessionMemoryService }  from './session-memory.service';
import { ContextWindowService }  from './context-window.service';
import { PromptAssemblyService } from './prompt-assembly.service';
import { ReasoningService }      from './reasoning.service';
import { ExecutionService }      from './execution.service';
import { ProviderService }       from './provider.service';
import { StreamingService }      from './streaming.service';

export const conversationService   = new ConversationService();
export const sessionMemoryService  = new SessionMemoryService();
export const contextWindowService  = new ContextWindowService();
export const promptAssemblyService = new PromptAssemblyService();
export const reasoningService      = new ReasoningService();
export const executionService      = new ExecutionService();
export const providerService       = new ProviderService();
export const streamingService      = new StreamingService();
