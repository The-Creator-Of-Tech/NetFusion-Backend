import { ConversationRepository } from './conversation.repository';
import { SessionMemoryRepository } from './session-memory.repository';
import { ContextWindowRepository } from './context-window.repository';
import { PromptAssemblyRepository } from './prompt-assembly.repository';
import { ReasoningRepository } from './reasoning.repository';
import { ExecutionRepository } from './execution.repository';
import { ProviderRepository } from './provider.repository';
import { StreamingRepository } from './streaming.repository';

export {
  ConversationRepository,
  SessionMemoryRepository,
  ContextWindowRepository,
  PromptAssemblyRepository,
  ReasoningRepository,
  ExecutionRepository,
  ProviderRepository,
  StreamingRepository,
};

export const conversationRepository = new ConversationRepository();
export const sessionMemoryRepository = new SessionMemoryRepository();
export const contextWindowRepository = new ContextWindowRepository();
export const promptAssemblyRepository = new PromptAssemblyRepository();
export const reasoningRepository = new ReasoningRepository();
export const executionRepository = new ExecutionRepository();
export const providerRepository = new ProviderRepository();
export const streamingRepository = new StreamingRepository();
