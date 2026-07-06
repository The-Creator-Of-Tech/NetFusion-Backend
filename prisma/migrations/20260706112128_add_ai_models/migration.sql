-- CreateEnum
CREATE TYPE "ConversationStatus" AS ENUM ('ACTIVE', 'ARCHIVED', 'COMPLETED', 'DELETED');

-- CreateEnum
CREATE TYPE "ExecutionStatus" AS ENUM ('ACTIVE', 'COMPLETED', 'FAILED', 'PENDING');

-- CreateEnum
CREATE TYPE "ProviderStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'DEGRADED');

-- CreateEnum
CREATE TYPE "StreamingStatus" AS ENUM ('ACTIVE', 'COMPLETED', 'FAILED', 'PENDING');

-- CreateEnum
CREATE TYPE "ReasoningStatus" AS ENUM ('ACTIVE', 'COMPLETED', 'FAILED', 'PENDING');

-- CreateEnum
CREATE TYPE "PromptStatus" AS ENUM ('ACTIVE', 'ARCHIVED', 'DRAFT');

-- CreateEnum
CREATE TYPE "MemoryStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "ContextStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "ProviderType" AS ENUM ('CLOUD', 'LOCAL', 'HYBRID');

-- CreateTable
CREATE TABLE "conversations" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID,
    "userId" UUID,
    "title" TEXT NOT NULL,
    "status" "ConversationStatus" NOT NULL DEFAULT 'ACTIVE',
    "summary" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "contextSize" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "conversations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "conversation_messages" (
    "id" UUID NOT NULL,
    "conversationId" UUID NOT NULL,
    "parentMessageId" UUID,
    "role" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "conversation_messages_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "session_memories" (
    "id" UUID NOT NULL,
    "conversationId" UUID NOT NULL,
    "investigationId" UUID,
    "projectId" UUID NOT NULL,
    "userId" UUID,
    "status" "MemoryStatus" NOT NULL DEFAULT 'ACTIVE',
    "contextSize" INTEGER NOT NULL DEFAULT 0,
    "sessionName" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "session_memories_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "memory_entries" (
    "id" UUID NOT NULL,
    "memoryId" UUID NOT NULL,
    "memoryType" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "importanceScore" DOUBLE PRECISION NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "sourceId" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "memory_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "context_windows" (
    "id" UUID NOT NULL,
    "investigationId" UUID,
    "conversationId" UUID,
    "projectId" UUID NOT NULL,
    "userId" UUID,
    "status" "ContextStatus" NOT NULL DEFAULT 'ACTIVE',
    "contextSize" INTEGER NOT NULL DEFAULT 0,
    "windowName" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "context_windows_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "context_entries" (
    "id" UUID NOT NULL,
    "contextId" UUID NOT NULL,
    "source" TEXT NOT NULL,
    "priority" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "referenceId" TEXT NOT NULL,
    "importanceScore" DOUBLE PRECISION NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "context_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "prompt_assemblies" (
    "id" UUID NOT NULL,
    "reasoningId" UUID,
    "contextId" UUID,
    "investigationId" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "userId" UUID,
    "systemPrompt" TEXT NOT NULL,
    "userPrompt" TEXT NOT NULL,
    "maxTokens" INTEGER NOT NULL DEFAULT 8192,
    "reservedTokens" INTEGER NOT NULL DEFAULT 1024,
    "processingTimeMs" INTEGER NOT NULL DEFAULT 0,
    "status" "PromptStatus" NOT NULL DEFAULT 'ACTIVE',
    "promptName" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "prompt_assemblies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "prompt_sections" (
    "id" UUID NOT NULL,
    "promptId" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "priority" INTEGER NOT NULL DEFAULT 50,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "prompt_sections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reasoning_sessions" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "userId" UUID,
    "decision" TEXT,
    "overallConfidence" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "overallRisk" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "status" "ReasoningStatus" NOT NULL DEFAULT 'ACTIVE',
    "sessionName" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "reasoning_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reasoning_steps" (
    "id" UUID NOT NULL,
    "reasoningId" UUID NOT NULL,
    "stepNumber" INTEGER NOT NULL,
    "stage" TEXT NOT NULL,
    "inputSummary" TEXT NOT NULL,
    "outputSummary" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "evidenceIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "findingIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "alertIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "relationshipIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "timelineEventIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "reasoning_steps_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "providers" (
    "id" UUID NOT NULL,
    "providerName" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "apiVersion" TEXT NOT NULL,
    "endpoint" TEXT NOT NULL,
    "defaultModel" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "priority" INTEGER NOT NULL DEFAULT 50,
    "healthScore" DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    "providerType" "ProviderType" NOT NULL DEFAULT 'CLOUD',
    "status" "ProviderStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "providers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "provider_models" (
    "id" UUID NOT NULL,
    "providerId" UUID NOT NULL,
    "modelName" TEXT NOT NULL,
    "alias" TEXT,
    "streaming" BOOLEAN NOT NULL DEFAULT false,
    "toolCalling" BOOLEAN NOT NULL DEFAULT false,
    "jsonMode" BOOLEAN NOT NULL DEFAULT false,
    "vision" BOOLEAN NOT NULL DEFAULT false,
    "embeddings" BOOLEAN NOT NULL DEFAULT false,
    "maxContextTokens" INTEGER NOT NULL DEFAULT 8192,
    "maxOutputTokens" INTEGER NOT NULL DEFAULT 4096,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "priority" INTEGER NOT NULL DEFAULT 50,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "provider_models_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "executions" (
    "id" UUID NOT NULL,
    "providerId" UUID NOT NULL,
    "providerModelId" UUID,
    "systemPrompt" TEXT NOT NULL,
    "userPrompt" TEXT NOT NULL,
    "temperature" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "maxTokens" INTEGER NOT NULL DEFAULT 1024,
    "stream" BOOLEAN NOT NULL DEFAULT false,
    "strategy" TEXT NOT NULL DEFAULT 'priority',
    "projectId" UUID,
    "investigationId" UUID,
    "userId" UUID,
    "status" "ExecutionStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "executions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "execution_usages" (
    "id" UUID NOT NULL,
    "executionId" UUID NOT NULL,
    "promptTokens" INTEGER NOT NULL,
    "completionTokens" INTEGER NOT NULL,
    "totalTokens" INTEGER NOT NULL,
    "estimatedCost" DOUBLE PRECISION NOT NULL,
    "latencyMs" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "execution_usages_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "streaming_sessions" (
    "id" UUID NOT NULL,
    "executionId" UUID,
    "streamName" TEXT,
    "status" "StreamingStatus" NOT NULL DEFAULT 'ACTIVE',
    "projectId" UUID,
    "investigationId" UUID,
    "userId" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "streaming_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "streaming_chunks" (
    "id" UUID NOT NULL,
    "streamingId" UUID NOT NULL,
    "sequenceNumber" INTEGER NOT NULL,
    "content" TEXT NOT NULL,
    "finishReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "streaming_chunks_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "conversations_userId_idx" ON "conversations"("userId");

-- CreateIndex
CREATE INDEX "conversations_projectId_idx" ON "conversations"("projectId");

-- CreateIndex
CREATE INDEX "conversations_investigationId_idx" ON "conversations"("investigationId");

-- CreateIndex
CREATE INDEX "conversations_status_idx" ON "conversations"("status");

-- CreateIndex
CREATE INDEX "conversations_createdAt_idx" ON "conversations"("createdAt");

-- CreateIndex
CREATE INDEX "conversations_updatedAt_idx" ON "conversations"("updatedAt");

-- CreateIndex
CREATE INDEX "conversation_messages_conversationId_idx" ON "conversation_messages"("conversationId");

-- CreateIndex
CREATE INDEX "conversation_messages_createdAt_idx" ON "conversation_messages"("createdAt");

-- CreateIndex
CREATE INDEX "conversation_messages_updatedAt_idx" ON "conversation_messages"("updatedAt");

-- CreateIndex
CREATE INDEX "session_memories_userId_idx" ON "session_memories"("userId");

-- CreateIndex
CREATE INDEX "session_memories_projectId_idx" ON "session_memories"("projectId");

-- CreateIndex
CREATE INDEX "session_memories_investigationId_idx" ON "session_memories"("investigationId");

-- CreateIndex
CREATE INDEX "session_memories_conversationId_idx" ON "session_memories"("conversationId");

-- CreateIndex
CREATE INDEX "session_memories_status_idx" ON "session_memories"("status");

-- CreateIndex
CREATE INDEX "session_memories_createdAt_idx" ON "session_memories"("createdAt");

-- CreateIndex
CREATE INDEX "session_memories_updatedAt_idx" ON "session_memories"("updatedAt");

-- CreateIndex
CREATE INDEX "memory_entries_createdAt_idx" ON "memory_entries"("createdAt");

-- CreateIndex
CREATE INDEX "memory_entries_updatedAt_idx" ON "memory_entries"("updatedAt");

-- CreateIndex
CREATE INDEX "context_windows_userId_idx" ON "context_windows"("userId");

-- CreateIndex
CREATE INDEX "context_windows_projectId_idx" ON "context_windows"("projectId");

-- CreateIndex
CREATE INDEX "context_windows_investigationId_idx" ON "context_windows"("investigationId");

-- CreateIndex
CREATE INDEX "context_windows_conversationId_idx" ON "context_windows"("conversationId");

-- CreateIndex
CREATE INDEX "context_windows_status_idx" ON "context_windows"("status");

-- CreateIndex
CREATE INDEX "context_windows_createdAt_idx" ON "context_windows"("createdAt");

-- CreateIndex
CREATE INDEX "context_windows_updatedAt_idx" ON "context_windows"("updatedAt");

-- CreateIndex
CREATE INDEX "context_entries_createdAt_idx" ON "context_entries"("createdAt");

-- CreateIndex
CREATE INDEX "context_entries_updatedAt_idx" ON "context_entries"("updatedAt");

-- CreateIndex
CREATE INDEX "prompt_assemblies_userId_idx" ON "prompt_assemblies"("userId");

-- CreateIndex
CREATE INDEX "prompt_assemblies_projectId_idx" ON "prompt_assemblies"("projectId");

-- CreateIndex
CREATE INDEX "prompt_assemblies_investigationId_idx" ON "prompt_assemblies"("investigationId");

-- CreateIndex
CREATE INDEX "prompt_assemblies_status_idx" ON "prompt_assemblies"("status");

-- CreateIndex
CREATE INDEX "prompt_assemblies_createdAt_idx" ON "prompt_assemblies"("createdAt");

-- CreateIndex
CREATE INDEX "prompt_assemblies_updatedAt_idx" ON "prompt_assemblies"("updatedAt");

-- CreateIndex
CREATE INDEX "prompt_sections_createdAt_idx" ON "prompt_sections"("createdAt");

-- CreateIndex
CREATE INDEX "prompt_sections_updatedAt_idx" ON "prompt_sections"("updatedAt");

-- CreateIndex
CREATE INDEX "reasoning_sessions_userId_idx" ON "reasoning_sessions"("userId");

-- CreateIndex
CREATE INDEX "reasoning_sessions_projectId_idx" ON "reasoning_sessions"("projectId");

-- CreateIndex
CREATE INDEX "reasoning_sessions_investigationId_idx" ON "reasoning_sessions"("investigationId");

-- CreateIndex
CREATE INDEX "reasoning_sessions_status_idx" ON "reasoning_sessions"("status");

-- CreateIndex
CREATE INDEX "reasoning_sessions_createdAt_idx" ON "reasoning_sessions"("createdAt");

-- CreateIndex
CREATE INDEX "reasoning_sessions_updatedAt_idx" ON "reasoning_sessions"("updatedAt");

-- CreateIndex
CREATE INDEX "reasoning_steps_createdAt_idx" ON "reasoning_steps"("createdAt");

-- CreateIndex
CREATE INDEX "reasoning_steps_updatedAt_idx" ON "reasoning_steps"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "providers_providerName_key" ON "providers"("providerName");

-- CreateIndex
CREATE INDEX "providers_status_idx" ON "providers"("status");

-- CreateIndex
CREATE INDEX "providers_createdAt_idx" ON "providers"("createdAt");

-- CreateIndex
CREATE INDEX "providers_updatedAt_idx" ON "providers"("updatedAt");

-- CreateIndex
CREATE INDEX "provider_models_providerId_idx" ON "provider_models"("providerId");

-- CreateIndex
CREATE INDEX "provider_models_createdAt_idx" ON "provider_models"("createdAt");

-- CreateIndex
CREATE INDEX "provider_models_updatedAt_idx" ON "provider_models"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "provider_models_providerId_modelName_key" ON "provider_models"("providerId", "modelName");

-- CreateIndex
CREATE INDEX "executions_userId_idx" ON "executions"("userId");

-- CreateIndex
CREATE INDEX "executions_projectId_idx" ON "executions"("projectId");

-- CreateIndex
CREATE INDEX "executions_investigationId_idx" ON "executions"("investigationId");

-- CreateIndex
CREATE INDEX "executions_providerId_idx" ON "executions"("providerId");

-- CreateIndex
CREATE INDEX "executions_status_idx" ON "executions"("status");

-- CreateIndex
CREATE INDEX "executions_createdAt_idx" ON "executions"("createdAt");

-- CreateIndex
CREATE INDEX "executions_updatedAt_idx" ON "executions"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "execution_usages_executionId_key" ON "execution_usages"("executionId");

-- CreateIndex
CREATE INDEX "execution_usages_executionId_idx" ON "execution_usages"("executionId");

-- CreateIndex
CREATE INDEX "execution_usages_createdAt_idx" ON "execution_usages"("createdAt");

-- CreateIndex
CREATE INDEX "execution_usages_updatedAt_idx" ON "execution_usages"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "streaming_sessions_executionId_key" ON "streaming_sessions"("executionId");

-- CreateIndex
CREATE INDEX "streaming_sessions_userId_idx" ON "streaming_sessions"("userId");

-- CreateIndex
CREATE INDEX "streaming_sessions_projectId_idx" ON "streaming_sessions"("projectId");

-- CreateIndex
CREATE INDEX "streaming_sessions_investigationId_idx" ON "streaming_sessions"("investigationId");

-- CreateIndex
CREATE INDEX "streaming_sessions_executionId_idx" ON "streaming_sessions"("executionId");

-- CreateIndex
CREATE INDEX "streaming_sessions_status_idx" ON "streaming_sessions"("status");

-- CreateIndex
CREATE INDEX "streaming_sessions_createdAt_idx" ON "streaming_sessions"("createdAt");

-- CreateIndex
CREATE INDEX "streaming_sessions_updatedAt_idx" ON "streaming_sessions"("updatedAt");

-- CreateIndex
CREATE INDEX "streaming_chunks_createdAt_idx" ON "streaming_chunks"("createdAt");

-- CreateIndex
CREATE INDEX "streaming_chunks_updatedAt_idx" ON "streaming_chunks"("updatedAt");

-- AddForeignKey
ALTER TABLE "conversations" ADD CONSTRAINT "conversations_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "conversations" ADD CONSTRAINT "conversations_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "conversations" ADD CONSTRAINT "conversations_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "conversation_messages" ADD CONSTRAINT "conversation_messages_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "conversations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "conversation_messages" ADD CONSTRAINT "conversation_messages_parentMessageId_fkey" FOREIGN KEY ("parentMessageId") REFERENCES "conversation_messages"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "session_memories" ADD CONSTRAINT "session_memories_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "conversations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "session_memories" ADD CONSTRAINT "session_memories_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "session_memories" ADD CONSTRAINT "session_memories_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "session_memories" ADD CONSTRAINT "session_memories_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "memory_entries" ADD CONSTRAINT "memory_entries_memoryId_fkey" FOREIGN KEY ("memoryId") REFERENCES "session_memories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "context_windows" ADD CONSTRAINT "context_windows_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "context_windows" ADD CONSTRAINT "context_windows_conversationId_fkey" FOREIGN KEY ("conversationId") REFERENCES "conversations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "context_windows" ADD CONSTRAINT "context_windows_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "context_windows" ADD CONSTRAINT "context_windows_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "context_entries" ADD CONSTRAINT "context_entries_contextId_fkey" FOREIGN KEY ("contextId") REFERENCES "context_windows"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prompt_assemblies" ADD CONSTRAINT "prompt_assemblies_reasoningId_fkey" FOREIGN KEY ("reasoningId") REFERENCES "reasoning_sessions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prompt_assemblies" ADD CONSTRAINT "prompt_assemblies_contextId_fkey" FOREIGN KEY ("contextId") REFERENCES "context_windows"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prompt_assemblies" ADD CONSTRAINT "prompt_assemblies_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prompt_assemblies" ADD CONSTRAINT "prompt_assemblies_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prompt_assemblies" ADD CONSTRAINT "prompt_assemblies_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prompt_sections" ADD CONSTRAINT "prompt_sections_promptId_fkey" FOREIGN KEY ("promptId") REFERENCES "prompt_assemblies"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reasoning_sessions" ADD CONSTRAINT "reasoning_sessions_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reasoning_sessions" ADD CONSTRAINT "reasoning_sessions_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reasoning_sessions" ADD CONSTRAINT "reasoning_sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reasoning_steps" ADD CONSTRAINT "reasoning_steps_reasoningId_fkey" FOREIGN KEY ("reasoningId") REFERENCES "reasoning_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "provider_models" ADD CONSTRAINT "provider_models_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "providers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "providers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_providerModelId_fkey" FOREIGN KEY ("providerModelId") REFERENCES "provider_models"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_usages" ADD CONSTRAINT "execution_usages_executionId_fkey" FOREIGN KEY ("executionId") REFERENCES "executions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "streaming_sessions" ADD CONSTRAINT "streaming_sessions_executionId_fkey" FOREIGN KEY ("executionId") REFERENCES "executions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "streaming_sessions" ADD CONSTRAINT "streaming_sessions_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "streaming_sessions" ADD CONSTRAINT "streaming_sessions_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "streaming_sessions" ADD CONSTRAINT "streaming_sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "streaming_chunks" ADD CONSTRAINT "streaming_chunks_streamingId_fkey" FOREIGN KEY ("streamingId") REFERENCES "streaming_sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
