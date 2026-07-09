"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const core_1 = require("../../repositories/core");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const crypto = __importStar(require("crypto"));
class UserService extends BaseService_1.BaseService {
    constructor(userRepo = core_1.userRepository, notificationRepo = core_1.notificationRepository, apiKeyRepo = core_1.apiKeyRepository, projectRepo = core_1.projectRepository) {
        super();
        this.userRepo = userRepo;
        this.notificationRepo = notificationRepo;
        this.apiKeyRepo = apiKeyRepo;
        this.projectRepo = projectRepo;
    }
    async validateUserUniqueness(email, username, tx) {
        const existingEmail = await this.userRepo.findOne({ email, deletedAt: null }, tx);
        if (existingEmail) {
            throw new Error(`Validation failed: User with email "${email}" already exists.`);
        }
        const existingUsername = await this.userRepo.findOne({ username, deletedAt: null }, tx);
        if (existingUsername) {
            throw new Error(`Validation failed: User with username "${username}" already exists.`);
        }
    }
    async createUser(data, tx) {
        this.validateRequired(data, ['email', 'username', 'passwordHash']);
        const runInTx = async (transaction) => {
            // 1. Uniqueness check
            await this.validateUserUniqueness(data.email, data.username, transaction);
            // 3. Create User
            const user = await this.userRepo.create({
                ...data,
                status: 'ACTIVE',
            }, transaction);
            // 4. Initialize default preference in user_preferences table
            const client = transaction || prisma_1.default;
            await client.userPreference.create({
                data: {
                    userId: user.id,
                    key: 'theme',
                    value: 'dark',
                    createdBy: user.username,
                    updatedBy: user.username,
                }
            });
            // 4. API Key generation (ACTIVE status)
            const rawKey = 'nf_' + crypto.randomBytes(24).toString('hex');
            const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
            await this.apiKeyRepo.create({
                userId: user.id,
                name: 'Default API Key',
                keyHash,
                status: 'ACTIVE',
                createdBy: user.username,
                updatedBy: user.username,
            }, transaction);
            // 5. Welcome Notification
            await this.notificationRepo.create({
                userId: user.id,
                title: 'Welcome to NetFusion',
                message: `Hello ${user.username}, welcome to your new NetFusion account!`,
                type: 'SYSTEM',
                status: 'UNREAD',
                createdBy: 'system',
                updatedBy: 'system',
            }, transaction);
            // 6. Publish event
            await EventPublisher_1.eventPublisher.publish('UserCreated', { user });
            return { user, apiKey: rawKey };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async updateUser(id, data, tx) {
        this.validateUuid(id, 'userId');
        const runInTx = async (transaction) => {
            const existing = await this.userRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`User with ID "${id}" not found.`);
            }
            const email = data.email && typeof data.email === 'string' ? data.email : undefined;
            const username = data.username && typeof data.username === 'string' ? data.username : undefined;
            if (email && email !== existing.email) {
                const other = await this.userRepo.findOne({ email, deletedAt: null }, transaction);
                if (other && other.id !== id) {
                    throw new Error(`Validation failed: User with email "${email}" already exists.`);
                }
            }
            if (username && username !== existing.username) {
                const other = await this.userRepo.findOne({ username, deletedAt: null }, transaction);
                if (other && other.id !== id) {
                    throw new Error(`Validation failed: User with username "${username}" already exists.`);
                }
            }
            const updated = await this.userRepo.update(id, data, transaction);
            await EventPublisher_1.eventPublisher.publish('UserUpdated', { user: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async activateUser(id, tx) {
        this.validateUuid(id, 'userId');
        const runInTx = async (transaction) => {
            const user = await this.updateUser(id, { status: 'ACTIVE' }, transaction);
            await EventPublisher_1.eventPublisher.publish('UserActivated', { user });
            return user;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async deactivateUser(id, tx) {
        this.validateUuid(id, 'userId');
        const runInTx = async (transaction) => {
            const user = await this.updateUser(id, { status: 'INACTIVE' }, transaction);
            await EventPublisher_1.eventPublisher.publish('UserDeactivated', { user });
            return user;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async resetApiKeys(userId, tx) {
        this.validateUuid(userId, 'userId');
        const runInTx = async (transaction) => {
            const user = await this.userRepo.findById(userId, transaction);
            if (!user || user.deletedAt) {
                throw new Error(`User with ID "${userId}" not found.`);
            }
            // Revoke all existing API keys for the user
            const existingKeys = await this.apiKeyRepo.findMany({
                filter: { userId, status: 'ACTIVE', deletedAt: null }
            }, transaction);
            for (const k of existingKeys) {
                await this.apiKeyRepo.update(k.id, { status: 'REVOKED' }, transaction);
            }
            // Generate a new key
            const rawKey = 'nf_' + crypto.randomBytes(24).toString('hex');
            const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
            await this.apiKeyRepo.create({
                userId,
                name: 'New API Key',
                keyHash,
                status: 'ACTIVE',
                createdBy: 'system',
                updatedBy: 'system',
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('UserApiKeysReset', { userId });
            return { apiKey: rawKey };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async listProjects(userId, tx) {
        this.validateUuid(userId, 'userId');
        return this.projectRepo.findMany({ filter: { ownerId: userId, deletedAt: null } }, tx);
    }
    async listNotifications(userId, status, tx) {
        this.validateUuid(userId, 'userId');
        const filter = { userId, deletedAt: null };
        if (status) {
            filter.status = status;
        }
        return this.notificationRepo.findMany({ filter }, tx);
    }
}
exports.UserService = UserService;
