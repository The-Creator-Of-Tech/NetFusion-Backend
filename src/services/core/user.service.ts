import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import {
  userRepository,
  notificationRepository,
  apiKeyRepository,
  projectRepository
} from '../../repositories/core';
import prisma from '../../lib/prisma';
import { User, Prisma, UserStatus, NotificationStatus } from '@prisma/client';
import * as crypto from 'crypto';

export class UserService extends BaseService {
  constructor(
    private readonly userRepo = userRepository,
    private readonly notificationRepo = notificationRepository,
    private readonly apiKeyRepo = apiKeyRepository,
    private readonly projectRepo = projectRepository
  ) {
    super();
  }

  async validateUserUniqueness(email: string, username: string, tx?: any): Promise<void> {
    const existingEmail = await this.userRepo.findOne({ email, deletedAt: null }, tx);
    if (existingEmail) {
      throw new Error(`Validation failed: User with email "${email}" already exists.`);
    }

    const existingUsername = await this.userRepo.findOne({ username, deletedAt: null }, tx);
    if (existingUsername) {
      throw new Error(`Validation failed: User with username "${username}" already exists.`);
    }
  }

  async createUser(data: Prisma.UserCreateInput, tx?: any): Promise<{ user: User; apiKey: string }> {
    this.validateRequired(data as any, ['email', 'username', 'passwordHash']);

    const runInTx = async (transaction: any) => {
      // 1. Uniqueness check
      await this.validateUserUniqueness(data.email, data.username, transaction);

      // 3. Create User
      const user = await this.userRepo.create({
        ...data,
        status: 'ACTIVE' as UserStatus,
      }, transaction);

      // 4. Initialize default preference in user_preferences table
      const client = transaction || prisma;
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
      await eventPublisher.publish('UserCreated', { user });

      return { user, apiKey: rawKey };
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async updateUser(id: string, data: Prisma.UserUpdateInput, tx?: any): Promise<User> {
    this.validateUuid(id, 'userId');

    const runInTx = async (transaction: any) => {
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
      await eventPublisher.publish('UserUpdated', { user: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async activateUser(id: string, tx?: any): Promise<User> {
    this.validateUuid(id, 'userId');
    const runInTx = async (transaction: any) => {
      const user = await this.updateUser(id, { status: 'ACTIVE' as UserStatus }, transaction);
      await eventPublisher.publish('UserActivated', { user });
      return user;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async deactivateUser(id: string, tx?: any): Promise<User> {
    this.validateUuid(id, 'userId');
    const runInTx = async (transaction: any) => {
      const user = await this.updateUser(id, { status: 'INACTIVE' as UserStatus }, transaction);
      await eventPublisher.publish('UserDeactivated', { user });
      return user;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async resetApiKeys(userId: string, tx?: any): Promise<{ apiKey: string }> {
    this.validateUuid(userId, 'userId');

    const runInTx = async (transaction: any) => {
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

      await eventPublisher.publish('UserApiKeysReset', { userId });
      return { apiKey: rawKey };
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async listProjects(userId: string, tx?: any): Promise<any[]> {
    this.validateUuid(userId, 'userId');
    return this.projectRepo.findMany({ filter: { ownerId: userId, deletedAt: null } }, tx);
  }

  async listNotifications(userId: string, status?: NotificationStatus, tx?: any): Promise<any[]> {
    this.validateUuid(userId, 'userId');
    const filter: any = { userId, deletedAt: null };
    if (status) {
      filter.status = status;
    }
    return this.notificationRepo.findMany({ filter }, tx);
  }
}
