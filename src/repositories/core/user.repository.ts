import { BaseRepository } from '../base/BaseRepository';
import { User, Prisma } from '@prisma/client';

export class UserRepository extends BaseRepository<User, Prisma.UserCreateInput, Prisma.UserUpdateInput> {
  constructor() {
    super('user');
  }

  /**
   * Finds a user by email where not deleted.
   */
  async findByEmail(email: string, tx?: any): Promise<User | null> {
    return this.findOne({ email, deletedAt: null }, tx);
  }

  /**
   * Finds a user by username where not deleted.
   */
  async findByUsername(username: string, tx?: any): Promise<User | null> {
    return this.findOne({ username, deletedAt: null }, tx);
  }

  /**
   * Finds all active users (status: ACTIVE and not deleted).
   */
  async findActiveUsers(tx?: any): Promise<User[]> {
    return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
  }

  /**
   * Finds a user by ID and includes their userRoles and roles.
   */
  async findWithRoles(id: string, tx?: any): Promise<any | null> {
    return this.getDelegate(tx).findUnique({
      where: { id },
      include: {
        userRoles: {
          include: {
            role: true,
          },
        },
      },
    });
  }

  /**
   * Finds a user by ID and includes their owned projects.
   */
  async findWithProjects(id: string, tx?: any): Promise<any | null> {
    return this.getDelegate(tx).findUnique({
      where: { id },
      include: {
        ownedProjects: true,
      },
    });
  }
}
