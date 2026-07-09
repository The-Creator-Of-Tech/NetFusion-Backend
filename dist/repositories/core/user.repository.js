"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class UserRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('user');
    }
    /**
     * Finds a user by email where not deleted.
     */
    async findByEmail(email, tx) {
        return this.findOne({ email, deletedAt: null }, tx);
    }
    /**
     * Finds a user by username where not deleted.
     */
    async findByUsername(username, tx) {
        return this.findOne({ username, deletedAt: null }, tx);
    }
    /**
     * Finds all active users (status: ACTIVE and not deleted).
     */
    async findActiveUsers(tx) {
        return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
    }
    /**
     * Finds a user by ID and includes their userRoles and roles.
     */
    async findWithRoles(id, tx) {
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
    async findWithProjects(id, tx) {
        return this.getDelegate(tx).findUnique({
            where: { id },
            include: {
                ownedProjects: true,
            },
        });
    }
}
exports.UserRepository = UserRepository;
