import { UserRepository } from './user.repository';
import { RoleRepository } from './role.repository';
import { PermissionRepository } from './permission.repository';
import { UserRoleRepository } from './user-role.repository';
import { RolePermissionRepository } from './role-permission.repository';
import { ProjectRepository } from './project.repository';
import { InvestigationRepository } from './investigation.repository';
import { AuditLogRepository } from './audit-log.repository';
import { ActivityLogRepository } from './activity-log.repository';
import { NotificationRepository } from './notification.repository';
import { ApiKeyRepository } from './api-key.repository';

export {
  UserRepository,
  RoleRepository,
  PermissionRepository,
  UserRoleRepository,
  RolePermissionRepository,
  ProjectRepository,
  InvestigationRepository,
  AuditLogRepository,
  ActivityLogRepository,
  NotificationRepository,
  ApiKeyRepository,
};

export const userRepository = new UserRepository();
export const roleRepository = new RoleRepository();
export const permissionRepository = new PermissionRepository();
export const userRoleRepository = new UserRoleRepository();
export const rolePermissionRepository = new RolePermissionRepository();
export const projectRepository = new ProjectRepository();
export const investigationRepository = new InvestigationRepository();
export const auditLogRepository = new AuditLogRepository();
export const activityLogRepository = new ActivityLogRepository();
export const notificationRepository = new NotificationRepository();
export const apiKeyRepository = new ApiKeyRepository();
