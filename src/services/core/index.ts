import { ProjectService } from './project.service';
import { InvestigationService } from './investigation.service';
import { UserService } from './user.service';
import { RoleService } from './role.service';
import { PermissionService } from './permission.service';

export {
  ProjectService,
  InvestigationService,
  UserService,
  RoleService,
  PermissionService,
};

export const projectService = new ProjectService();
export const investigationService = new InvestigationService();
export const userService = new UserService();
export const roleService = new RoleService();
export const permissionService = new PermissionService();
