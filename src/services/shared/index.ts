/**
 * Shared Domain Services — Phase A5.3.7
 * =========================================
 * Barrel export for all shared domain service singletons and classes.
 *
 * Services
 * --------
 * - NotificationService  — notification lifecycle
 * - AttachmentService    — file/attachment management
 * - CommentService       — comment lifecycle & visibility
 * - TagService           — tag + assignment management
 * - FavoriteService      — favorites toggle / lookup
 * - ActivityService      — activity logging & audit trail
 * - SettingService       — system settings (upsert/typed getters)
 * - ApiKeyService        — API key management & validation
 */

export { NotificationService, notificationService } from './notification.service';
export { AttachmentService, attachmentService } from './attachment.service';
export { CommentService, commentService } from './comment.service';
export { TagService, tagService } from './tag.service';
export { FavoriteService, favoriteService } from './favorite.service';
export { ActivityService, activityService } from './activity.service';
export { SettingService, settingService } from './setting.service';
export { ApiKeyService, apiKeyService } from './apikey.service';
