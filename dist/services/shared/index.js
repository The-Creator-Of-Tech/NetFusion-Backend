"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.apiKeyService = exports.ApiKeyService = exports.settingService = exports.SettingService = exports.activityService = exports.ActivityService = exports.favoriteService = exports.FavoriteService = exports.tagService = exports.TagService = exports.commentService = exports.CommentService = exports.attachmentService = exports.AttachmentService = exports.notificationService = exports.NotificationService = void 0;
var notification_service_1 = require("./notification.service");
Object.defineProperty(exports, "NotificationService", { enumerable: true, get: function () { return notification_service_1.NotificationService; } });
Object.defineProperty(exports, "notificationService", { enumerable: true, get: function () { return notification_service_1.notificationService; } });
var attachment_service_1 = require("./attachment.service");
Object.defineProperty(exports, "AttachmentService", { enumerable: true, get: function () { return attachment_service_1.AttachmentService; } });
Object.defineProperty(exports, "attachmentService", { enumerable: true, get: function () { return attachment_service_1.attachmentService; } });
var comment_service_1 = require("./comment.service");
Object.defineProperty(exports, "CommentService", { enumerable: true, get: function () { return comment_service_1.CommentService; } });
Object.defineProperty(exports, "commentService", { enumerable: true, get: function () { return comment_service_1.commentService; } });
var tag_service_1 = require("./tag.service");
Object.defineProperty(exports, "TagService", { enumerable: true, get: function () { return tag_service_1.TagService; } });
Object.defineProperty(exports, "tagService", { enumerable: true, get: function () { return tag_service_1.tagService; } });
var favorite_service_1 = require("./favorite.service");
Object.defineProperty(exports, "FavoriteService", { enumerable: true, get: function () { return favorite_service_1.FavoriteService; } });
Object.defineProperty(exports, "favoriteService", { enumerable: true, get: function () { return favorite_service_1.favoriteService; } });
var activity_service_1 = require("./activity.service");
Object.defineProperty(exports, "ActivityService", { enumerable: true, get: function () { return activity_service_1.ActivityService; } });
Object.defineProperty(exports, "activityService", { enumerable: true, get: function () { return activity_service_1.activityService; } });
var setting_service_1 = require("./setting.service");
Object.defineProperty(exports, "SettingService", { enumerable: true, get: function () { return setting_service_1.SettingService; } });
Object.defineProperty(exports, "settingService", { enumerable: true, get: function () { return setting_service_1.settingService; } });
var apikey_service_1 = require("./apikey.service");
Object.defineProperty(exports, "ApiKeyService", { enumerable: true, get: function () { return apikey_service_1.ApiKeyService; } });
Object.defineProperty(exports, "apiKeyService", { enumerable: true, get: function () { return apikey_service_1.apiKeyService; } });
