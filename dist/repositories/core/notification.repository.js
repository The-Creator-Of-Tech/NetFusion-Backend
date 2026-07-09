"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NotificationRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class NotificationRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('notification');
    }
}
exports.NotificationRepository = NotificationRepository;
