"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ActivityLogRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class ActivityLogRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('activityLog');
    }
}
exports.ActivityLogRepository = ActivityLogRepository;
