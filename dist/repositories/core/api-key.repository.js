"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ApiKeyRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class ApiKeyRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('apiKey');
    }
}
exports.ApiKeyRepository = ApiKeyRepository;
