import { BaseRepository } from '../base/BaseRepository';
import { ApiKey, Prisma } from '@prisma/client';

export class ApiKeyRepository extends BaseRepository<ApiKey, Prisma.ApiKeyUncheckedCreateInput, Prisma.ApiKeyUncheckedUpdateInput> {
  constructor() {
    super('apiKey');
  }
}
