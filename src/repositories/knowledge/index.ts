import { MitreRepository } from './mitre.repository';
import { CveRepository } from './cve.repository';
import { IocRepository } from './ioc.repository';
import { ThreatRepository } from './threat.repository';

export {
  MitreRepository,
  CveRepository,
  IocRepository,
  ThreatRepository,
};

export const mitreRepository = new MitreRepository();
export const cveRepository = new CveRepository();
export const iocRepository = new IocRepository();
export const threatRepository = new ThreatRepository();
