import { AssetRepository } from './asset.repository';
import { FindingRepository } from './finding.repository';
import { EvidenceRepository } from './evidence.repository';
import { AlertRepository } from './alert.repository';
import { TimelineRepository } from './timeline.repository';
import { AttackGraphRepository } from './attack-graph.repository';
import { NoteRepository } from './note.repository';
import { ReportRepository } from './report.repository';

export {
  AssetRepository,
  FindingRepository,
  EvidenceRepository,
  AlertRepository,
  TimelineRepository,
  AttackGraphRepository,
  NoteRepository,
  ReportRepository,
};

export const assetRepository = new AssetRepository();
export const findingRepository = new FindingRepository();
export const evidenceRepository = new EvidenceRepository();
export const alertRepository = new AlertRepository();
export const timelineRepository = new TimelineRepository();
export const attackGraphRepository = new AttackGraphRepository();
export const noteRepository = new NoteRepository();
export const reportRepository = new ReportRepository();
