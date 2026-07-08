/**
 * Investigation Services — Phase A5.3.3
 * ========================================
 * Re-exports all investigation domain services and their singleton instances.
 */

export { TimelineService }     from './timeline.service';
export { AssetService }        from './asset.service';
export { FindingService }      from './finding.service';
export { EvidenceService }     from './evidence.service';
export { AlertService }        from './alert.service';
export { AttackGraphService }  from './attack-graph.service';
export { NoteService }         from './note.service';
export { ReportService }       from './report.service';

import { TimelineService }     from './timeline.service';
import { AssetService }        from './asset.service';
import { FindingService }      from './finding.service';
import { EvidenceService }     from './evidence.service';
import { AlertService }        from './alert.service';
import { AttackGraphService }  from './attack-graph.service';
import { NoteService }         from './note.service';
import { ReportService }       from './report.service';

export const timelineService    = new TimelineService();
export const assetService       = new AssetService();
export const findingService     = new FindingService();
export const evidenceService    = new EvidenceService();
export const alertService       = new AlertService();
export const attackGraphService = new AttackGraphService();
export const noteService        = new NoteService();
export const reportService      = new ReportService();
