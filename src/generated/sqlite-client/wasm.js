
Object.defineProperty(exports, "__esModule", { value: true });

const {
  Decimal,
  objectEnumValues,
  makeStrictEnum,
  Public,
  getRuntime,
  skip
} = require('./runtime/index-browser.js')


const Prisma = {}

exports.Prisma = Prisma
exports.$Enums = {}

/**
 * Prisma Client JS version: 5.22.0
 * Query Engine version: 605197351a3c8bdd595af2d2a9bc3025bca48ea2
 */
Prisma.prismaVersion = {
  client: "5.22.0",
  engine: "605197351a3c8bdd595af2d2a9bc3025bca48ea2"
}

Prisma.PrismaClientKnownRequestError = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`PrismaClientKnownRequestError is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)};
Prisma.PrismaClientUnknownRequestError = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`PrismaClientUnknownRequestError is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.PrismaClientRustPanicError = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`PrismaClientRustPanicError is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.PrismaClientInitializationError = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`PrismaClientInitializationError is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.PrismaClientValidationError = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`PrismaClientValidationError is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.NotFoundError = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`NotFoundError is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.Decimal = Decimal

/**
 * Re-export of sql-template-tag
 */
Prisma.sql = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`sqltag is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.empty = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`empty is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.join = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`join is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.raw = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`raw is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.validator = Public.validator

/**
* Extensions
*/
Prisma.getExtensionContext = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`Extensions.getExtensionContext is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}
Prisma.defineExtension = () => {
  const runtimeName = getRuntime().prettyName;
  throw new Error(`Extensions.defineExtension is unable to run in this browser environment, or has been bundled for the browser (running in ${runtimeName}).
In case this error is unexpected for you, please report it in https://pris.ly/prisma-prisma-bug-report`,
)}

/**
 * Shorthand utilities for JSON filtering
 */
Prisma.DbNull = objectEnumValues.instances.DbNull
Prisma.JsonNull = objectEnumValues.instances.JsonNull
Prisma.AnyNull = objectEnumValues.instances.AnyNull

Prisma.NullTypes = {
  DbNull: objectEnumValues.classes.DbNull,
  JsonNull: objectEnumValues.classes.JsonNull,
  AnyNull: objectEnumValues.classes.AnyNull
}



/**
 * Enums
 */

exports.Prisma.TransactionIsolationLevel = makeStrictEnum({
  Serializable: 'Serializable'
});

exports.Prisma.ScanRunScalarFieldEnum = {
  id: 'id',
  projectId: 'projectId',
  captureId: 'captureId',
  startedAt: 'startedAt',
  completedAt: 'completedAt',
  status: 'status',
  packetCount: 'packetCount',
  summary: 'summary',
  findings: 'findings',
  createdAt: 'createdAt',
  updatedAt: 'updatedAt',
  captureSessionId: 'captureSessionId'
};

exports.Prisma.CaptureSessionScalarFieldEnum = {
  id: 'id',
  projectId: 'projectId',
  captureId: 'captureId',
  packetCount: 'packetCount',
  analysis: 'analysis',
  timeline: 'timeline',
  alerts: 'alerts',
  iocs: 'iocs',
  correlations: 'correlations',
  mitre: 'mitre',
  riskRanking: 'riskRanking',
  attackStory: 'attackStory',
  investigationPlan: 'investigationPlan',
  executiveReport: 'executiveReport',
  createdAt: 'createdAt',
  updatedAt: 'updatedAt'
};

exports.Prisma.ReportArchiveScalarFieldEnum = {
  id: 'id',
  projectId: 'projectId',
  reportType: 'reportType',
  reportData: 'reportData',
  createdAt: 'createdAt',
  archivedAt: 'archivedAt'
};

exports.Prisma.PcapInvestigationScalarFieldEnum = {
  id: 'id',
  projectId: 'projectId',
  filename: 'filename',
  summary: 'summary',
  findings: 'findings',
  alerts: 'alerts',
  iocs: 'iocs',
  correlations: 'correlations',
  timeline: 'timeline',
  mitre: 'mitre',
  riskRanking: 'riskRanking',
  trafficIntelligence: 'trafficIntelligence',
  attackStory: 'attackStory',
  investigationPlan: 'investigationPlan',
  executiveReport: 'executiveReport',
  createdAt: 'createdAt'
};

exports.Prisma.NmapScanScalarFieldEnum = {
  id: 'id',
  projectId: 'projectId',
  target: 'target',
  profile: 'profile',
  resultJson: 'resultJson',
  rawOutput: 'rawOutput',
  createdAt: 'createdAt'
};

exports.Prisma.AssetScalarFieldEnum = {
  id: 'id',
  projectId: 'projectId',
  deviceType: 'deviceType',
  vendor: 'vendor',
  os: 'os',
  osVersion: 'osVersion',
  firstSeen: 'firstSeen',
  lastSeen: 'lastSeen',
  confidence: 'confidence',
  riskScore: 'riskScore',
  isManaged: 'isManaged',
  notes: 'notes',
  metadata: 'metadata',
  createdAt: 'createdAt',
  updatedAt: 'updatedAt'
};

exports.Prisma.AssetHostnameScalarFieldEnum = {
  id: 'id',
  assetId: 'assetId',
  hostname: 'hostname',
  isPrimary: 'isPrimary',
  confidence: 'confidence',
  firstSeen: 'firstSeen',
  lastSeen: 'lastSeen',
  source: 'source'
};

exports.Prisma.AssetIPAddressScalarFieldEnum = {
  id: 'id',
  assetId: 'assetId',
  ipAddress: 'ipAddress',
  isCurrent: 'isCurrent',
  firstSeen: 'firstSeen',
  lastSeen: 'lastSeen',
  source: 'source'
};

exports.Prisma.AssetMACScalarFieldEnum = {
  id: 'id',
  assetId: 'assetId',
  macAddress: 'macAddress',
  isCurrent: 'isCurrent',
  isPrimary: 'isPrimary',
  vendor: 'vendor',
  firstSeen: 'firstSeen',
  lastSeen: 'lastSeen',
  source: 'source'
};

exports.Prisma.AssetSSIDScalarFieldEnum = {
  id: 'id',
  assetId: 'assetId',
  ssid: 'ssid',
  isCurrent: 'isCurrent',
  firstSeen: 'firstSeen',
  lastSeen: 'lastSeen',
  source: 'source'
};

exports.Prisma.AssetPortScalarFieldEnum = {
  id: 'id',
  assetId: 'assetId',
  port: 'port',
  protocol: 'protocol',
  service: 'service',
  state: 'state',
  firstSeen: 'firstSeen',
  lastSeen: 'lastSeen'
};

exports.Prisma.AssetServiceScalarFieldEnum = {
  id: 'id',
  assetId: 'assetId',
  name: 'name',
  version: 'version',
  protocol: 'protocol',
  port: 'port',
  confidence: 'confidence'
};

exports.Prisma.AssetTagScalarFieldEnum = {
  id: 'id',
  assetId: 'assetId',
  tag: 'tag',
  createdAt: 'createdAt'
};

exports.Prisma.AssetFieldEvidenceScalarFieldEnum = {
  id: 'id',
  assetId: 'assetId',
  fieldName: 'fieldName',
  fieldValue: 'fieldValue',
  confidence: 'confidence',
  sourceType: 'sourceType',
  sourceId: 'sourceId',
  packetNumber: 'packetNumber',
  captureId: 'captureId',
  observedAt: 'observedAt',
  metadata: 'metadata'
};

exports.Prisma.AssetRelationshipScalarFieldEnum = {
  id: 'id',
  sourceId: 'sourceId',
  targetId: 'targetId',
  relationshipType: 'relationshipType',
  confidence: 'confidence',
  firstSeen: 'firstSeen',
  lastSeen: 'lastSeen',
  metadata: 'metadata'
};

exports.Prisma.RelationshipScalarFieldEnum = {
  id: 'id',
  projectId: 'projectId',
  sourceAssetId: 'sourceAssetId',
  targetAssetId: 'targetAssetId',
  relationshipType: 'relationshipType',
  protocol: 'protocol',
  port: 'port',
  direction: 'direction',
  state: 'state',
  relationshipKey: 'relationshipKey',
  packetCount: 'packetCount',
  byteCount: 'byteCount',
  firstSeen: 'firstSeen',
  lastSeen: 'lastSeen',
  confidence: 'confidence',
  lastEvidenceId: 'lastEvidenceId',
  engineVersion: 'engineVersion',
  metadata: 'metadata',
  createdAt: 'createdAt',
  updatedAt: 'updatedAt'
};

exports.Prisma.RelationshipEvidenceScalarFieldEnum = {
  id: 'id',
  relationshipId: 'relationshipId',
  evidenceId: 'evidenceId',
  captureId: 'captureId',
  packetNumber: 'packetNumber',
  sourceType: 'sourceType',
  observedAt: 'observedAt',
  metadata: 'metadata',
  createdAt: 'createdAt'
};

exports.Prisma.RelationshipHistoryScalarFieldEnum = {
  id: 'id',
  relationshipId: 'relationshipId',
  relationshipKey: 'relationshipKey',
  projectId: 'projectId',
  sourceAssetId: 'sourceAssetId',
  targetAssetId: 'targetAssetId',
  relationshipType: 'relationshipType',
  protocol: 'protocol',
  port: 'port',
  eventType: 'eventType',
  changedFields: 'changedFields',
  changeReason: 'changeReason',
  previousSnapshot: 'previousSnapshot',
  currentSnapshot: 'currentSnapshot',
  sequenceNumber: 'sequenceNumber',
  parentEventId: 'parentEventId',
  occurredAt: 'occurredAt',
  summary: 'summary',
  engineVersion: 'engineVersion',
  metadata: 'metadata',
  createdAt: 'createdAt'
};

exports.Prisma.SortOrder = {
  asc: 'asc',
  desc: 'desc'
};

exports.Prisma.NullsOrder = {
  first: 'first',
  last: 'last'
};


exports.Prisma.ModelName = {
  ScanRun: 'ScanRun',
  CaptureSession: 'CaptureSession',
  ReportArchive: 'ReportArchive',
  PcapInvestigation: 'PcapInvestigation',
  NmapScan: 'NmapScan',
  Asset: 'Asset',
  AssetHostname: 'AssetHostname',
  AssetIPAddress: 'AssetIPAddress',
  AssetMAC: 'AssetMAC',
  AssetSSID: 'AssetSSID',
  AssetPort: 'AssetPort',
  AssetService: 'AssetService',
  AssetTag: 'AssetTag',
  AssetFieldEvidence: 'AssetFieldEvidence',
  AssetRelationship: 'AssetRelationship',
  Relationship: 'Relationship',
  RelationshipEvidence: 'RelationshipEvidence',
  RelationshipHistory: 'RelationshipHistory'
};

/**
 * This is a stub Prisma Client that will error at runtime if called.
 */
class PrismaClient {
  constructor() {
    return new Proxy(this, {
      get(target, prop) {
        let message
        const runtime = getRuntime()
        if (runtime.isEdge) {
          message = `PrismaClient is not configured to run in ${runtime.prettyName}. In order to run Prisma Client on edge runtime, either:
- Use Prisma Accelerate: https://pris.ly/d/accelerate
- Use Driver Adapters: https://pris.ly/d/driver-adapters
`;
        } else {
          message = 'PrismaClient is unable to run in this browser environment, or has been bundled for the browser (running in `' + runtime.prettyName + '`).'
        }
        
        message += `
If this is unexpected, please open an issue: https://pris.ly/prisma-prisma-bug-report`

        throw new Error(message)
      }
    })
  }
}

exports.PrismaClient = PrismaClient

Object.assign(exports, Prisma)
