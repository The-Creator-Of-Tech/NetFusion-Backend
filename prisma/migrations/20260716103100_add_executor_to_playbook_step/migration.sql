-- AlterTable
ALTER TABLE "playbook_steps" ADD COLUMN     "executor" TEXT;

-- AlterTable
ALTER TABLE "timeline_events" DROP COLUMN "executionId",
DROP COLUMN "severity",
DROP COLUMN "source",
ADD COLUMN     "eventTimestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "type" "TimelineEventType" NOT NULL DEFAULT 'OBSERVED',
ALTER COLUMN "investigationId" SET NOT NULL;
