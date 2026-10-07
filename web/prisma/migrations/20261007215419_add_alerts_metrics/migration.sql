/*
  Warnings:

  - You are about to drop the column `prediction` on the `Scan` table. All the data in the column will be lost.
  - Added the required column `isThreat` to the `Scan` table without a default value. This is not possible if the table is not empty.
  - Added the required column `label` to the `Scan` table without a default value. This is not possible if the table is not empty.
  - Changed the type of `type` on the `Scan` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Made the column `confidence` on table `Scan` required. This step will fail if there are existing NULL values in that column.
  - Made the column `threatScore` on table `Scan` required. This step will fail if there are existing NULL values in that column.

*/
-- CreateEnum
CREATE TYPE "ScanType" AS ENUM ('URL', 'TEXT', 'NETWORK');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "AlertStatus" AS ENUM ('OPEN', 'ACKNOWLEDGED', 'RESOLVED');

-- DropIndex
DROP INDEX "Scan_type_idx";

-- AlterTable
ALTER TABLE "Scan" DROP COLUMN "prediction",
ADD COLUMN     "details" JSONB,
ADD COLUMN     "isDemo" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "isThreat" BOOLEAN NOT NULL,
ADD COLUMN     "label" TEXT NOT NULL,
ADD COLUMN     "mock" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "modelVersion" TEXT NOT NULL DEFAULT 'unknown',
ADD COLUMN     "severity" "Severity" NOT NULL DEFAULT 'NONE',
DROP COLUMN "type",
ADD COLUMN     "type" "ScanType" NOT NULL,
ALTER COLUMN "confidence" SET NOT NULL,
ALTER COLUMN "threatScore" SET NOT NULL;

-- CreateTable
CREATE TABLE "Alert" (
    "id" TEXT NOT NULL,
    "scanId" TEXT,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "attackType" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "status" "AlertStatus" NOT NULL DEFAULT 'OPEN',
    "recommendedAction" TEXT NOT NULL,
    "source" "ScanType" NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),

    CONSTRAINT "Alert_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ModelMetric" (
    "id" TEXT NOT NULL,
    "modelKey" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "task" TEXT NOT NULL,
    "dataset" TEXT NOT NULL,
    "isBaseline" BOOLEAN NOT NULL DEFAULT false,
    "served" BOOLEAN NOT NULL DEFAULT false,
    "nTest" INTEGER NOT NULL,
    "accuracy" DOUBLE PRECISION NOT NULL,
    "precisionMacro" DOUBLE PRECISION NOT NULL,
    "recallMacro" DOUBLE PRECISION NOT NULL,
    "f1Macro" DOUBLE PRECISION NOT NULL,
    "labels" JSONB NOT NULL,
    "confusionMatrix" JSONB NOT NULL,
    "perClass" JSONB NOT NULL,
    "extra" JSONB,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ModelMetric_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Alert_status_createdAt_idx" ON "Alert"("status", "createdAt");

-- CreateIndex
CREATE INDEX "Alert_severity_idx" ON "Alert"("severity");

-- CreateIndex
CREATE INDEX "Alert_scanId_idx" ON "Alert"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "ModelMetric_modelKey_key" ON "ModelMetric"("modelKey");

-- CreateIndex
CREATE INDEX "Scan_type_isThreat_idx" ON "Scan"("type", "isThreat");

-- AddForeignKey
ALTER TABLE "Alert" ADD CONSTRAINT "Alert_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;
