-- CreateTable
CREATE TABLE "url_shortener" (
    "id" TEXT NOT NULL,
    "shortCode" VARCHAR(8) NOT NULL,
    "originalUrl" TEXT NOT NULL,
    "userId" TEXT,
    "expiresAt" TIMESTAMP(3),
    "clickCount" INTEGER NOT NULL DEFAULT 0,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "url_shortener_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "url_shortener_shortCode_key" ON "url_shortener"("shortCode");

-- CreateIndex
CREATE INDEX "url_shortener_shortCode_idx" ON "url_shortener"("shortCode");

-- CreateIndex
CREATE INDEX "url_shortener_userId_idx" ON "url_shortener"("userId");

-- CreateIndex
CREATE INDEX "url_shortener_expiresAt_idx" ON "url_shortener"("expiresAt");

-- CreateIndex
CREATE INDEX "url_shortener_isActive_idx" ON "url_shortener"("isActive");

-- CreateIndex
CREATE INDEX "url_shortener_createdAt_idx" ON "url_shortener"("createdAt");

-- AddForeignKey
ALTER TABLE "url_shortener" ADD CONSTRAINT "url_shortener_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
