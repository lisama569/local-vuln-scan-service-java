package com.github.lisama569.localvulnscanservicejava.model;

import java.time.Instant;
import java.util.List;

/** 一次扫描的完整快照（运行中也可生成，findings 为空、状态为当前状态）。 */
public record ScanResult(
        String scanId,
        String artifactHash,
        String ruleSetVersion,
        ScanStatus status,
        ErrorCode errorCode,
        String errorMessage,
        ManifestFormat manifestFormat,
        int componentCount,
        List<ScanFinding> findings,
        List<RuleError> ruleErrors,
        Instant createdAt,
        Instant startedAt,
        Instant finishedAt) {
}
