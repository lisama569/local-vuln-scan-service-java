package com.github.lisama569.localvulnscanservicejava.model;

/** 一条命中结论，rationale 记录判定依据（区间、边界、预发布处理）。 */
public record ScanFinding(Component component, VulnerabilityRule rule, String rationale) {
}
