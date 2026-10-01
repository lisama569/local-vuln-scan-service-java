package com.github.lisama569.localvulnscanservicejava.model;

import java.util.List;

/** 规则集：version 为内容哈希，扫描在提交时固定版本，保证历史可复现。 */
public record RuleSet(
        String version,
        String contentHash,
        String generatedAt,
        List<VulnerabilityRule> rules) {
}
