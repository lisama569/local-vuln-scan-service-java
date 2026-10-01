package com.github.lisama569.localvulnscanservicejava.rules;

import java.util.List;

/**
 * 某一版本的规则集快照。扫描报告记录 rulesetVersion 以复现历史结论。
 */
public record RuleSet(String rulesetVersion, List<VulnerabilityRule> rules) {
}
