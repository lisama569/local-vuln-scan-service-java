package com.github.lisama569.localvulnscanservicejava.model;

/** 单条规则的归一化错误，隔离上报，不使整个任务失败。 */
public record RuleError(String ruleId, ErrorCode code, String message) {
}
