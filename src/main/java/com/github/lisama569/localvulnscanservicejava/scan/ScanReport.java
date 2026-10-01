package com.github.lisama569.localvulnscanservicejava.scan;

import java.util.List;

/**
 * 扫描报告。记录 rulesetVersion 与输入摘要，保证历史结论可复现。
 */
public record ScanReport(String taskId,
                         String artifactDigest,
                         String manifestFormat,
                         String rulesetVersion,
                         List<Finding> findings,
                         List<ScanError> errors) {
}
