package com.github.lisama569.localvulnscanservicejava.scan;

/**
 * 归一化后的扫描错误。
 *
 * @param reason  可区分原因
 * @param ruleId  相关规则 id（非规则错误为 null）
 * @param message 可解释描述
 */
public record ScanError(ScanErrorReason reason, String ruleId, String message) {
}
