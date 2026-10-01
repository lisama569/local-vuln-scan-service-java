package com.github.lisama569.localvulnscanservicejava.scan;

/** 扫描执行期错误的归一化原因。 */
public enum ScanErrorReason {
    /** 清单被拒绝（解析阶段）。 */
    MANIFEST_REJECTED,
    /** 单条规则求值失败（不影响其他规则）。 */
    RULE_EVALUATION_FAILED,
    /** 组件版本无法解析，无法参与匹配。 */
    COMPONENT_VERSION_INVALID,
    /** 未预期的内部错误。 */
    INTERNAL_ERROR
}
