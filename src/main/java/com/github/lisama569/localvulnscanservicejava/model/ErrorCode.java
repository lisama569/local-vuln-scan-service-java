package com.github.lisama569.localvulnscanservicejava.model;

/**
 * 所有失败路径的可区分原因码。任何拒绝 / 失败都必须携带其中之一，
 * 不允许把异常输入静默当成空结果成功返回。
 */
public enum ErrorCode {
    EMPTY_CONTENT("提交内容为空"),
    FORMAT_UNRECOGNIZED("清单格式无法识别"),
    MANIFEST_SYNTAX_INVALID("清单语法非法，无法解析"),
    MANIFEST_MISSING_FIELD("清单条目缺少必填字段"),
    MANIFEST_ENTRY_MALFORMED("清单条目结构畸形"),
    MANIFEST_VERSION_INVALID("清单条目的版本号不符合语义化版本"),
    RULESET_SYNTAX_INVALID("规则集文件语法非法"),
    RULESET_MISSING_FIELD("规则集条目缺少必填字段"),
    RULE_INVALID_VERSION_RANGE("规则的受影响版本区间非法"),
    RULE_MATCH_FAILED("单条规则匹配时异常，已隔离不影响其他规则"),
    SCAN_INTERNAL_ERROR("扫描执行过程中出现未归类内部错误"),
    TASK_NOT_FOUND("扫描任务不存在"),
    TASK_ALREADY_FINISHED("任务已终态，无法执行该操作");

    private final String description;

    ErrorCode(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
