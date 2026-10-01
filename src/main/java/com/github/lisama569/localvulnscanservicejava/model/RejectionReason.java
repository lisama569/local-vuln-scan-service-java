package com.github.lisama569.localvulnscanservicejava.model;

/** 可区分的输入拒绝原因。 */
public enum RejectionReason {
    /** 内容无法识别为任何支持的清单格式。 */
    UNRECOGNIZED_FORMAT,
    /** 文档整体畸形（如 JSON 无法解析、CSV 无表头）。 */
    MALFORMED_DOCUMENT,
    /** 单条依赖条目畸形（无法归一化为组件）。 */
    MALFORMED_ENTRY,
    /** 必填字段缺失（如 name/version/ecosystem）。 */
    MISSING_FIELD,
    /** 版本字符串或版本区间非法。 */
    INVALID_VERSION
}
