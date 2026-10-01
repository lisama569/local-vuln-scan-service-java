package com.github.lisama569.localvulnscanservicejava.rules;

import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;

/** 规则集文件无法加载 / 语法非法 / 区间非法。 */
public class RuleSetLoadException extends RuntimeException {

    private final ErrorCode code;

    public RuleSetLoadException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public RuleSetLoadException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }
}
