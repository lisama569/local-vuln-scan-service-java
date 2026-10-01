package com.github.lisama569.localvulnscanservicejava.parser;

import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;

/** 清单解析的可区分拒绝异常（畸形/缺字段/格式不可识别等）。 */
public class ManifestParseException extends RuntimeException {

    private final ErrorCode code;

    public ManifestParseException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public ManifestParseException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }
}
