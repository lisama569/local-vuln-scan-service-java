package com.github.lisama569.localvulnscanservicejava.scan;

import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;

/** 任务当前状态不允许该操作（如对已终态任务取消/重试）。 */
public class ScanStateConflictException extends RuntimeException {

    private final ErrorCode code;

    public ScanStateConflictException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }
}
