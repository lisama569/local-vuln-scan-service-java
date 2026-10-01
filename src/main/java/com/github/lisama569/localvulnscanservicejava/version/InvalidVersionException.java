package com.github.lisama569.localvulnscanservicejava.version;

/** 版本号或版本区间不符合语义化版本语法。 */
public class InvalidVersionException extends IllegalArgumentException {
    public InvalidVersionException(String message) {
        super(message);
    }

    public InvalidVersionException(String message, Throwable cause) {
        super(message, cause);
    }
}
