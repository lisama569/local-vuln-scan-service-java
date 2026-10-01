package com.github.lisama569.localvulnscanservicejava.version;

/** 版本字符串或版本区间无法解析时抛出。 */
public class InvalidVersionException extends RuntimeException {
    public InvalidVersionException(String message) {
        super(message);
    }
}
