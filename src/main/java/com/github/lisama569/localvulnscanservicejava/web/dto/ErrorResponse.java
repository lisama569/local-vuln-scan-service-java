package com.github.lisama569.localvulnscanservicejava.web.dto;

/** 统一错误响应：可区分的 code + 可读 message。 */
public record ErrorResponse(String code, String message) {
}
