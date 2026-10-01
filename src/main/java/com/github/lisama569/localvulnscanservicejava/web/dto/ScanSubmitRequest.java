package com.github.lisama569.localvulnscanservicejava.web.dto;

/** POST /scans 请求体。content 为清单原文。 */
public record ScanSubmitRequest(String content) {
}
