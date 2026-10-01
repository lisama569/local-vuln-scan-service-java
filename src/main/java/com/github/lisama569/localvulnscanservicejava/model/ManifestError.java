package com.github.lisama569.localvulnscanservicejava.model;

/**
 * 清单解析中的单条错误，携带可区分原因与定位信息。
 *
 * @param reason     归一化后的拒绝原因
 * @param entryIndex 出错条目在清单中的序号（文档级错误为 -1）
 * @param message    面向调用方的可解释描述
 */
public record ManifestError(RejectionReason reason, int entryIndex, String message) {
}
