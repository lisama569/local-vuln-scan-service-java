package com.github.lisama569.localvulnscanservicejava.model;

import java.util.List;

/**
 * 清单解析结果：识别出的格式 + 归一化组件列表。
 */
public record ParsedManifest(String format, List<Component> components) {
}
