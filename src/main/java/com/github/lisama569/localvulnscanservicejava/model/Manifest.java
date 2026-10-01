package com.github.lisama569.localvulnscanservicejava.model;

import java.util.List;

/** 归一化清单：识别出的格式 + 组件列表（保持清单中的原始顺序）。 */
public record Manifest(ManifestFormat format, String sourceHash, List<Component> components) {
}
