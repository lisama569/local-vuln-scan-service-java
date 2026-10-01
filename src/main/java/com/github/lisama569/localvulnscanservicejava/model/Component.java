package com.github.lisama569.localvulnscanservicejava.model;

/**
 * 归一化后的统一组件模型。
 *
 * @param ecosystem 生态（如 maven / npm / pypi）
 * @param name      包名
 * @param version   原始版本字符串（匹配前会解析为 SemVersion）
 */
public record Component(String ecosystem, String name, String version) {
}
