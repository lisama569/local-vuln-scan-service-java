package com.github.lisama569.localvulnscanservicejava.model;

/** 归一化后的依赖组件。rawVersion 保留原文，版本结构化在匹配阶段完成。 */
public record Component(Ecosystem ecosystem, String name, String rawVersion) {
}
