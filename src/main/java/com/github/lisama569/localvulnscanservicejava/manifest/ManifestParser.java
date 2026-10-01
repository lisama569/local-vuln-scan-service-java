package com.github.lisama569.localvulnscanservicejava.manifest;

import com.github.lisama569.localvulnscanservicejava.model.ParsedManifest;

/** 单格式清单解析器。 */
public interface ManifestParser {

    /** 该解析器负责的格式名（如 cyclonedx-json）。 */
    String format();

    /** 试探内容是否属于本格式（不抛异常）。 */
    boolean supports(String content);

    /** 解析并归一化；任何畸形都通过 ManifestParseException 上报，不得静默跳过。 */
    ParsedManifest parse(String content);
}
