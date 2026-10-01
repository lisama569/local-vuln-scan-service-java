package com.github.lisama569.localvulnscanservicejava.parser;

import com.github.lisama569.localvulnscanservicejava.model.Manifest;

/** 单一格式的清单解析器。任何畸形条目都必须抛出 ManifestParseException，不得跳过。 */
public interface ManifestParser {

    Manifest parse(String content);
}
