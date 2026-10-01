package com.github.lisama569.localvulnscanservicejava.model;

/** 支持的清单 / SBOM 格式。 */
public enum ManifestFormat {
    INVENTORY_JSON,
    CYCLONEDX_JSON,
    SPDX_TAG_VALUE,
    CSV
}
