package com.github.lisama569.localvulnscanservicejava.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.ManifestFormat;
import com.github.lisama569.localvulnscanservicejava.util.Hashes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 清单解析门面：先纯结构嗅探格式，再分派给对应解析器归一化。
 * 空内容（EMPTY_CONTENT）、不可识别（FORMAT_UNRECOGNIZED）在此被显式拒绝，
 * 绝不回退为“空清单成功”。
 */
@Service
public class ManifestParserService {

    private static final Logger log = LoggerFactory.getLogger(ManifestParserService.class);

    private final InventoryJsonParser inventoryJsonParser;
    private final CycloneDxJsonParser cycloneDxJsonParser;
    private final SpdxTagValueParser spdxTagValueParser;
    private final CsvManifestParser csvManifestParser;

    public ManifestParserService(ObjectMapper objectMapper) {
        this.inventoryJsonParser = new InventoryJsonParser(objectMapper);
        this.cycloneDxJsonParser = new CycloneDxJsonParser(objectMapper);
        this.spdxTagValueParser = new SpdxTagValueParser();
        this.csvManifestParser = new CsvManifestParser();
    }

    public ManifestFormat detectFormat(String content) {
        return FormatDetector.detect(content);
    }

    public Manifest parse(String content) {
        ManifestFormat format = FormatDetector.detect(content);
        Manifest manifest = switch (format) {
            case INVENTORY_JSON -> inventoryJsonParser.parse(content);
            case CYCLONEDX_JSON -> cycloneDxJsonParser.parse(content);
            case SPDX_TAG_VALUE -> spdxTagValueParser.parse(content);
            case CSV -> csvManifestParser.parse(content);
        };
        log.info("清单归一化完成: format={}, componentCount={}, hash={}",
                manifest.format(), manifest.components().size(), manifest.sourceHash());
        if (log.isDebugEnabled()) {
            log.debug("归一化组件: {}", manifest.components());
        }
        return manifest;
    }
}
