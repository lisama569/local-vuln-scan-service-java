package com.github.lisama569.localvulnscanservicejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.ManifestFormat;
import com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException;
import com.github.lisama569.localvulnscanservicejava.parser.ManifestParserService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 四种清单格式的正常归一化与异常输入拒绝测试。
 * 每个用例都打印：原始输入（截断）、归一化结果或拒绝 code/message。
 */
class ManifestParserTest {

    private static final Logger log = LoggerFactory.getLogger(ManifestParserTest.class);

    private final ManifestParserService service = new ManifestParserService(new ObjectMapper());

    private void logInput(String label, String input) {
        String shown = input.length() > 160 ? input.substring(0, 160) + "..." : input;
        System.out.println("[清单输入] " + label + " => " + shown.replace("\n", "\\n"));
        log.info("清单输入[{}]: {}", label, shown);
    }

    private void logNormalized(Manifest m) {
        System.out.println("[归一化结果] format=" + m.format() + ", count=" + m.components().size()
                + ", components=" + m.components());
        log.info("归一化结果 format={}, hash={}, components={}",
                m.format(), m.sourceHash(), m.components());
    }

    private Manifest parse(String label, String content) {
        logInput(label, content);
        Manifest m = service.parse(content);
        logNormalized(m);
        return m;
    }

    private void assertRejected(String label, String content,
                                com.github.lisama569.localvulnscanservicejava.model.ErrorCode expected) {
        logInput(label, content);
        ManifestParseException ex = assertThrows(ManifestParseException.class, () -> service.parse(content));
        System.out.println("[拒绝归类] " + label + " => code=" + ex.code() + ", reason=" + ex.getMessage());
        log.info("拒绝归类[{}]: code={}, reason={}", label, ex.code(), ex.getMessage());
        assertEquals(expected, ex.code(), "拒绝原因必须可区分且归类正确: " + label);
    }

    @Test
    void parsesAllFourFormats() {
        String inventory = """
                {"components":[
                  {"ecosystem":"maven","name":"log4j-core","version":"2.14.0"},
                  {"ecosystem":"npm","name":"lodash","version":"4.17.20"}
                ]}
                """;
        Manifest m1 = parse("inventory-json", inventory);
        assertEquals(ManifestFormat.INVENTORY_JSON, m1.format());
        assertEquals(2, m1.components().size());
        assertEquals("log4j-core", m1.components().get(0).name());

        String cdx = """
                {"bomFormat":"CycloneDX","specVersion":"1.5","components":[
                  {"type":"library","purl":"pkg:maven/com.fasterxml/jackson@2.14.2"},
                  {"type":"library","ecosystem":"pypi","name":"requests","version":"2.28.0"}
                ]}
                """;
        Manifest m2 = parse("cyclonedx-json", cdx);
        assertEquals(ManifestFormat.CYCLONEDX_JSON, m2.format());
        assertEquals(2, m2.components().size());
        assertEquals("jackson", m2.components().get(0).name());

        String spdx = """
                SPDXVersion: SPDX-2.3
                DataLicense: CC0-1.0
                PackageName: left-pad
                PackageVersion: 1.2.3
                ExternalRef: PURL pkg:npm/left-pad@1.2.3

                PackageName: commons-text
                ExternalRef: PURL pkg:maven/org.apache.commons/commons-text@1.9.0
                """;
        Manifest m3 = parse("spdx-tag-value", spdx);
        assertEquals(ManifestFormat.SPDX_TAG_VALUE, m3.format());
        assertEquals(2, m3.components().size());
        assertEquals("commons-text", m3.components().get(1).name());

        String csv = """
                ecosystem,name,version
                maven,netty-codec-http,4.1.50
                npm,lodash,4.17.21
                """;
        Manifest m4 = parse("csv", csv);
        assertEquals(ManifestFormat.CSV, m4.format());
        assertEquals(2, m4.components().size());
        // 合法空清单（表头存在但无数据行）必须成功，而不是被当错误
        Manifest empty = parse("csv-empty", "ecosystem,name,version\n");
        assertEquals(0, empty.components().size());
    }

    @Test
    void rejectsMalformedInputsWithDistinguishableCodes() {
        assertRejected("empty", "",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.EMPTY_CONTENT);
        assertRejected("blank", "   \n\t ",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.EMPTY_CONTENT);
        assertRejected("unrecognized-yaml", "components:\n  - log4j-core: 2.14\n",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.FORMAT_UNRECOGNIZED);
        assertRejected("json-without-markers", "{\"foo\":\"bar\"}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.FORMAT_UNRECOGNIZED);
        assertRejected("broken-json", "{\"components\": [",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_SYNTAX_INVALID);
        assertRejected("components-not-array",
                "{\"components\":{\"ecosystem\":\"maven\"}}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_ENTRY_MALFORMED);
        assertRejected("empty-object-no-marker", "{}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.FORMAT_UNRECOGNIZED);
        assertRejected("entry-missing-version",
                "{\"components\":[{\"ecosystem\":\"maven\",\"name\":\"log4j-core\"}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_MISSING_FIELD);
        assertRejected("entry-empty-name",
                "{\"components\":[{\"ecosystem\":\"maven\",\"name\":\"  \",\"version\":\"1.0.0\"}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_MISSING_FIELD);
        assertRejected("entry-not-object", "{\"components\":[\"oops\"]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_ENTRY_MALFORMED);
        assertRejected("bad-ecosystem",
                "{\"components\":[{\"ecosystem\":\"cargo\",\"name\":\"x\",\"version\":\"1.0.0\"}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_ENTRY_MALFORMED);
        assertRejected("invalid-version-leading-zero",
                "{\"components\":[{\"ecosystem\":\"maven\",\"name\":\"x\",\"version\":\"01.2.3\"}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_VERSION_INVALID);
        assertRejected("invalid-version-garbage",
                "{\"components\":[{\"ecosystem\":\"maven\",\"name\":\"x\",\"version\":\"latest\"}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_VERSION_INVALID);
        assertRejected("number-typed-field",
                "{\"components\":[{\"ecosystem\":\"maven\",\"name\":\"x\",\"version\":12}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_ENTRY_MALFORMED);
    }

    @Test
    void rejectsCycloneDxAndSpdxAndCsvDefects() {
        assertRejected("cdx-wrong-bomformat",
                "{\"bomFormat\":\"SPDX\",\"components\":[]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.FORMAT_UNRECOGNIZED);
        assertRejected("cdx-no-identity",
                "{\"bomFormat\":\"CycloneDX\",\"components\":[{\"version\":\"1.0.0\"}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_MISSING_FIELD);
        assertRejected("cdx-bad-purl-type",
                "{\"bomFormat\":\"CycloneDX\",\"components\":[{\"purl\":\"pkg:cargo/x@1.0.0\"}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_ENTRY_MALFORMED);
        assertRejected("cdx-purl-no-version",
                "{\"bomFormat\":\"CycloneDX\",\"components\":[{\"purl\":\"pkg:npm/x\"}]}",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_MISSING_FIELD);
        assertRejected("spdx-missing-header",
                "PackageName: x\nPackageVersion: 1.0.0\n",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.FORMAT_UNRECOGNIZED);
        assertRejected("spdx-garbage-line",
                "SPDXVersion: SPDX-2.3\nthis line has no colon tag\n",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_SYNTAX_INVALID);
        assertRejected("spdx-package-no-version",
                "SPDXVersion: SPDX-2.3\nPackageName: x\n",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_MISSING_FIELD);
        // 表头列名被错列：嗅探阶段无法识别为 CSV（真实 CSV 表头必须是 ecosystem,name,version）
        assertRejected("csv-wrong-header",
                "name,ecosystem,version\nx,maven,1.0.0\n",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.FORMAT_UNRECOGNIZED);
        assertRejected("csv-wrong-column-count",
                "ecosystem,name,version\nmaven,x,1.0.0,extra\n",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_ENTRY_MALFORMED);
        assertRejected("csv-unterminated-quote",
                "ecosystem,name,version\nmaven,\"unterminated,1.0.0\n",
                com.github.lisama569.localvulnscanservicejava.model.ErrorCode.MANIFEST_SYNTAX_INVALID);
    }

    @Test
    void bomDoesNotConfuseDetection() {
        String withBom = "﻿{\"components\":[{\"ecosystem\":\"npm\",\"name\":\"x\",\"version\":\"1.0.0\"}]}";
        Manifest m = parse("utf8-bom-inventory", withBom);
        assertEquals(ManifestFormat.INVENTORY_JSON, m.format());
        assertTrue(m.sourceHash().length() == 64);
    }
}
