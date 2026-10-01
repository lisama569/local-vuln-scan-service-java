package com.github.lisama569.localvulnscanservicejava.tests;

import com.github.lisama569.localvulnscanservicejava.manifest.CsvManifestParser;
import com.github.lisama569.localvulnscanservicejava.manifest.CycloneDxJsonParser;
import com.github.lisama569.localvulnscanservicejava.manifest.ManifestParseException;
import com.github.lisama569.localvulnscanservicejava.manifest.ManifestParserRegistry;
import com.github.lisama569.localvulnscanservicejava.manifest.SpdxJsonParser;
import com.github.lisama569.localvulnscanservicejava.model.ManifestError;
import com.github.lisama569.localvulnscanservicejava.model.ParsedManifest;
import com.github.lisama569.localvulnscanservicejava.model.RejectionReason;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 清单解析：多格式归一、畸形输入的可区分拒绝原因。 */
class ManifestParserTest {

    private static final Logger log = LoggerFactory.getLogger(ManifestParserTest.class);

    private final ManifestParserRegistry registry = new ManifestParserRegistry(
            List.of(new CycloneDxJsonParser(), new SpdxJsonParser(), new CsvManifestParser()));

    private Set<RejectionReason> reasonsOf(String content) {
        ManifestParseException e = assertThrows(ManifestParseException.class,
                () -> registry.parse(content));
        Set<RejectionReason> reasons = e.errors().stream()
                .map(ManifestError::reason).collect(Collectors.toSet());
        log.info("输入: {} | 拒绝原因: {} | 明细: {}",
                abbrev(content), reasons, e.errors());
        return reasons;
    }

    private static String abbrev(String s) {
        String oneLine = s.replaceAll("\\s+", " ").trim();
        return oneLine.length() > 80 ? oneLine.substring(0, 80) + "..." : oneLine;
    }

    @Test
    void cycloneDxNormalized() {
        String content = """
                {"bomFormat":"CycloneDX","specVersion":"1.5","components":[
                  {"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
                  {"name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}
                ]}""";
        ParsedManifest parsed = registry.parse(content);
        log.info("输入: {} | 归一化: format={} components={}", abbrev(content), parsed.format(), parsed.components());
        assertEquals("cyclonedx-json", parsed.format());
        assertEquals(2, parsed.components().size());
        assertEquals("maven", parsed.components().get(0).ecosystem());
        assertEquals("npm", parsed.components().get(1).ecosystem());
    }

    @Test
    void spdxNormalized() {
        String content = """
                {"spdxVersion":"SPDX-2.3","packages":[
                  {"name":"requests","versionInfo":"2.30.0",
                   "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/requests@2.30.0"}]}
                ]}""";
        ParsedManifest parsed = registry.parse(content);
        log.info("输入: {} | 归一化: format={} components={}", abbrev(content), parsed.format(), parsed.components());
        assertEquals("spdx-json", parsed.format());
        assertEquals("pypi", parsed.components().get(0).ecosystem());
        assertEquals("requests", parsed.components().get(0).name());
    }

    @Test
    void csvNormalized() {
        String content = "ecosystem,name,version\nmaven,log4j-core,2.14.1\nnpm,lodash,4.17.20\n";
        ParsedManifest parsed = registry.parse(content);
        log.info("输入: {} | 归一化: format={} components={}", abbrev(content), parsed.format(), parsed.components());
        assertEquals("csv", parsed.format());
        assertEquals(2, parsed.components().size());
    }

    @Test
    void unrecognizedFormatRejectedNotTreatedAsEmpty() {
        Set<RejectionReason> reasons = reasonsOf("this is not a manifest at all");
        assertEquals(Set.of(RejectionReason.UNRECOGNIZED_FORMAT), reasons);
        // 空内容同样不得当成空清单成功
        assertEquals(Set.of(RejectionReason.UNRECOGNIZED_FORMAT), reasonsOf("   "));
        // 无 bomFormat/spdxVersion 标记的 JSON 也不识别
        assertEquals(Set.of(RejectionReason.UNRECOGNIZED_FORMAT), reasonsOf("{\"foo\":1}"));
    }

    @Test
    void malformedJsonDocumentRejected() {
        Set<RejectionReason> reasons = reasonsOf("{\"bomFormat\":\"CycloneDX\",\"components\":[");
        assertEquals(Set.of(RejectionReason.MALFORMED_DOCUMENT), reasons);
    }

    @Test
    void missingFieldsRejectedPerEntry() {
        String content = """
                {"bomFormat":"CycloneDX","components":[
                  {"version":"1.0.0"},
                  {"name":"no-version"}
                ]}""";
        Set<RejectionReason> reasons = reasonsOf(content);
        assertEquals(Set.of(RejectionReason.MISSING_FIELD), reasons);
    }

    @Test
    void invalidVersionRejectedPerEntry() {
        String content = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"a","version":"1.2.x"},
                  {"name":"b","version":"1.0.0"}
                ]}""";
        ManifestParseException e = assertThrows(ManifestParseException.class,
                () -> registry.parse(content));
        log.info("输入: {} | 错误明细: {}", abbrev(content), e.errors());
        assertEquals(1, e.errors().size());
        assertEquals(RejectionReason.INVALID_VERSION, e.errors().get(0).reason());
        assertEquals(0, e.errors().get(0).entryIndex());
    }

    @Test
    void csvMalformedEntryRejected() {
        String content = "ecosystem,name,version\nmaven,only-two-columns\nnpm,lodash,4.17.20,extra\n";
        Set<RejectionReason> reasons = reasonsOf(content);
        assertEquals(Set.of(RejectionReason.MALFORMED_ENTRY), reasons);
    }

    @Test
    void csvMissingHeaderRejected() {
        Set<RejectionReason> reasons = reasonsOf("maven,log4j-core,2.14.1\n");
        // 无表头 -> 格式无法识别（不是空清单成功）
        assertEquals(Set.of(RejectionReason.UNRECOGNIZED_FORMAT), reasons);
    }

    @Test
    void mixedErrorsAllReported() {
        String content = """
                {"bomFormat":"CycloneDX","components":[
                  {"version":"1.0.0"},
                  {"name":"bad","version":"x.y"},
                  {"name":"ok","version":"1.0.0"}
                ]}""";
        ManifestParseException e = assertThrows(ManifestParseException.class,
                () -> registry.parse(content));
        log.info("输入: {} | 错误明细: {}", abbrev(content), e.errors());
        assertEquals(2, e.errors().size());
        assertTrue(e.errors().stream().anyMatch(err -> err.reason() == RejectionReason.MISSING_FIELD));
        assertTrue(e.errors().stream().anyMatch(err -> err.reason() == RejectionReason.INVALID_VERSION));
    }
}
