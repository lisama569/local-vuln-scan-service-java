package com.github.lisama569.localvulnscanservicejava.tests;

import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.RuleSet;
import com.github.lisama569.localvulnscanservicejava.rules.RuleRepository;
import com.github.lisama569.localvulnscanservicejava.rules.RuleSetLoadException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 规则集加载校验、版本指纹与非法规则拒绝测试（使用临时 classpath 资源）。 */
class RuleRepositoryTest {

    private static final Logger log = LoggerFactory.getLogger(RuleRepositoryTest.class);

    private RuleRepository repoWith(String json) throws Exception {
        Path dir = Files.createTempDirectory("rules-test");
        Path file = dir.resolve("rules.json");
        Files.writeString(file, json, StandardCharsets.UTF_8);
        // 通过 file: 前缀走 ClassPathResource 的 URL 解析
        RuleRepository repo = new RuleRepository(file.toUri().toString());
        return repo;
    }

    @Test
    void loadsValidRulesetAndVersionIsHashPrefix() throws Exception {
        String json = """
                {"generatedAt":"2026-10-01T00:00:00Z","rules":[
                  {"id":"CVE-2","ecosystem":"npm","packageName":"b","range":">=1.0.0 <2.0.0","severity":"LOW","description":""},
                  {"id":"CVE-1","ecosystem":"maven","packageName":"a","range":">=1.0.0","severity":"HIGH","description":"x"}
                ]}
                """;
        RuleRepository repo = repoWith(json);
        RuleSet rs = repo.current();
        System.out.println("[规则集加载] version=" + rs.version() + ", rules=" + rs.rules());
        log.info("规则集版本={}, 规则数={}, contentHash={}", rs.version(), rs.rules().size(), rs.contentHash());
        assertEquals(2, rs.rules().size());
        // 规则按 id 排序，遍历顺序确定
        assertEquals("CVE-1", rs.rules().get(0).id());
        assertTrue(rs.contentHash().startsWith(rs.version()));
        // 缓存：同一实例重复加载返回同一个规则集快照
        assertSame(rs, repo.current());
    }

    @Test
    void rejectsInvalidRulesetsWithDistinguishableCodes() throws Exception {
        expectCode("syntax", "{not json", ErrorCode.RULESET_SYNTAX_INVALID);
        expectCode("rules-missing", "{}", ErrorCode.RULESET_MISSING_FIELD);
        expectCode("entry-missing-field",
                "{\"rules\":[{\"id\":\"X\",\"ecosystem\":\"maven\"}]}",
                ErrorCode.RULESET_MISSING_FIELD);
        expectCode("bad-range",
                "{\"rules\":[{\"id\":\"X\",\"ecosystem\":\"maven\",\"packageName\":\"a\","
                        + "\"range\":\">=banana\",\"severity\":\"HIGH\"}]}",
                ErrorCode.RULE_INVALID_VERSION_RANGE);
        expectCode("bad-severity",
                "{\"rules\":[{\"id\":\"X\",\"ecosystem\":\"maven\",\"packageName\":\"a\","
                        + "\"range\":\">=1.0.0\",\"severity\":\"URGENT\"}]}",
                ErrorCode.RULESET_MISSING_FIELD);
        expectCode("duplicate-id",
                "{\"rules\":["
                        + "{\"id\":\"X\",\"ecosystem\":\"maven\",\"packageName\":\"a\",\"range\":\"=1.0.0\",\"severity\":\"HIGH\"},"
                        + "{\"id\":\"X\",\"ecosystem\":\"npm\",\"packageName\":\"b\",\"range\":\"=1.0.0\",\"severity\":\"LOW\"}"
                        + "]}",
                ErrorCode.RULESET_SYNTAX_INVALID);
    }

    private void expectCode(String label, String json, ErrorCode expected) throws Exception {
        RuleRepository repo = repoWith(json);
        RuleSetLoadException ex = assertThrows(RuleSetLoadException.class, repo::current);
        System.out.println("[规则集拒绝] " + label + " => code=" + ex.code() + ", reason=" + ex.getMessage());
        log.info("规则集拒绝[{}]: code={}, reason={}", label, ex.code(), ex.getMessage());
        assertEquals(expected, ex.code());
    }
}
