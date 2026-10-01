package com.github.lisama569.localvulnscanservicejava.tests;

import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.rules.MatchEngine;
import com.github.lisama569.localvulnscanservicejava.rules.RuleSet;
import com.github.lisama569.localvulnscanservicejava.rules.VulnerabilityRule;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 规则匹配：多规则命中的确定性结论与单规则出错隔离。 */
class MatchEngineTest {

    private static final Logger log = LoggerFactory.getLogger(MatchEngineTest.class);

    private final MatchEngine engine = new MatchEngine();

    private static VulnerabilityRule rule(String id, String severity, String range) {
        return new VulnerabilityRule(id, "CVE-TEST-" + id, "maven", "demo", range, severity, "test rule " + id);
    }

    @Test
    void multipleHitsDeterministicallyOrdered() {
        RuleSet rs = new RuleSet("t1", List.of(
                rule("R-LOW", "LOW", "<9.0.0"),
                rule("R-CRIT", "CRITICAL", "[1.0.0,2.0.0)"),
                rule("R-HIGH", "HIGH", ">=1.5.0")));
        Component c = new Component("maven", "demo", "1.6.0");
        MatchEngine.MatchOutcome outcome = engine.match(rs, c);
        log.info("输入: component={} rules={} | 命中: {} | 判定依据: {}",
                c, rs.rules().stream().map(VulnerabilityRule::ruleId).toList(),
                outcome.matches().stream().map(m -> m.rule().ruleId()).toList(),
                outcome.matches().stream().map(MatchEngine.RuleMatch::explanation).toList());
        // 确定性：严重度降序，同级 ruleId 升序
        assertEquals(List.of("R-CRIT", "R-HIGH", "R-LOW"),
                outcome.matches().stream().map(m -> m.rule().ruleId()).toList());
        assertTrue(outcome.errors().isEmpty());
        // 重复执行结论一致
        MatchEngine.MatchOutcome again = engine.match(rs, c);
        assertEquals(outcome.matches().stream().map(m -> m.rule().ruleId()).toList(),
                again.matches().stream().map(m -> m.rule().ruleId()).toList());
    }

    @Test
    void brokenRuleIsolatedFromOthers() {
        RuleSet rs = new RuleSet("t2", List.of(
                rule("R-BROKEN", "HIGH", "[1.0.0,2.0.0"),   // 非法区间
                rule("R-OK", "MEDIUM", "<2.0.0")));
        Component c = new Component("maven", "demo", "1.5.0");
        MatchEngine.MatchOutcome outcome = engine.match(rs, c);
        log.info("输入: component={} | 命中: {} | 隔离错误: {}",
                c,
                outcome.matches().stream().map(m -> m.rule().ruleId()).toList(),
                outcome.errors().stream().map(e -> e.ruleId() + ": " + e.getMessage()).toList());
        assertEquals(List.of("R-OK"), outcome.matches().stream().map(m -> m.rule().ruleId()).toList());
        assertEquals(1, outcome.errors().size());
        assertEquals("R-BROKEN", outcome.errors().get(0).ruleId());
    }

    @Test
    void ecosystemAndNameMustMatch() {
        RuleSet rs = new RuleSet("t3", List.of(rule("R-1", "HIGH", "<2.0.0")));
        assertTrue(engine.match(rs, new Component("npm", "demo", "1.0.0")).matches().isEmpty());
        assertTrue(engine.match(rs, new Component("maven", "other", "1.0.0")).matches().isEmpty());
        assertEquals(1, engine.match(rs, new Component("MAVEN", "demo", "1.0.0")).matches().size());
    }

    @Test
    void prereleaseBoundaryExplained() {
        RuleSet rs = new RuleSet("t4", List.of(rule("R-1", "HIGH", "<2.0.0")));
        Component pre = new Component("maven", "demo", "2.0.0-rc1");
        MatchEngine.MatchOutcome outcome = engine.match(rs, pre);
        log.info("输入: component={} | 命中: {} | 判定依据: {}",
                pre,
                outcome.matches().stream().map(m -> m.rule().ruleId()).toList(),
                outcome.matches().stream().map(MatchEngine.RuleMatch::explanation).toList());
        // 2.0.0-rc1 < 2.0.0，故命中 <2.0.0
        assertEquals(1, outcome.matches().size());
        assertTrue(outcome.matches().get(0).explanation().contains("2.0.0-rc1"));
    }
}
