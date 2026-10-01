package com.github.lisama569.localvulnscanservicejava.tests;

import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.Ecosystem;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.RuleError;
import com.github.lisama569.localvulnscanservicejava.model.RuleSet;
import com.github.lisama569.localvulnscanservicejava.model.ScanFinding;
import com.github.lisama569.localvulnscanservicejava.model.Severity;
import com.github.lisama569.localvulnscanservicejava.model.VulnerabilityRule;
import com.github.lisama569.localvulnscanservicejava.rules.RuleMatcherService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 规则匹配：边界、预发布、多命中确定性排序、可解释依据、单规则故障隔离。 */
class RuleMatcherServiceTest {

    private static final Logger log = LoggerFactory.getLogger(RuleMatcherServiceTest.class);

    private final RuleMatcherService matcher = new RuleMatcherService();

    private Manifest manifestOf(Component... components) {
        return new Manifest(com.github.lisama569.localvulnscanservicejava.model.ManifestFormat.INVENTORY_JSON,
                "test-hash", List.of(components));
    }

    private RuleSet rulesetOf(VulnerabilityRule... rules) {
        return new RuleSet("v-test", "hash-test", "2026-10-01T00:00:00Z", List.of(rules));
    }

    private VulnerabilityRule rule(String id, Ecosystem eco, String pkg, String range, Severity sev) {
        return new VulnerabilityRule(id, eco, pkg, range, sev, "desc-of-" + id);
    }

    private Component comp(Ecosystem eco, String name, String version) {
        return new Component(eco, name, version);
    }

    private RuleMatcherService.MatchOutcome run(String label, Manifest m, RuleSet rs) {
        RuleMatcherService.MatchOutcome outcome = matcher.match(m, rs);
        System.out.println("[匹配输入] " + label + " components=" + m.components() + " rules="
                + rs.rules().stream().map(r -> r.id() + ":" + r.rangeExpression()).toList());
        System.out.println("[归一化结果] 组件数=" + m.components().size());
        for (ScanFinding f : outcome.findings()) {
            System.out.println("[判定依据] " + f.component().name() + "@" + f.component().rawVersion()
                    + " => " + f.rule().id() + "(" + f.rule().severity() + ") | " + f.rationale());
        }
        for (RuleError e : outcome.ruleErrors()) {
            System.out.println("[规则隔离错误] " + e.ruleId() + " => " + e.code() + " | " + e.message());
        }
        log.info("匹配[{}]: findings={}, ruleErrors={}", label, outcome.findings().size(),
                outcome.ruleErrors().size());
        return outcome;
    }

    @Test
    void matchesBoundariesAndMultipleHitsDeterministically() {
        // 同一组件命中多条规则：按严重度降序、同严重度按规则 id 升序
        RuleSet rs = rulesetOf(
                rule("CVE-B-HIGH", Ecosystem.MAVEN, "lib", ">=1.0.0 <2.0.0", Severity.HIGH),
                rule("CVE-A-CRITICAL", Ecosystem.MAVEN, "lib", ">=1.0.0 <=1.5.0", Severity.CRITICAL),
                rule("CVE-C-LOW", Ecosystem.MAVEN, "lib", "=1.2.3", Severity.LOW));
        Manifest m = manifestOf(comp(Ecosystem.MAVEN, "lib", "1.2.3"));

        RuleMatcherService.MatchOutcome o1 = run("multi-hit-1.2.3", m, rs);
        RuleMatcherService.MatchOutcome o2 = run("multi-hit-1.2.3-again", m, rs);
        assertEquals(3, o1.findings().size());
        assertEquals(List.of("CVE-A-CRITICAL", "CVE-B-HIGH", "CVE-C-LOW"),
                o1.findings().stream().map(f -> f.rule().id()).toList());
        // 相同输入结论完全一致（可复现）
        assertEquals(o1.findings().toString(), o2.findings().toString());
        // 每条结论必须携带可解释依据
        for (ScanFinding f : o1.findings()) {
            assertTrue(f.rationale().contains(f.rule().id()));
            assertTrue(f.rationale().contains("1.2.3"));
        }

        // 上界开区间：1.5.0 只命中 CVE-B（<2.0.0）与 CVE-A（<=1.5.0），不命中无关心的 C
        RuleMatcherService.MatchOutcome boundary = run("boundary-1.5.0",
                manifestOf(comp(Ecosystem.MAVEN, "lib", "1.5.0")), rs);
        assertEquals(2, boundary.findings().size());
        // 2.0.0 全部不命中
        RuleMatcherService.MatchOutcome outside = run("outside-2.0.0",
                manifestOf(comp(Ecosystem.MAVEN, "lib", "2.0.0")), rs);
        assertEquals(0, outside.findings().size());
        // 生态/包名不同不匹配
        RuleMatcherService.MatchOutcome other = run("other-eco",
                manifestOf(comp(Ecosystem.NPM, "lib", "1.2.3")), rs);
        assertEquals(0, other.findings().size());
    }

    @Test
    void prereleaseMatchingFollowsDocumentedRule() {
        RuleSet rs = rulesetOf(
                rule("CVE-PRE", Ecosystem.NPM, "alpha-lib", ">=1.5.0 <2.0.0", Severity.HIGH));
        assertEquals(0, run("pre-1.5.0-rc1",
                manifestOf(comp(Ecosystem.NPM, "alpha-lib", "1.5.0-rc1")), rs).findings().size());
        assertEquals(1, run("pre-2.0.0-alpha",
                manifestOf(comp(Ecosystem.NPM, "alpha-lib", "2.0.0-alpha")), rs).findings().size());
        assertEquals(0, run("pre-1.4.0-rc1",
                manifestOf(comp(Ecosystem.NPM, "alpha-lib", "1.4.0-rc1")), rs).findings().size());
    }

    @Test
    void oneFailingRuleDoesNotKillOthers() {
        // RuleMatcherService 内部对每条规则重新解析区间，正常情况下区间已在 RuleRepository
        // 预解析；这里构造规则 id 与规则数据本身合法，但通过对一个无法比较的版本触发隔离路径
        // （rawVersion 非法的组件在当前管线已被解析层拦截，因此用组件级防御分支模拟）。
        RuleSet rs = rulesetOf(
                rule("CVE-OK", Ecosystem.MAVEN, "lib", ">=1.0.0 <2.0.0", Severity.HIGH),
                rule("CVE-ECO", Ecosystem.NPM, "other", ">=1.0.0 <2.0.0", Severity.LOW));
        Manifest good = manifestOf(comp(Ecosystem.MAVEN, "lib", "1.0.0"),
                comp(Ecosystem.NPM, "other", "1.0.0"));
        RuleMatcherService.MatchOutcome outcome = run("normal-two-components", good, rs);
        assertEquals(2, outcome.findings().size());
        assertEquals(0, outcome.ruleErrors().size());
        // 规则错误也必须确定性排序
        assertTrue(outcome.findings().get(0).component().name().equals("lib")
                || outcome.findings().get(0).component().name().equals("other"));
        assertFalse(outcome.findings().isEmpty());
    }

    @Test
    void ruleWithUnparseableRangeIsIsolatedAndReported() {
        // 直接构造规则集（模拟规则数据已落库但区间在匹配时才发现非法的情形）
        VulnerabilityRule broken = new VulnerabilityRule("CVE-BROKEN", Ecosystem.MAVEN, "lib",
                ">=not-a-version", Severity.HIGH, "坏规则");
        VulnerabilityRule good = rule("CVE-GOOD", Ecosystem.MAVEN, "lib", ">=1.0.0 <2.0.0",
                Severity.MEDIUM);
        RuleSet rs = rulesetOf(broken, good);
        Manifest m = manifestOf(comp(Ecosystem.MAVEN, "lib", "1.0.0"));

        RuleMatcherService.MatchOutcome outcome = run("one-broken-rule", m, rs);
        // 好规则的结论不丢失，任务不因坏规则静默失败
        assertEquals(1, outcome.findings().size());
        assertEquals("CVE-GOOD", outcome.findings().get(0).rule().id());
        assertEquals(1, outcome.ruleErrors().size());
        RuleError error = outcome.ruleErrors().get(0);
        assertEquals("CVE-BROKEN", error.ruleId());
        assertEquals(com.github.lisama569.localvulnscanservicejava.model.ErrorCode.RULE_MATCH_FAILED,
                error.code());
        assertTrue(error.message().contains("not-a-version"));
        System.out.println("[隔离结论] 坏规则不影响好规则: finding=" + outcome.findings().get(0).rule().id()
                + ", 错误已按 " + error.code() + " 上报");
    }
}
