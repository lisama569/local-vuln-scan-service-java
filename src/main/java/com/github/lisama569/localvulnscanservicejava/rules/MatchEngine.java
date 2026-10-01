package com.github.lisama569.localvulnscanservicejava.rules;

import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.version.SemVersion;
import com.github.lisama569.localvulnscanservicejava.version.VersionRange;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * 基于规则集的漏洞匹配引擎。
 * 结论确定性：命中结果按 (严重度降序, ruleId 升序) 排序；
 * 单条规则出错被隔离进 errors，不影响其他规则的判定。
 */
@Service
public class MatchEngine {

    /** 匹配结果：命中的规则 + 判定依据。 */
    public record RuleMatch(VulnerabilityRule rule, String explanation) {
    }

    /** 单组件匹配产出：命中列表 + 被隔离的规则错误。 */
    public record MatchOutcome(List<RuleMatch> matches, List<RuleEvaluationException> errors) {
    }

    private static final Map<String, Integer> SEVERITY_RANK = Map.of(
            "CRITICAL", 4, "HIGH", 3, "MEDIUM", 2, "LOW", 1);

    public static int severityRank(String severity) {
        return SEVERITY_RANK.getOrDefault(severity == null ? "" : severity.toUpperCase(), 0);
    }

    /**
     * 对单个组件执行全部规则。
     * 组件版本无法解析时抛出 InvalidVersionException（由调用方归一化）。
     */
    public MatchOutcome match(RuleSet ruleSet, Component component) {
        SemVersion version = SemVersion.parse(component.version());
        List<RuleMatch> matches = new ArrayList<>();
        List<RuleEvaluationException> errors = new ArrayList<>();
        for (VulnerabilityRule rule : ruleSet.rules()) {
            if (!rule.ecosystem().equalsIgnoreCase(component.ecosystem())
                    || !rule.packageName().equals(component.name())) {
                continue;
            }
            try {
                VersionRange range = VersionRange.parse(rule.rangeSpec());
                if (range.contains(version)) {
                    matches.add(new RuleMatch(rule, String.format(
                            "%s %s@%s 命中规则 %s：版本 %s 落入区间 %s（%s）",
                            component.ecosystem(), component.name(), component.version(),
                            rule.ruleId(), component.version(), rule.rangeSpec(), rule.vulnId())));
                }
            } catch (RuntimeException e) {
                // 单条规则出错不影响其他规则
                errors.add(new RuleEvaluationException(rule.ruleId(),
                        "rule " + rule.ruleId() + " failed on " + component.name()
                                + "@" + component.version() + ": " + e.getMessage(), e));
            }
        }
        matches.sort(Comparator
                .comparingInt((RuleMatch m) -> severityRank(m.rule().severity())).reversed()
                .thenComparing(m -> m.rule().ruleId()));
        return new MatchOutcome(List.copyOf(matches), List.copyOf(errors));
    }
}
