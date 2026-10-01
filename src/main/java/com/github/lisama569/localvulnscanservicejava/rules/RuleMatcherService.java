package com.github.lisama569.localvulnscanservicejava.rules;

import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.RuleError;
import com.github.lisama569.localvulnscanservicejava.model.RuleSet;
import com.github.lisama569.localvulnscanservicejava.model.ScanFinding;
import com.github.lisama569.localvulnscanservicejava.version.InvalidVersionException;
import com.github.lisama569.localvulnscanservicejava.version.SemanticVersion;
import com.github.lisama569.localvulnscanservicejava.version.VersionRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 对归一化清单执行规则匹配。
 * <h3>结论确定性</h3>
 * 组件按清单顺序遍历，规则按 id 顺序（RuleRepository 已排序）遍历；
 * 一个组件可命中多条规则，命中列表按 {@code (组件索引, 严重度降序, 规则 id 升序)} 排序，
 * 相同输入永远得到相同结论。
 * <h3>故障隔离</h3>
 * 单条规则（区间解析 / 版本比较）抛出的任何异常都被捕获并归一化为
 * {@link RuleError}(RULE_MATCH_FAILED)，其余规则继续执行，任务不失败。
 * <h3>可解释性</h3>
 * 每条 finding 的 rationale 记录：规则 id、区间表达式、候选版本、
 * 是否预发布、采用的预发布门槛、最终比较结果。
 */
@Service
public class RuleMatcherService {

    private static final Logger log = LoggerFactory.getLogger(RuleMatcherService.class);

    public record MatchOutcome(List<ScanFinding> findings, List<RuleError> ruleErrors) {
    }

    public MatchOutcome match(Manifest manifest, RuleSet ruleSet) {
        List<ScanFinding> findings = new ArrayList<>();
        List<RuleError> ruleErrors = new ArrayList<>();
        List<Component> components = manifest.components();

        for (int ci = 0; ci < components.size(); ci++) {
            Component component = components.get(ci);
            SemanticVersion candidate;
            try {
                candidate = SemanticVersion.parse(component.rawVersion());
            } catch (InvalidVersionException e) {
                // 解析阶段已保证版本合法；防御性处理，作为规则匹配隔离错误上报
                ruleErrors.add(new RuleError("@component#" + ci,
                        com.github.lisama569.localvulnscanservicejava.model.ErrorCode.RULE_MATCH_FAILED,
                        "组件版本无法比较: " + component + " (" + e.getMessage() + ")"));
                continue;
            }
            for (var rule : ruleSet.rules()) {
                try {
                    if (!rule.ecosystem().equals(component.ecosystem())
                            || !rule.packageName().equals(component.name())) {
                        continue;
                    }
                    VersionRange range = VersionRange.parse(rule.rangeExpression());
                    boolean hit = range.contains(candidate);
                    log.debug("匹配判定: component={} rule={} range={} candidate={} preRelease={} -> hit={}",
                            component.name(), rule.id(), rule.rangeExpression(),
                            candidate.raw(), candidate.isPreRelease(), hit);
                    if (hit) {
                        String rationale = "规则 " + rule.id() + " 的受影响区间 ["
                                + rule.rangeExpression() + "] 包含版本 " + candidate.raw()
                                + (candidate.isPreRelease()
                                        ? "（预发布版本，已校验存在同核心的严格区间边界）"
                                        : "（稳定版本）")
                                + "；" + rule.severity() + "：" + rule.description();
                        findings.add(new ScanFinding(component, rule, rationale));
                    }
                } catch (RuntimeException e) {
                    log.warn("规则匹配异常已隔离: ruleId={}, component={}", rule.id(), component, e);
                    ruleErrors.add(new RuleError(rule.id(),
                            com.github.lisama569.localvulnscanservicejava.model.ErrorCode.RULE_MATCH_FAILED,
                            "规则 '" + rule.id() + "' 匹配组件 '" + component.name() + "@"
                                    + component.rawVersion() + "' 时异常: " + e.getMessage()));
                }
            }
        }

        // 确定性排序：严重度高者在前，同级按规则 id；为保留组件顺序先记录索引
        record IndexedFinding(int componentIndex, ScanFinding finding) {
        }
        List<IndexedFinding> indexed = new ArrayList<>();
        // findings 已按 (组件顺序, 规则id顺序) 追加；重新按规则比较时需要组件索引，
        // 因此这里用组件名+版本在清单中的位置重算索引
        for (ScanFinding f : findings) {
            int idx = indexOf(components, f.component());
            indexed.add(new IndexedFinding(idx, f));
        }
        indexed.sort(Comparator
                .comparingInt((IndexedFinding x) -> x.componentIndex())
                .thenComparing(x -> x.finding().rule().severity().rank(), Comparator.reverseOrder())
                .thenComparing(x -> x.finding().rule().id()));
        List<ScanFinding> ordered = new ArrayList<>();
        for (IndexedFinding f : indexed) {
            ordered.add(f.finding());
        }
        ruleErrors.sort(Comparator.comparing(RuleError::ruleId));
        log.info("规则匹配完成: ruleSetVersion={}, components={}, findings={}, ruleErrors={}",
                ruleSet.version(), components.size(), ordered.size(), ruleErrors.size());
        return new MatchOutcome(ordered, ruleErrors);
    }

    private static int indexOf(List<Component> components, Component target) {
        for (int i = 0; i < components.size(); i++) {
            if (components.get(i).equals(target)) {
                return i;
            }
        }
        return Integer.MAX_VALUE;
    }
}
