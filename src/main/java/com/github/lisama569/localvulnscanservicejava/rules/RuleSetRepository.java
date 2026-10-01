package com.github.lisama569.localvulnscanservicejava.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Repository;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 从本地 classpath 加载规则集。
 * 当前版本位于 {@code rules/ruleset.json}；历史快照位于 {@code rules/ruleset-<version>.json}。
 * 已加载版本全部缓存，保证规则集更新后历史扫描结论仍可复现。
 */
@Repository
public class RuleSetRepository {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, RuleSet> cache = new ConcurrentHashMap<>();
    private volatile RuleSet current;

    /** 当前生效的规则集。 */
    public RuleSet current() {
        RuleSet rs = current;
        if (rs == null) {
            synchronized (this) {
                if (current == null) {
                    current = load("rules/ruleset.json");
                }
            }
            rs = current;
        }
        return rs;
    }

    /** 按版本获取规则集快照；不存在时抛出 IllegalArgumentException。 */
    public RuleSet byVersion(String rulesetVersion) {
        return cache.computeIfAbsent(rulesetVersion, v -> {
            RuleSet cur = current();
            if (cur.rulesetVersion().equals(v)) {
                return cur;
            }
            return load("rules/ruleset-" + v + ".json");
        });
    }

    /** 允许运行时替换当前规则集（规则集更新），历史版本仍在缓存中。 */
    public synchronized void updateCurrent(RuleSet newRuleSet) {
        cache.put(newRuleSet.rulesetVersion(), newRuleSet);
        this.current = newRuleSet;
    }

    private RuleSet load(String path) {
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            JsonNode root = MAPPER.readTree(in);
            String version = root.get("rulesetVersion").asText();
            List<VulnerabilityRule> rules = new ArrayList<>();
            for (JsonNode r : root.withArray("rules")) {
                rules.add(new VulnerabilityRule(
                        r.get("ruleId").asText(),
                        r.get("vulnId").asText(),
                        r.get("ecosystem").asText(),
                        r.get("packageName").asText(),
                        r.get("rangeSpec").asText(),
                        r.get("severity").asText(),
                        r.has("summary") ? r.get("summary").asText() : ""));
            }
            RuleSet rs = new RuleSet(version, List.copyOf(rules));
            cache.put(version, rs);
            return rs;
        } catch (Exception e) {
            throw new IllegalArgumentException("cannot load ruleset from " + path + ": " + e.getMessage(), e);
        }
    }
}
