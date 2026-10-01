package com.github.lisama569.localvulnscanservicejava.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.localvulnscanservicejava.model.Ecosystem;
import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.RuleSet;
import com.github.lisama569.localvulnscanservicejava.model.Severity;
import com.github.lisama569.localvulnscanservicejava.model.VulnerabilityRule;
import com.github.lisama569.localvulnscanservicejava.version.InvalidVersionException;
import com.github.lisama569.localvulnscanservicejava.version.VersionRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 从 classpath:rules/rules.json 加载规则集：
 * <ul>
 *   <li>version 与 contentHash 都取文件内容的 SHA-256：文件不变版本不变，
 *       更新文件后重启即换版本；历史 ScanResult 记录了提交时的版本，结论可复现；</li>
 *   <li>每条规则的 id/ecosystem/packageName/range/severity 必填且校验，
 *       区间在加载期预解析，非法区间（RULE_INVALID_VERSION_RANGE）使启动失败而不是延迟到扫描时；</li>
 *   <li>规则按 id 排序后存储，保证匹配遍历顺序确定。</li>
 * </ul>
 */
@Repository
public class RuleRepository {

    private static final Logger log = LoggerFactory.getLogger(RuleRepository.class);
    private static final Map<String, Ecosystem> ECOSYSTEMS = Map.of(
            "maven", Ecosystem.MAVEN,
            "npm", Ecosystem.NPM,
            "pypi", Ecosystem.PYPI,
            "generic", Ecosystem.GENERIC);

    private final String resourcePath;
    private volatile RuleSet cached;

    public RuleRepository() {
        this("rules/rules.json");
    }

    public RuleRepository(String resourcePath) {
        this.resourcePath = resourcePath;
    }

    public RuleSet current() {
        RuleSet snapshot = cached;
        if (snapshot == null) {
            synchronized (this) {
                if (cached == null) {
                    cached = load();
                }
                return cached;
            }
        }
        return snapshot;
    }

    private RuleSet load() {
        String content;
        Resource resource = resolveResource();
        try (InputStream in = resource.getInputStream()) {
            content = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuleSetLoadException(ErrorCode.RULESET_SYNTAX_INVALID,
                    "规则集文件无法读取: " + resourcePath, e);
        }
        JsonNode root;
        try {
            root = new ObjectMapper().readTree(content);
        } catch (IOException e) {
            throw new RuleSetLoadException(ErrorCode.RULESET_SYNTAX_INVALID,
                    "规则集 JSON 语法非法: " + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new RuleSetLoadException(ErrorCode.RULESET_SYNTAX_INVALID,
                    "规则集顶层必须是 JSON 对象");
        }
        String generatedAt = textOrNull(root, "generatedAt");
        JsonNode rulesNode = root.get("rules");
        if (rulesNode == null || rulesNode.isNull()) {
            throw new RuleSetLoadException(ErrorCode.RULESET_MISSING_FIELD,
                    "规则集缺少必填字段 'rules'");
        }
        if (!rulesNode.isArray()) {
            throw new RuleSetLoadException(ErrorCode.RULESET_SYNTAX_INVALID,
                    "规则集 'rules' 必须是数组");
        }
        List<VulnerabilityRule> rules = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < rulesNode.size(); i++) {
            JsonNode node = rulesNode.get(i);
            String where = "rules[" + i + "]";
            if (!node.isObject()) {
                throw new RuleSetLoadException(ErrorCode.RULESET_SYNTAX_INVALID,
                        where + " 必须是对象");
            }
            String id = requireText(node, "id", where);
            if (!ids.add(id)) {
                throw new RuleSetLoadException(ErrorCode.RULESET_SYNTAX_INVALID,
                        where + " 规则 id 重复: " + id);
            }
            String ecoText = requireText(node, "ecosystem", where);
            Ecosystem ecosystem = ECOSYSTEMS.get(ecoText.toLowerCase());
            if (ecosystem == null) {
                throw new RuleSetLoadException(ErrorCode.RULESET_MISSING_FIELD,
                        where + " 生态无法识别: '" + ecoText + "'");
            }
            String packageName = requireText(node, "packageName", where);
            String rangeExpr = requireText(node, "range", where);
            try {
                VersionRange.parse(rangeExpr);
            } catch (InvalidVersionException e) {
                throw new RuleSetLoadException(ErrorCode.RULE_INVALID_VERSION_RANGE,
                        where + "(" + id + ") 受影响版本区间非法: " + e.getMessage(), e);
            }
            String severityText = requireText(node, "severity", where);
            Severity severity;
            try {
                severity = Severity.valueOf(severityText.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new RuleSetLoadException(ErrorCode.RULESET_MISSING_FIELD,
                        where + "(" + id + ") 严重等级无法识别: '" + severityText
                                + "'（应为 LOW/MEDIUM/HIGH/CRITICAL）");
            }
            String description = node.has("description") && node.get("description").isTextual()
                    ? node.get("description").asText() : "";
            rules.add(new VulnerabilityRule(id, ecosystem, packageName, rangeExpr, severity, description));
        }
        rules.sort((a, b) -> a.id().compareTo(b.id()));
        String hash = com.github.lisama569.localvulnscanservicejava.util.Hashes.sha256(content);
        RuleSet ruleSet = new RuleSet(hash.substring(0, 12), hash,
                generatedAt != null ? generatedAt : "", rules);
        log.info("规则集加载完成: version={}, rules={}", ruleSet.version(), rules.size());
        return ruleSet;
    }

    private static String requireText(JsonNode node, String field, String where) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || !value.isTextual() || value.asText().isBlank()) {
            throw new RuleSetLoadException(ErrorCode.RULESET_MISSING_FIELD,
                    where + " 缺少必填字段 '" + field + "' 或字段为空");
        }
        return value.asText().trim();
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && v.isTextual() ? v.asText() : null;
    }

    String resourcePath() {
        return resourcePath;
    }

    private org.springframework.core.io.Resource resolveResource() {
        if (resourcePath.startsWith("file:")) {
            try {
                return new UrlResource(resourcePath);
            } catch (Exception e) {
                return new FileSystemResource(resourcePath);
            }
        }
        return new ClassPathResource(resourcePath);
    }
}
