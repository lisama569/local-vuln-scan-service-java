package com.github.lisama569.localvulnscanservicejava.parser;

import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.Ecosystem;
import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.version.InvalidVersionException;
import com.github.lisama569.localvulnscanservicejava.version.SemanticVersion;

/** 各解析器共享的字段校验：任何缺字段 / 非法枚举 / 非法版本都抛 ManifestParseException，绝不跳过。 */
final class ParsingSupport {

    private ParsingSupport() {
    }

    static Ecosystem parseEcosystem(String raw, String where) {
        if (raw == null || raw.isBlank()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    where + " 缺少 ecosystem 字段");
        }
        return switch (raw.trim().toLowerCase()) {
            case "maven" -> Ecosystem.MAVEN;
            case "npm" -> Ecosystem.NPM;
            case "pypi", "python" -> Ecosystem.PYPI;
            case "generic" -> Ecosystem.GENERIC;
            default -> throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    where + " 的 ecosystem 无法识别: '" + raw + "'");
        };
    }

    static String requireText(String value, String fieldName, String where) {
        if (value == null || value.isBlank()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    where + " 缺少必填字段 '" + fieldName + "' 或字段为空");
        }
        return value.trim();
    }

    /** 构造组件并校验版本号可解析（非法版本必须显式拒绝，不能静默丢弃）。 */
    static Component buildComponent(String ecosystem, String name, String version, String where) {
        Ecosystem eco = parseEcosystem(ecosystem, where);
        String n = requireText(name, "name", where);
        String v = requireText(version, "version", where);
        try {
            SemanticVersion.parse(v);
        } catch (InvalidVersionException e) {
            throw new ManifestParseException(ErrorCode.MANIFEST_VERSION_INVALID,
                    where + " 组件 '" + n + "' 的版本 '" + v + "' 不是合法语义化版本: " + e.getMessage(), e);
        }
        return new Component(eco, n, v);
    }
}
