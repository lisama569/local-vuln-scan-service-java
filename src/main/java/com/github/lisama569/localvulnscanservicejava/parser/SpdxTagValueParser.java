package com.github.lisama569.localvulnscanservicejava.parser;

import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.Ecosystem;
import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.ManifestFormat;
import com.github.lisama569.localvulnscanservicejava.util.Hashes;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * SPDX 标签值（tag-value）格式解析，识别的标签：
 * <ul>
 *   <li>{@code SPDXVersion: SPDX-2.3}（文件头必填，用于格式识别）</li>
 *   <li>{@code PackageName: ...}：每出现一次开始一个新包，必填</li>
 *   <li>{@code PackageVersion: ...}：包版本（有 purl 时由 purl 提供，否则必填）</li>
 *   <li>{@code ExternalRef: PURL pkg:type/...@version}：包定位，提供生态与版本</li>
 * </ul>
 * 注释行（# 开头）被忽略；缺少冒号或标签不可识别的行按语法非法拒绝。
 * 每个包名称、版本（purl 或显式字段）、生态缺一即拒绝。
 */
public class SpdxTagValueParser implements ManifestParser {

    private static final Map<String, Ecosystem> PURL_TYPES = Map.of(
            "maven", Ecosystem.MAVEN,
            "npm", Ecosystem.NPM,
            "pypi", Ecosystem.PYPI,
            "generic", Ecosystem.GENERIC);

    @Override
    public Manifest parse(String content) {
        String text = FormatDetector.stripBom(content);
        String[] lines = text.split("\\r?\\n", -1);
        List<Component> components = new ArrayList<>();
        boolean sawHeader = false;
        String pendingName = null;
        String pendingVersion = null;
        String pendingPurl = null;
        int packageStartLine = -1;

        for (int i = 0; i < lines.length; i++) {
            String raw = lines[i].trim();
            if (raw.isEmpty() || raw.startsWith("#")) {
                continue;
            }
            int colon = raw.indexOf(':');
            if (colon < 0) {
                throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                        "SPDX 第 " + (i + 1) + " 行不是 'Tag: value' 形式: '" + raw + "'");
            }
            String tag = raw.substring(0, colon).trim();
            String value = raw.substring(colon + 1).trim();
            if (!isKnownTag(tag)) {
                throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                        "SPDX 第 " + (i + 1) + " 行出现无法识别的标签: '" + tag + "'");
            }
            int lineNo = i + 1;
            switch (tag) {
                case "SPDXVersion" -> {
                    if (i > firstNonCommentLine(lines)) {
                        throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                                "SPDXVersion 必须出现在首个有效行（第 " + lineNo + " 行）");
                    }
                    if (value.isBlank()) {
                        throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                                "SPDX 第 " + lineNo + " 行 SPDXVersion 值为空");
                    }
                    sawHeader = true;
                }
                case "PackageName" -> {
                    if (pendingName != null) {
                        components.add(finishPackage(pendingName, pendingVersion, pendingPurl,
                                packageStartLine));
                    }
                    if (value.isBlank()) {
                        throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                                "SPDX 第 " + lineNo + " 行 PackageName 为空");
                    }
                    pendingName = value;
                    pendingVersion = null;
                    pendingPurl = null;
                    packageStartLine = lineNo;
                }
                case "PackageVersion" -> {
                    if (pendingName == null) {
                        throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                                "SPDX 第 " + lineNo + " 行出现 PackageVersion，但此前没有 PackageName");
                    }
                    if (value.isBlank()) {
                        throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                                "SPDX 第 " + lineNo + " 行 PackageVersion 为空");
                    }
                    pendingVersion = value;
                }
                case "ExternalRef" -> {
                    if (pendingName == null) {
                        throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                                "SPDX 第 " + lineNo + " 行出现 ExternalRef，但此前没有 PackageName");
                    }
                    String purl = extractPurl(value);
                    if (purl != null) {
                        pendingPurl = purl;
                    }
                    // 非 PURL 的 ExternalRef（如 cpe、swid）本地扫描不使用，忽略
                }
                default -> {
                    // 已识别但与依赖归一化无关的标签：忽略
                }
            }
        }
        if (pendingName != null) {
            components.add(finishPackage(pendingName, pendingVersion, pendingPurl, packageStartLine));
        }
        if (!sawHeader) {
            throw new ManifestParseException(ErrorCode.FORMAT_UNRECOGNIZED,
                    "SPDX 标签值缺少 SPDXVersion 文件头");
        }
        return new Manifest(ManifestFormat.SPDX_TAG_VALUE, Hashes.sha256(content), components);
    }

    private boolean isKnownTag(String tag) {
        return tag.equals("SPDXVersion") || tag.equals("DataLicense")
                || tag.equals("SPDXID") || tag.equals("DocumentName")
                || tag.equals("DocumentNamespace") || tag.equals("Creator")
                || tag.equals("Created") || tag.equals("PackageName")
                || tag.equals("PackageVersion") || tag.equals("PackageDownloadLocation")
                || tag.equals("PackageLicenseConcluded") || tag.equals("PackageLicenseDeclared")
                || tag.equals("PackageCopyrightText") || tag.equals("FilesAnalyzed")
                || tag.equals("ExternalRef") || tag.equals("ExternalRefComment")
                || tag.equals("Relationship");
    }

    private int firstNonCommentLine(String[] lines) {
        for (int i = 0; i < lines.length; i++) {
            String t = lines[i].trim();
            if (!t.isEmpty() && !t.startsWith("#")) {
                return i;
            }
        }
        return -1;
    }

    /** ExternalRef 值形如 "PURL pkg:maven/g/a@1.0 category"，提取以 pkg: 开头的段。 */
    private String extractPurl(String value) {
        for (String token :value.split("\\s+")) {
            if (token.startsWith("pkg:")) {
                return token;
            }
        }
        return null;
    }

    private Component finishPackage(String name, String version, String purl, int lineNo) {
        String where = "spdx Package@line" + lineNo + " ('" + name + "')";
        if (purl != null) {
            ParsedPurl parsed = parsePurl(purl, where);
            // purl 的版本优先；purl 无版本时回退 PackageVersion
            String effectiveVersion = parsed.version() != null ? parsed.version() : version;
            return ParsingSupport.buildComponent(
                    parsed.ecosystem().name(), parsed.name(), effectiveVersion, where);
        }
        if (version == null) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    where + " 缺少版本：既没有 PURL 也没有 PackageVersion");
        }
        // 无 purl 时生态未知，统一归一到 GENERIC（标签值格式没有结构化生态字段）
        return ParsingSupport.buildComponent(Ecosystem.GENERIC.name(), name, version, where);
    }

    private record ParsedPurl(Ecosystem ecosystem, String name, String version) {
    }

    private ParsedPurl parsePurl(String purl, String where) {
        String rest = purl.substring("pkg:".length());
        int slash = rest.indexOf('/');
        if (slash < 0) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    where + " purl 缺少 '/name' 段: '" + purl + "'");
        }
        String type = rest.substring(0, slash).toLowerCase();
        Ecosystem eco = PURL_TYPES.get(type);
        if (eco == null) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    where + " purl 包类型不受支持: '" + type + "'");
        }
        String path = rest.substring(slash + 1);
        int qualifiers = path.indexOf('?');
        String main = qualifiers >= 0 ? path.substring(0, qualifiers) : path;
        int at = main.lastIndexOf('@');
        String namePart = at >= 0 ? main.substring(0, at) : main;
        String ver = at >= 0 ? URLDecoder.decode(main.substring(at + 1), StandardCharsets.UTF_8) : null;
        if (namePart.isBlank()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    where + " purl 缺少包名: '" + purl + "'");
        }
        String simpleName = namePart.contains("/")
                ? namePart.substring(namePart.lastIndexOf('/') + 1) : namePart;
        return new ParsedPurl(eco, URLDecoder.decode(simpleName, StandardCharsets.UTF_8), ver);
    }
}
