package com.github.lisama569.localvulnscanservicejava.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.Ecosystem;
import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.ManifestFormat;
import static com.github.lisama569.localvulnscanservicejava.util.Hashes.sha256;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * CycloneDX 风格 JSON SBOM，最小识别字段：
 * <pre>
 * {
 *   "bomFormat": "CycloneDX",
 *   "components": [
 *     {"type": "library", "group": "com.fasterxml", "name": "jackson", "version": "2.15.0"},
 *     {"type": "library", "purl": "pkg:maven/com.fasterxml/jackson@2.15.0"}
 *   ]
 * }
 * </pre>
 * 每个 component：优先使用 purl（{@code pkg:type/namespace/name@version}），
 * 没有 purl 时 group+name（或仅 name）与 version 必须齐备，否则按缺字段/畸形拒绝。
 */
public class CycloneDxJsonParser implements ManifestParser {

    /** purl type -> 归一化生态。 */
    private static final Map<String, Ecosystem> PURL_TYPES = Map.of(
            "maven", Ecosystem.MAVEN,
            "npm", Ecosystem.NPM,
            "pypi", Ecosystem.PYPI,
            "generic", Ecosystem.GENERIC);

    private final ObjectMapper objectMapper;
    public CycloneDxJsonParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Manifest parse(String content) {
        JsonNode root;
        try {
            root = objectMapper.readTree(FormatDetector.stripBom(content));
        } catch (IOException e) {
            throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                    "CycloneDX JSON 语法非法，无法解析: " + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    "CycloneDX JSON 顶层必须是对象");
        }
        JsonNode bomFormat = root.get("bomFormat");
        if (bomFormat == null || !bomFormat.isTextual()
                || !"CycloneDX".equalsIgnoreCase(bomFormat.asText())) {
            throw new ManifestParseException(ErrorCode.FORMAT_UNRECOGNIZED,
                    "JSON 不是 CycloneDX BOM：bomFormat 字段缺失或不为 \"CycloneDX\"");
        }
        if (!root.has("components") || root.get("components").isNull()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    "CycloneDX BOM 缺少 'components' 字段");
        }
        JsonNode array = root.get("components");
        if (!array.isArray()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    "CycloneDX 'components' 必须是数组");
        }
        List<Component> components = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            JsonNode node = array.get(i);
            String where = "cyclonedx components[" + i + "]";
            if (!node.isObject()) {
                throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                        where + " 必须是对象");
            }
            components.add(parseComponent(node, where));
        }
        return new Manifest(ManifestFormat.CYCLONEDX_JSON, sha256(content), components);
    }

    private Component parseComponent(JsonNode node, String where) {
        JsonNode purlNode = node.get("purl");
        if (purlNode != null && purlNode.isTextual() && !purlNode.asText().isBlank()) {
            return parsePurl(purlNode.asText(), where);
        }
        String name = textOrNull(node, "name");
        String version = textOrNull(node, "version");
        String group = textOrNull(node, "group");
        if (name == null) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    where + " 缺少 purl，且缺少 name 字段，无法确定组件标识");
        }
        // 没有 purl 时无法得知生态：允许 group 前缀映射 maven 过于隐式，
        // 因此要求显式 ecosystem 字段（对标准 CycloneDX 的最小本地扩展）。
        String ecosystem = textOrNull(node, "ecosystem");
        if (ecosystem == null) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    where + " 组件 '" + name + "' 缺少 purl 时必须显式提供 ecosystem 字段");
        }
        return ParsingSupport.buildComponent(ecosystem, name, version, where);
    }

    private Component parsePurl(String purl, String where) {
        if (!purl.startsWith("pkg:")) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    where + " purl 必须以 'pkg:' 开头: '" + purl + "'");
        }
        String rest = purl.substring(4);
        int slash = rest.indexOf('/');
        if (slash < 0) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    where + " purl 缺少 '/name' 段: '" + purl + "'");
        }
        String type = rest.substring(0, slash).toLowerCase();
        Ecosystem eco = PURL_TYPES.get(type);
        if (eco == null) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    where + " purl 包类型不受支持: '" + type + "'（支持 maven/npm/pypi/generic）");
        }
        String path = rest.substring(slash + 1);
        int at = path.lastIndexOf('@');
        int qualifiers = path.indexOf('?');
        String namePart;
        String version;
        if (at < 0 || (qualifiers >= 0 && at > qualifiers)) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    where + " purl 缺少 '@version' 段: '" + purl + "'");
        }
        namePart = path.substring(0, at);
        String afterAt = path.substring(at + 1);
        if (qualifiers >= 0) {
            afterAt = afterAt.substring(0, qualifiers);
        }
        version = URLDecoder.decode(afterAt, StandardCharsets.UTF_8);
        if (namePart.isBlank()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    where + " purl 缺少包名: '" + purl + "'");
        }
        // name 段含命名空间时保留最后一段作为包名（group 仅作命名空间）
        String simpleName = namePart.contains("/")
                ? namePart.substring(namePart.lastIndexOf('/') + 1) : namePart;
        simpleName = URLDecoder.decode(simpleName, StandardCharsets.UTF_8);
        return ParsingSupport.buildComponent(eco.name(), simpleName, version,
                where + "(purl=" + purl + ")");
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    "字段 '" + field + "' 必须是字符串，但得到: " + value.getNodeType());
        }
        return value.asText().isBlank() ? null : value.asText();
    }
}
