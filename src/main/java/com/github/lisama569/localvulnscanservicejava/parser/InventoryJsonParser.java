package com.github.lisama569.localvulnscanservicejava.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.ManifestFormat;
import static com.github.lisama569.localvulnscanservicejava.util.Hashes.sha256;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 本地自定义 JSON 清单：
 * <pre>
 * {"components":[{"ecosystem":"maven","name":"...","version":"..."}, ...]}
 * </pre>
 * 顶层必须为对象；components 必须存在且为数组（允许空数组，表示合法的空清单）；
 * 每个元素必须为含 ecosystem/name/version 三个非空字符串字段的对象。
 */
public class InventoryJsonParser implements ManifestParser {

    private final ObjectMapper objectMapper;
    public InventoryJsonParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Manifest parse(String content) {
        JsonNode root;
        try {
            root = objectMapper.readTree(FormatDetector.stripBom(content));
        } catch (IOException e) {
            throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                    "inventory JSON 语法非法，无法解析: " + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    "inventory JSON 顶层必须是对象 {\"components\":[...]}");
        }
        if (!root.has("components") || root.get("components").isNull()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_MISSING_FIELD,
                    "inventory JSON 缺少必填字段 'components'");
        }
        JsonNode array = root.get("components");
        if (!array.isArray()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    "inventory JSON 的 'components' 必须是数组");
        }
        List<Component> components = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            JsonNode node = array.get(i);
            String where = "inventory JSON components[" + i + "]";
            if (!node.isObject()) {
                throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                        where + " 必须是对象");
            }
            components.add(ParsingSupport.buildComponent(
                    textOrNull(node, "ecosystem"),
                    textOrNull(node, "name"),
                    textOrNull(node, "version"),
                    where));
        }
        return new Manifest(ManifestFormat.INVENTORY_JSON, sha256(content), components);
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            // 非字符串值不能静默 toString 后吞掉，按畸形条目拒绝
            throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                    "字段 '" + field + "' 必须是字符串，但得到: " + value.getNodeType());
        }
        return value.asText();
    }
}
