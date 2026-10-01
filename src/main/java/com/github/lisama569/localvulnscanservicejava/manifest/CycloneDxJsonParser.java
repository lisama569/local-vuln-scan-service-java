package com.github.lisama569.localvulnscanservicejava.manifest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.ManifestError;
import com.github.lisama569.localvulnscanservicejava.model.ParsedManifest;
import com.github.lisama569.localvulnscanservicejava.model.RejectionReason;
import com.github.lisama569.localvulnscanservicejava.version.InvalidVersionException;
import com.github.lisama569.localvulnscanservicejava.version.SemVersion;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** CycloneDX JSON（子集）解析器：读取 components[] 的 purl/name/version。 */
@org.springframework.stereotype.Component
public class CycloneDxJsonParser implements ManifestParser {

    private static final Pattern BOM_FORMAT =
            Pattern.compile("\\\"bomFormat\\\"\\s*:\\s*\\\"CycloneDX\\\"");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public String format() {
        return "cyclonedx-json";
    }

    @Override
    public boolean supports(String content) {
        return content != null && BOM_FORMAT.matcher(content).find();
    }

    @Override
    public ParsedManifest parse(String content) {
        JsonNode root;
        try {
            root = MAPPER.readTree(content);
        } catch (Exception e) {
            throw new ManifestParseException(List.of(new ManifestError(
                    RejectionReason.MALFORMED_DOCUMENT, -1,
                    "invalid JSON document: " + e.getMessage())));
        }
        JsonNode components = root.get("components");
        List<Component> out = new ArrayList<>();
        List<ManifestError> errors = new ArrayList<>();
        if (components == null || components.isNull()) {
            // 无 components 字段视为空清单（格式已识别）
            return new ParsedManifest(format(), out);
        }
        if (!components.isArray()) {
            throw new ManifestParseException(List.of(new ManifestError(
                    RejectionReason.MALFORMED_DOCUMENT, -1,
                    "'components' must be an array")));
        }
        for (int i = 0; i < components.size(); i++) {
            JsonNode entry = components.get(i);
            String name = text(entry, "name");
            String version = text(entry, "version");
            String purl = text(entry, "purl");
            String ecosystem = ecosystemFromPurl(purl);
            if (name == null || name.isBlank()) {
                errors.add(new ManifestError(RejectionReason.MISSING_FIELD, i,
                        "component[" + i + "] missing 'name'"));
                continue;
            }
            if (version == null || version.isBlank()) {
                errors.add(new ManifestError(RejectionReason.MISSING_FIELD, i,
                        "component[" + i + "] missing 'version'"));
                continue;
            }
            try {
                SemVersion.parse(version);
            } catch (InvalidVersionException e) {
                errors.add(new ManifestError(RejectionReason.INVALID_VERSION, i,
                        "component[" + i + "] '" + name + "': " + e.getMessage()));
                continue;
            }
            out.add(new Component(ecosystem == null ? "unknown" : ecosystem, name, version));
        }
        if (!errors.isEmpty()) {
            throw new ManifestParseException(errors);
        }
        return new ParsedManifest(format(), out);
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && v.isTextual() ? v.asText() : null;
    }

    /** 从 purl（pkg:type/namespace/name@version）提取生态类型。 */
    static String ecosystemFromPurl(String purl) {
        if (purl == null || !purl.startsWith("pkg:")) {
            return null;
        }
        int slash = purl.indexOf('/', 4);
        if (slash < 0) {
            return null;
        }
        return purl.substring(4, slash);
    }
}
