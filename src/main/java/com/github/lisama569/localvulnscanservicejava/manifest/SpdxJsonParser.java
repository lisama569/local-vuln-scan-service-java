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

/** SPDX JSON（子集）解析器：读取 packages[] 的 name/versionInfo 与 purl externalRef。 */
@org.springframework.stereotype.Component
public class SpdxJsonParser implements ManifestParser {

    private static final Pattern SPDX_VERSION =
            Pattern.compile("\\\"spdxVersion\\\"\\s*:\\s*\\\"SPDX-");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public String format() {
        return "spdx-json";
    }

    @Override
    public boolean supports(String content) {
        return content != null && SPDX_VERSION.matcher(content).find();
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
        JsonNode packages = root.get("packages");
        List<Component> out = new ArrayList<>();
        if (packages == null || packages.isNull()) {
            return new ParsedManifest(format(), out);
        }
        if (!packages.isArray()) {
            throw new ManifestParseException(List.of(new ManifestError(
                    RejectionReason.MALFORMED_DOCUMENT, -1,
                    "'packages' must be an array")));
        }
        List<ManifestError> errors = new ArrayList<>();
        for (int i = 0; i < packages.size(); i++) {
            JsonNode entry = packages.get(i);
            String name = text(entry, "name");
            String version = text(entry, "versionInfo");
            String ecosystem = ecosystemFromExternalRefs(entry);
            if (name == null || name.isBlank()) {
                errors.add(new ManifestError(RejectionReason.MISSING_FIELD, i,
                        "package[" + i + "] missing 'name'"));
                continue;
            }
            if (version == null || version.isBlank()) {
                errors.add(new ManifestError(RejectionReason.MISSING_FIELD, i,
                        "package[" + i + "] missing 'versionInfo'"));
                continue;
            }
            try {
                SemVersion.parse(version);
            } catch (InvalidVersionException e) {
                errors.add(new ManifestError(RejectionReason.INVALID_VERSION, i,
                        "package[" + i + "] '" + name + "': " + e.getMessage()));
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

    private static String ecosystemFromExternalRefs(JsonNode entry) {
        JsonNode refs = entry.get("externalRefs");
        if (refs != null && refs.isArray()) {
            for (JsonNode ref : refs) {
                JsonNode locator = ref.get("referenceLocator");
                if (locator != null && locator.isTextual()) {
                    String eco = CycloneDxJsonParser.ecosystemFromPurl(locator.asText());
                    if (eco != null) {
                        return eco;
                    }
                }
            }
        }
        return null;
    }
}
