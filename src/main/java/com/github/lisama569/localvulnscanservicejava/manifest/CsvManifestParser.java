package com.github.lisama569.localvulnscanservicejava.manifest;

import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.ManifestError;
import com.github.lisama569.localvulnscanservicejava.model.ParsedManifest;
import com.github.lisama569.localvulnscanservicejava.model.RejectionReason;
import com.github.lisama569.localvulnscanservicejava.version.InvalidVersionException;
import com.github.lisama569.localvulnscanservicejava.version.SemVersion;

import java.util.ArrayList;
import java.util.List;

/** 简单 CSV 清单解析器，表头必须为 ecosystem,name,version（顺序固定）。 */
@org.springframework.stereotype.Component
public class CsvManifestParser implements ManifestParser {

    static final String HEADER = "ecosystem,name,version";

    @Override
    public String format() {
        return "csv";
    }

    @Override
    public boolean supports(String content) {
        if (content == null) {
            return false;
        }
        String firstLine = content.stripLeading().lines().findFirst().orElse("");
        return firstLine.trim().equalsIgnoreCase(HEADER);
    }

    @Override
    public ParsedManifest parse(String content) {
        List<String> lines = content.lines().filter(l -> !l.isBlank()).toList();
        if (lines.isEmpty() || !lines.get(0).trim().equalsIgnoreCase(HEADER)) {
            throw new ManifestParseException(List.of(new ManifestError(
                    RejectionReason.MALFORMED_DOCUMENT, -1,
                    "csv manifest must start with header: " + HEADER)));
        }
        List<Component> out = new ArrayList<>();
        List<ManifestError> errors = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            String[] cols = line.split(",", -1);
            int entry = i - 1;
            if (cols.length != 3) {
                errors.add(new ManifestError(RejectionReason.MALFORMED_ENTRY, entry,
                        "row " + i + " expects 3 columns but got " + cols.length + ": " + line));
                continue;
            }
            String ecosystem = cols[0].trim();
            String name = cols[1].trim();
            String version = cols[2].trim();
            if (ecosystem.isEmpty() || name.isEmpty()) {
                errors.add(new ManifestError(RejectionReason.MISSING_FIELD, entry,
                        "row " + i + " has empty ecosystem/name: " + line));
                continue;
            }
            if (version.isEmpty()) {
                errors.add(new ManifestError(RejectionReason.MISSING_FIELD, entry,
                        "row " + i + " has empty version: " + line));
                continue;
            }
            try {
                SemVersion.parse(version);
            } catch (InvalidVersionException e) {
                errors.add(new ManifestError(RejectionReason.INVALID_VERSION, entry,
                        "row " + i + " '" + name + "': " + e.getMessage()));
                continue;
            }
            out.add(new Component(ecosystem, name, version));
        }
        if (!errors.isEmpty()) {
            throw new ManifestParseException(errors);
        }
        return new ParsedManifest(format(), out);
    }
}
