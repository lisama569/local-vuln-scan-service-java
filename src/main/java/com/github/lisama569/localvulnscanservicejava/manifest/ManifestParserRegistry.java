package com.github.lisama569.localvulnscanservicejava.manifest;

import com.github.lisama569.localvulnscanservicejava.model.ManifestError;
import com.github.lisama569.localvulnscanservicejava.model.ParsedManifest;
import com.github.lisama569.localvulnscanservicejava.model.RejectionReason;
import org.springframework.stereotype.Service;

import java.util.List;

/** 按内容探测格式并分发到对应解析器；无法识别时以 UNRECOGNIZED_FORMAT 拒绝。 */
@Service
public class ManifestParserRegistry {

    private final List<ManifestParser> parsers;

    public ManifestParserRegistry(List<ManifestParser> parsers) {
        this.parsers = parsers;
    }

    public List<String> supportedFormats() {
        return parsers.stream().map(ManifestParser::format).toList();
    }

    public ParsedManifest parse(String content) {
        if (content == null || content.isBlank()) {
            throw new ManifestParseException(List.of(new ManifestError(
                    RejectionReason.UNRECOGNIZED_FORMAT, -1,
                    "empty content; supported formats: " + supportedFormats())));
        }
        for (ManifestParser parser : parsers) {
            if (parser.supports(content)) {
                return parser.parse(content);
            }
        }
        String head = content.stripLeading();
        head = head.length() > 40 ? head.substring(0, 40) + "..." : head;
        throw new ManifestParseException(List.of(new ManifestError(
                RejectionReason.UNRECOGNIZED_FORMAT, -1,
                "unrecognized manifest format near '" + head.replaceAll("\\s+", " ")
                        + "'; supported formats: " + supportedFormats())));
    }
}
