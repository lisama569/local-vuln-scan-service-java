package com.github.lisama569.localvulnscanservicejava.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.ManifestFormat;

/**
 * 纯结构嗅探（不依赖文件名或调用方声明的格式）：
 * <ol>
 *   <li>去除 UTF-8 BOM 后，空 / 全空白 -> {@code EMPTY_CONTENT}；</li>
 *   <li>首个非空白字符为 {@code '{'}：真正解析 JSON。JSON 语法损坏 ->
 *       {@code MANIFEST_SYNTAX_INVALID}；非对象 -> {@code FORMAT_UNRECOGNIZED}；
 *       含 {@code "bomFormat":"CycloneDX"} -> CYCLONEDX_JSON；含 {@code components} 字段 ->
 *       INVENTORY_JSON；两者都没有 -> {@code FORMAT_UNRECOGNIZED}（注意：
 *       合法 JSON 但没有 components 的 {} 在这里被拒，缺字段错误由各解析器针对
 *       “有 bomFormat/有结构但缺 components” 的情况给出）；</li>
 *   <li>含 {@code SPDXVersion:} 文件头 -> SPDX_TAG_VALUE；</li>
 *   <li>首行是表头且恰好为 ecosystem,name,version 三列 -> CSV；</li>
 *   <li>其余 -> {@code FORMAT_UNRECOGNIZED}。</li>
 * </ol>
 */
public final class FormatDetector {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private FormatDetector() {
    }

    public static ManifestFormat detect(String content) {
        if (content == null || content.isBlank()) {
            throw new ManifestParseException(ErrorCode.EMPTY_CONTENT, "清单内容为空");
        }
        String text = stripBom(content);
        int p = 0;
        while (p < text.length() && Character.isWhitespace(text.charAt(p))) {
            p++;
        }
        if (p >= text.length()) {
            throw new ManifestParseException(ErrorCode.EMPTY_CONTENT, "清单内容为空白");
        }
        char first = text.charAt(p);
        if (first == '{') {
            return detectJson(text);
        }
        String trimmed = text.stripLeading();
        if (trimmed.startsWith("SPDXVersion:")) {
            return ManifestFormat.SPDX_TAG_VALUE;
        }
        String firstLine = trimmed.split("\\r?\\n", 2)[0].trim();
        if (isCsvHeader(firstLine)) {
            return ManifestFormat.CSV;
        }
        throw new ManifestParseException(ErrorCode.FORMAT_UNRECOGNIZED,
                "无法识别的清单格式（既不是已知 JSON/SBOM，也不是 SPDX 标签值或 CSV）: 开头为 '"
                        + abbreviate(firstLine) + "'");
    }

    private static ManifestFormat detectJson(String text) {
        JsonNode root;
        try {
            root = OBJECT_MAPPER.readTree(text);
        } catch (com.fasterxml.jackson.core.JacksonException e) {
            throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                    "内容以 '{' 开头但不是合法 JSON: " + e.getOriginalMessage(), e);
        } catch (java.io.IOException e) {
            throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                    "JSON 读取失败: " + e.getMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new ManifestParseException(ErrorCode.FORMAT_UNRECOGNIZED,
                    "JSON 顶层不是对象，无法识别为受支持的清单/SBOM");
        }
        JsonNode bomFormat = root.get("bomFormat");
        if (bomFormat != null) {
            // 声明了 bomFormat 就按 SBOM 识别；只支持 CycloneDX
            if (bomFormat.isTextual() && "CycloneDX".equalsIgnoreCase(bomFormat.asText())) {
                return ManifestFormat.CYCLONEDX_JSON;
            }
            throw new ManifestParseException(ErrorCode.FORMAT_UNRECOGNIZED,
                    "不支持的 BOM 格式 bomFormat="
                            + (bomFormat.isTextual() ? bomFormat.asText() : bomFormat.getNodeType()));
        }
        if (root.has("components")) {
            return ManifestFormat.INVENTORY_JSON;
        }
        throw new ManifestParseException(ErrorCode.FORMAT_UNRECOGNIZED,
                "JSON 清单缺少 bomFormat=CycloneDX 声明，也没有顶层 components 字段");
    }

    private static boolean isCsvHeader(String line) {
        String[] cols = line.split(",", -1);
        if (cols.length != 3) {
            return false;
        }
        return cols[0].trim().equalsIgnoreCase("ecosystem")
                && cols[1].trim().equalsIgnoreCase("name")
                && cols[2].trim().equalsIgnoreCase("version");
    }

    static String stripBom(String text) {
        if (!text.isEmpty() && text.charAt(0) == '﻿') {
            return text.substring(1);
        }
        return text;
    }

    private static String abbreviate(String s) {
        return s.length() <= 60 ? s : s.substring(0, 60) + "...";
    }
}
