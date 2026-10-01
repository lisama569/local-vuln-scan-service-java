package com.github.lisama569.localvulnscanservicejava.parser;

import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.ManifestFormat;
import com.github.lisama569.localvulnscanservicejava.util.Hashes;

import java.util.ArrayList;
import java.util.List;

/**
 * CSV 清单：首行必须是表头，且恰好包含 ecosystem,name,version 三列
 * （顺序必须一致，错列直接拒绝，不做容错映射）。值可用双引号包裹，
 * 引号内 {@code ""} 表示一个引号；空行忽略；行数列数不符、引号未闭合都按语法非法拒绝。
 */
public class CsvManifestParser implements ManifestParser {

    @Override
    public Manifest parse(String content) {
        String text = FormatDetector.stripBom(content);
        List<List<String>> rows = parseCsv(text);
        if (rows.isEmpty()) {
            throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                    "CSV 为空，缺少表头 ecosystem,name,version");
        }
        List<String> header = rows.get(0);
        if (header.size() != 3
                || !"ecosystem".equalsIgnoreCase(header.get(0).trim())
                || !"name".equalsIgnoreCase(header.get(1).trim())
                || !"version".equalsIgnoreCase(header.get(2).trim())) {
            throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                    "CSV 表头必须恰好为 ecosystem,name,version 三列且顺序一致，实际为: " + header);
        }
        List<Component> components = new ArrayList<>();
        for (int r = 1; r < rows.size(); r++) {
            List<String> row = rows.get(r);
            if (row.stream().allMatch(String::isBlank)) {
                continue;
            }
            if (row.size() != 3) {
                throw new ManifestParseException(ErrorCode.MANIFEST_ENTRY_MALFORMED,
                        "CSV 第 " + (r + 1) + " 行列数为 " + row.size() + "，期望 3: " + row);
            }
            String where = "csv 第 " + (r + 1) + " 行";
            components.add(ParsingSupport.buildComponent(
                    row.get(0), row.get(1), row.get(2), where));
        }
        return new Manifest(ManifestFormat.CSV, Hashes.sha256(content), components);
    }

    /** 最小 RFC4180 风格解析：逗号分隔、双引号包裹、引号内两个双引号转义、引号内允许 CRLF。 */
    private static List<List<String>> parseCsv(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> current = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;
        boolean fieldStarted = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
                        field.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    field.append(c);
                }
                continue;
            }
            if (c == '"' && !fieldStarted) {
                inQuotes = true;
                fieldStarted = true;
                continue;
            }
            if (c == ',') {
                current.add(field.toString());
                field.setLength(0);
                fieldStarted = false;
                continue;
            }
            if (c == '\n') {
                current.add(field.toString());
                field.setLength(0);
                fieldStarted = false;
                rows.add(current);
                current = new ArrayList<>();
                continue;
            }
            if (c == '\r') {
                if (i + 1 < text.length() && text.charAt(i + 1) == '\n') {
                    current.add(field.toString());
                    field.setLength(0);
                    fieldStarted = false;
                    rows.add(current);
                    current = new ArrayList<>();
                    i++;
                    continue;
                }
                // 单独 CR 也当行结束
                current.add(field.toString());
                field.setLength(0);
                fieldStarted = false;
                rows.add(current);
                current = new ArrayList<>();
                continue;
            }
            if (c == '"' && fieldStarted) {
                throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                        "CSV 引号只能出现在字段开头，位置 " + (i + 1));
            }
            field.append(c);
            fieldStarted = true;
        }
        if (inQuotes) {
            throw new ManifestParseException(ErrorCode.MANIFEST_SYNTAX_INVALID,
                    "CSV 存在未闭合的双引号字段");
        }
        // 最后一行（无结尾换行）
        if (field.length() > 0 || !current.isEmpty()) {
            current.add(field.toString());
            rows.add(current);
        }
        return rows;
    }
}
