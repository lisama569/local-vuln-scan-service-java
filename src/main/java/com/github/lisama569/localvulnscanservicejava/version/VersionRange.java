package com.github.lisama569.localvulnscanservicejava.version;

import java.util.ArrayList;
import java.util.List;

/**
 * 版本区间。支持三种写法：
 * <ul>
 *   <li>精确版本：{@code 1.2.3}</li>
 *   <li>比较表达式（逗号分隔的合取）：{@code >=1.2.3,<2.0.0}</li>
 *   <li>区间记号：{@code [1.0,2.0)}、{@code (,2.0]}、{@code [1.0]}（等价精确版本）、{@code [,2.0)}</li>
 * </ul>
 * 预发布语义：严格按 semver 排序比较，不做特殊豁免——
 * 例如 {@code <2.0.0} 包含 {@code 2.0.0-rc1}，{@code >=1.0.0} 不包含 {@code 1.0.0-rc1}。
 */
public final class VersionRange {

    private record Bound(SemVersion version, boolean inclusive, boolean lower) {
        boolean satisfiedBy(SemVersion v) {
            int c = v.compareTo(version);
            if (lower) {
                return inclusive ? c >= 0 : c > 0;
            }
            return inclusive ? c <= 0 : c < 0;
        }
    }

    private final String spec;
    private final List<Bound> bounds;

    private VersionRange(String spec, List<Bound> bounds) {
        this.spec = spec;
        this.bounds = bounds;
    }

    public static VersionRange parse(String spec) {
        if (spec == null || spec.isBlank()) {
            throw new InvalidVersionException("range spec is blank");
        }
        String s = spec.trim();
        List<Bound> bounds = new ArrayList<>();
        if (s.startsWith("[") || s.startsWith("(")) {
            parseBracket(s, bounds);
        } else if (s.contains(",") || s.startsWith(">") || s.startsWith("<") || s.startsWith("=")) {
            parseComparators(s, bounds);
        } else {
            // 精确版本
            SemVersion exact = SemVersion.parse(s);
            bounds.add(new Bound(exact, true, true));
            bounds.add(new Bound(exact, true, false));
        }
        return new VersionRange(s, List.copyOf(bounds));
    }

    private static void parseBracket(String s, List<Bound> bounds) {
        char end = s.charAt(s.length() - 1);
        if (end != ']' && end != ')') {
            throw new InvalidVersionException("bracket range must end with ] or ): " + s);
        }
        String inner = s.substring(1, s.length() - 1);
        String[] parts = inner.split(",", -1);
        if (parts.length == 1) {
            // [1.0] 精确版本
            if (s.charAt(0) != '[' || end != ']') {
                throw new InvalidVersionException("single-value range must use []: " + s);
            }
            SemVersion exact = SemVersion.parse(parts[0].trim());
            bounds.add(new Bound(exact, true, true));
            bounds.add(new Bound(exact, true, false));
            return;
        }
        if (parts.length != 2) {
            throw new InvalidVersionException("bracket range expects lower,upper: " + s);
        }
        String lo = parts[0].trim();
        String hi = parts[1].trim();
        if (!lo.isEmpty()) {
            bounds.add(new Bound(SemVersion.parse(lo), s.charAt(0) == '[', true));
        }
        if (!hi.isEmpty()) {
            bounds.add(new Bound(SemVersion.parse(hi), end == ']', false));
        }
        if (bounds.isEmpty()) {
            throw new InvalidVersionException("range has no bounds: " + s);
        }
    }

    private static void parseComparators(String s, List<Bound> bounds) {
        for (String token : s.split(",", -1)) {
            String t = token.trim();
            String op;
            String ver;
            if (t.startsWith(">=")) { op = ">="; ver = t.substring(2); }
            else if (t.startsWith("<=")) { op = "<="; ver = t.substring(2); }
            else if (t.startsWith(">")) { op = ">"; ver = t.substring(1); }
            else if (t.startsWith("<")) { op = "<"; ver = t.substring(1); }
            else if (t.startsWith("=")) { op = "="; ver = t.substring(1); }
            else {
                throw new InvalidVersionException("comparator expected (>=,<=,>,<,=) but got: " + t);
            }
            SemVersion v = SemVersion.parse(ver.trim());
            switch (op) {
                case ">=" -> bounds.add(new Bound(v, true, true));
                case ">" -> bounds.add(new Bound(v, false, true));
                case "<=" -> bounds.add(new Bound(v, true, false));
                case "<" -> bounds.add(new Bound(v, false, false));
                case "=" -> {
                    bounds.add(new Bound(v, true, true));
                    bounds.add(new Bound(v, true, false));
                }
                default -> throw new InvalidVersionException("unknown comparator: " + op);
            }
        }
    }

    public boolean contains(SemVersion version) {
        for (Bound b : bounds) {
            if (!b.satisfiedBy(version)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return spec;
    }
}
