package com.github.lisama569.localvulnscanservicejava.version;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 语义化版本，采用 SemVer 2.0 的优先级（precedence）规则：
 * <ul>
 *   <li>宽松解析：允许 {@code 1}、{@code 1.2} 形式，缺失的次版本/补丁按 0 补齐；
 *       但不允许前导零（如 {@code 01.2.3}）。</li>
 *   <li>预发布段 {@code -alpha.1} 参与比较，构建元数据 {@code +build} 不参与。</li>
 *   <li>同一核心版本下，预发布版本 &lt; 稳定版本（{@code 1.0.0-alpha} &lt; {@code 1.0.0}）。</li>
 *   <li>预发布标识符逐个比较：数字标识符 &lt; 非数字标识符；数字按数值，非数字按 ASCII 字典序；
 *       前缀相同则字段少者更小。</li>
 * </ul>
 * 不可变值对象。
 */
public final class SemanticVersion implements Comparable<SemanticVersion> {

    private static final Pattern SEMVER = Pattern.compile(
            "^(\\d{1,18})(?:\\.(\\d{1,18}))?(?:\\.(\\d{1,18}))?(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$");

    private final String raw;
    private final int major;
    private final int minor;
    private final int patch;
    /** 预发布标识符；稳定版为空列表（null 不便于比较）。 */
    private final List<String> prerelease;

    private SemanticVersion(String raw, int major, int minor, int patch, List<String> prerelease) {
        this.raw = raw;
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.prerelease = List.copyOf(prerelease);
    }

    public static SemanticVersion parse(String raw) {
        if (raw == null) {
            throw new InvalidVersionException("版本号为 null");
        }
        String text = raw.trim();
        if (text.isEmpty()) {
            throw new InvalidVersionException("版本号为空字符串");
        }
        Matcher m = SEMVER.matcher(text);
        if (!m.matches()) {
            throw new InvalidVersionException("不符合语义化版本: '" + raw + "'");
        }
        int major = parseSegment(m.group(1), raw, "major");
        int minor = m.group(2) != null ? parseSegment(m.group(2), raw, "minor") : 0;
        int patch = m.group(3) != null ? parseSegment(m.group(3), raw, "patch") : 0;
        List<String> pre = new ArrayList<>();
        if (m.group(4) != null) {
            for (String id : m.group(4).split("\\.")) {
                if (id.isEmpty()) {
                    throw new InvalidVersionException("预发布标识符为空: '" + raw + "'");
                }
                if (isAllDigits(id) && id.length() > 1 && id.startsWith("0")) {
                    throw new InvalidVersionException("数字预发布标识符存在前导零: '" + raw + "'");
                }
                pre.add(id);
            }
        }
        return new SemanticVersion(text, major, minor, patch, pre);
    }

    private static int parseSegment(String segment, String raw, String field) {
        if (segment.length() > 1 && segment.startsWith("0")) {
            throw new InvalidVersionException(field + " 版本段存在前导零: '" + raw + "'");
        }
        try {
            return Integer.parseInt(segment);
        } catch (NumberFormatException e) {
            throw new InvalidVersionException(field + " 版本段超出范围: '" + raw + "'", e);
        }
    }

    private static boolean isAllDigits(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) < '0' || s.charAt(i) > '9') {
                return false;
            }
        }
        return true;
    }

    public String raw() {
        return raw;
    }

    public int major() {
        return major;
    }

    public int minor() {
        return minor;
    }

    public int patch() {
        return patch;
    }

    /** 主.次.补丁数字段。 */
    public int[] core() {
        return new int[] {major, minor, patch};
    }

    /** 预发布标识符；稳定版返回空列表。 */
    public List<String> prerelease() {
        return prerelease;
    }

    public boolean isPreRelease() {
        return !prerelease.isEmpty();
    }

    /** 主次补三段是否相同（用于预发布版本的区间边界判定）。 */
    public boolean sameCoreAs(SemanticVersion other) {
        return major == other.major && minor == other.minor && patch == other.patch;
    }

    @Override
    public int compareTo(SemanticVersion o) {
        if (major != o.major) {
            return Integer.compare(major, o.major);
        }
        if (minor != o.minor) {
            return Integer.compare(minor, o.minor);
        }
        if (patch != o.patch) {
            return Integer.compare(patch, o.patch);
        }
        return comparePrerelease(prerelease, o.prerelease);
    }

    private static int comparePrerelease(List<String> a, List<String> b) {
        if (a.isEmpty() && b.isEmpty()) {
            return 0;
        }
        // 同一核心版本：有预发布段者优先级更低
        if (a.isEmpty()) {
            return 1;
        }
        if (b.isEmpty()) {
            return -1;
        }
        int n = Math.min(a.size(), b.size());
        for (int i = 0; i < n; i++) {
            String x = a.get(i);
            String y = b.get(i);
            boolean xNum = isAllDigits(x);
            boolean yNum = isAllDigits(y);
            int cmp;
            if (xNum && yNum) {
                cmp = Long.compare(Long.parseLong(x), Long.parseLong(y));
            } else if (xNum) {
                cmp = -1; // 数字标识符 < 非数字标识符
            } else if (yNum) {
                cmp = 1;
            } else {
                cmp = x.compareTo(y);
            }
            if (cmp != 0) {
                return cmp;
            }
        }
        return Integer.compare(a.size(), b.size());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SemanticVersion other)) {
            return false;
        }
        return compareTo(other) == 0;
    }

    @Override
    public int hashCode() {
        int h = major;
        h = 31 * h + minor;
        h = 31 * h + patch;
        h = 31 * h + prerelease.hashCode();
        return h;
    }

    @Override
    public String toString() {
        return raw;
    }
}
