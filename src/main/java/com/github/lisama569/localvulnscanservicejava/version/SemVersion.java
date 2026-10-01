package com.github.lisama569.localvulnscanservicejava.version;

import java.util.Arrays;
import java.util.Objects;

/**
 * 语义化版本（宽松解析）：{@code 主[.次[.补丁]][-预发布][+构建]}。
 * 缺省的次/补丁按 0 处理；构建元数据不参与比较。
 * 预发布版本按 semver 规则低于同号正式版：数字标识符小于字母标识符，
 * 数字按数值比较，字母按字典序，标识符更少者更小。
 */
public final class SemVersion implements Comparable<SemVersion> {

    private final String raw;
    private final int[] numbers;      // [major, minor, patch]
    private final String[] prerelease; // 空数组表示正式版

    private SemVersion(String raw, int[] numbers, String[] prerelease) {
        this.raw = raw;
        this.numbers = numbers;
        this.prerelease = prerelease;
    }

    public static SemVersion parse(String text) {
        if (text == null || text.isBlank()) {
            throw new InvalidVersionException("version is blank");
        }
        String v = text.trim();
        // 去掉构建元数据
        int plus = v.indexOf('+');
        if (plus >= 0) {
            v = v.substring(0, plus);
        }
        String pre = "";
        int dash = v.indexOf('-');
        if (dash >= 0) {
            pre = v.substring(dash + 1);
            v = v.substring(0, dash);
        }
        String[] parts = v.split("\\.", -1);
        if (parts.length < 1 || parts.length > 3) {
            throw new InvalidVersionException("version must have 1-3 numeric segments: " + text);
        }
        int[] nums = new int[]{0, 0, 0};
        for (int i = 0; i < parts.length; i++) {
            if (!parts[i].matches("\\d+")) {
                throw new InvalidVersionException("non-numeric segment '" + parts[i] + "' in version: " + text);
            }
            try {
                nums[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                throw new InvalidVersionException("segment too large in version: " + text);
            }
        }
        String[] preIds = new String[0];
        if (!pre.isEmpty()) {
            preIds = pre.split("\\.", -1);
            for (String id : preIds) {
                if (!id.matches("[0-9A-Za-z-]+")) {
                    throw new InvalidVersionException("illegal prerelease identifier '" + id + "' in version: " + text);
                }
            }
        }
        return new SemVersion(text.trim(), nums, preIds);
    }

    public boolean isPrerelease() {
        return prerelease.length > 0;
    }

    @Override
    public int compareTo(SemVersion other) {
        for (int i = 0; i < 3; i++) {
            int c = Integer.compare(this.numbers[i], other.numbers[i]);
            if (c != 0) {
                return c;
            }
        }
        // 正式版 > 预发布版
        if (this.prerelease.length == 0 && other.prerelease.length == 0) {
            return 0;
        }
        if (this.prerelease.length == 0) {
            return 1;
        }
        if (other.prerelease.length == 0) {
            return -1;
        }
        int n = Math.min(this.prerelease.length, other.prerelease.length);
        for (int i = 0; i < n; i++) {
            int c = compareIdentifier(this.prerelease[i], other.prerelease[i]);
            if (c != 0) {
                return c;
            }
        }
        return Integer.compare(this.prerelease.length, other.prerelease.length);
    }

    private static int compareIdentifier(String a, String b) {
        boolean an = a.chars().allMatch(Character::isDigit);
        boolean bn = b.chars().allMatch(Character::isDigit);
        if (an && bn) {
            return Long.compare(Long.parseLong(a), Long.parseLong(b));
        }
        if (an) {
            return -1; // 数字 < 字母
        }
        if (bn) {
            return 1;
        }
        return a.compareTo(b);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SemVersion other && compareTo(other) == 0;
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(numbers), Arrays.hashCode(prerelease));
    }

    @Override
    public String toString() {
        return raw;
    }
}
