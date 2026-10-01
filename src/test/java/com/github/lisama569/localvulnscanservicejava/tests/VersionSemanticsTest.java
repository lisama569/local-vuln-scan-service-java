package com.github.lisama569.localvulnscanservicejava.tests;

import com.github.lisama569.localvulnscanservicejava.version.InvalidVersionException;
import com.github.lisama569.localvulnscanservicejava.version.SemVersion;
import com.github.lisama569.localvulnscanservicejava.version.VersionRange;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 版本解析与区间匹配语义：边界与预发布版本。 */
class VersionSemanticsTest {

    private static final Logger log = LoggerFactory.getLogger(VersionSemanticsTest.class);

    private void check(String range, String version, boolean expected) {
        boolean actual = VersionRange.parse(range).contains(SemVersion.parse(version));
        log.info("输入: range={} version={} | 归一化: range={} version={} | 判定: contains={} (期望 {})",
                range, version, VersionRange.parse(range), SemVersion.parse(version), actual, expected);
        assertEquals(expected, actual);
    }

    @Test
    void prereleaseIsLowerThanRelease() {
        assertTrue(SemVersion.parse("2.0.0-rc1").compareTo(SemVersion.parse("2.0.0")) < 0);
        assertTrue(SemVersion.parse("1.0.0-alpha").compareTo(SemVersion.parse("1.0.0-alpha.1")) < 0);
        assertTrue(SemVersion.parse("1.0.0-alpha.1").compareTo(SemVersion.parse("1.0.0-alpha.beta")) < 0);
        assertTrue(SemVersion.parse("1.0.0-2").compareTo(SemVersion.parse("1.0.0-10")) < 0);
    }

    @Test
    void buildMetadataIgnored() {
        assertEquals(0, SemVersion.parse("1.2.3+build.5").compareTo(SemVersion.parse("1.2.3")));
    }

    @Test
    void missingSegmentsDefaultToZero() {
        assertEquals(0, SemVersion.parse("1.2").compareTo(SemVersion.parse("1.2.0")));
        assertEquals(0, SemVersion.parse("2").compareTo(SemVersion.parse("2.0.0")));
    }

    @Test
    void invalidVersionsRejected() {
        assertThrows(InvalidVersionException.class, () -> SemVersion.parse(""));
        assertThrows(InvalidVersionException.class, () -> SemVersion.parse("1.2.x"));
        assertThrows(InvalidVersionException.class, () -> SemVersion.parse("1.2.3.4"));
        assertThrows(InvalidVersionException.class, () -> SemVersion.parse("1.0-rc_1"));
    }

    @Test
    void comparatorRangeBoundaries() {
        check(">=2.0.0,<2.15.0", "2.0.0", true);    // 下边界包含
        check(">=2.0.0,<2.15.0", "2.15.0", false);  // 上边界排除
        check(">=2.0.0,<2.15.0", "2.14.1", true);
        check(">=2.0.0,<2.15.0", "1.9.9", false);
    }

    @Test
    void prereleaseSemanticsInRanges() {
        // 预发布版本严格按 semver 排序：2.0.0-rc1 < 2.0.0
        check(">=2.0.0", "2.0.0-rc1", false);
        check("<2.0.0", "2.0.0-rc1", true);
        check("[2.0.0-rc1,2.0.0]", "2.0.0-rc1", true);
    }

    @Test
    void bracketRangeBoundaries() {
        check("[2.15.0,2.16.0)", "2.15.0", true);
        check("[2.15.0,2.16.0)", "2.16.0", false);
        check("(1.0,2.0]", "1.0", false);
        check("(1.0,2.0]", "2.0", true);
        check("[,2.0)", "1.99", true);   // 无下界
        check("[2.0,]", "99.0", true);   // 无上界
    }

    @Test
    void exactVersion() {
        check("1.2.3", "1.2.3", true);
        check("1.2.3", "1.2.4", false);
        check("[1.2.3]", "1.2.3", true);
        check("[1.2.3]", "1.2.3-rc1", false);
    }

    @Test
    void invalidRangeSpecsRejected() {
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse(""));
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse("[1.0,2.0"));
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse("(1.0)"));
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse("~1.2.3"));
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse("(,)"));
    }
}
