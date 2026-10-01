package com.github.lisama569.localvulnscanservicejava.tests;

import com.github.lisama569.localvulnscanservicejava.version.InvalidVersionException;
import com.github.lisama569.localvulnscanservicejava.version.SemanticVersion;
import com.github.lisama569.localvulnscanservicejava.version.VersionRange;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 版本解析与区间边界、预发布门槛、版本混淆（01/2.0/2.0.0）测试。 */
class VersionSemanticsTest {

    private static final Logger log = LoggerFactory.getLogger(VersionSemanticsTest.class);

    private void logCase(String input, String normalized, String decision) {
        System.out.println("[版本判定] 输入=" + input + " | 归一化=" + normalized + " | 判定=" + decision);
        log.info("输入={} | 归一化={} | 判定={}", input, normalized, decision);
    }

    @Test
    void parsesLooseSegmentsAndRejectsLeadingZero() {
        assertEquals(2, SemanticVersion.parse("2").major());
        assertEquals(0, SemanticVersion.parse("2").minor());
        assertEquals(0, SemanticVersion.parse("2.4").patch());
        assertEquals(0, SemanticVersion.parse("2.4.0").compareTo(SemanticVersion.parse("2.4")));
        assertThrows(InvalidVersionException.class, () -> SemanticVersion.parse("01.2.3"));
        assertThrows(InvalidVersionException.class, () -> SemanticVersion.parse("1.02.3"));
        assertThrows(InvalidVersionException.class, () -> SemanticVersion.parse("1.2.x"));
        assertThrows(InvalidVersionException.class, () -> SemanticVersion.parse(""));
        assertThrows(InvalidVersionException.class, () -> SemanticVersion.parse("v1.2.3"));
        log.info("宽松解析/前导零拒绝通过");
    }

    @Test
    void prereleasePrecedenceFollowsSemVer() {
        // 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-rc.1 < 1.0.0
        assertTrue(v("1.0.0-alpha").compareTo(v("1.0.0-alpha.1")) < 0);
        assertTrue(v("1.0.0-alpha.1").compareTo(v("1.0.0-alpha.beta")) < 0);
        assertTrue(v("1.0.0-alpha.beta").compareTo(v("1.0.0-beta")) < 0);
        assertTrue(v("1.0.0-beta").compareTo(v("1.0.0-rc.1")) < 0);
        assertTrue(v("1.0.0-rc.1").compareTo(v("1.0.0")) < 0);
        // 数字标识符 < 非数字标识符
        assertTrue(v("1.0.0-1").compareTo(v("1.0.0-alpha")) < 0);
        logCase("1.0.0-rc.1 vs 1.0.0", "SemVer 优先级",
                v("1.0.0-rc.1").compareTo(v("1.0.0")) < 0 ? "rc1 < stable" : "WRONG");
    }

    @Test
    void inclusiveAndExclusiveBoundariesAreExact() {
        VersionRange range = VersionRange.parse(">=2.0.0 <2.17.1");
        // 闭边界恰好包含
        assertTrue(range.contains(v("2.0.0")));
        // 开边界恰好不包含（版本混淆重点：2.17.1 不是 2.17）
        assertFalse(range.contains(v("2.17.1")));
        assertFalse(range.contains(v("1.17.0")));
        assertTrue(range.contains(v("2.17.0")));

        VersionRange closed = VersionRange.parse(">=1.0.0 <=1.2.3");
        assertTrue(closed.contains(v("1.2.3")));
        assertFalse(closed.contains(v("1.2.4")));

        VersionRange eq = VersionRange.parse("=1.2.3");
        assertTrue(eq.contains(v("1.2.3")));
        // 1.2.3-0 是预发布，优先级低于 1.2.3
        assertFalse(eq.contains(v("1.2.3-0")));
        logCase("2.17.1", range.expression(), range.contains(v("2.17.1")) + " (应为 false)");
        logCase("2.0.0", range.expression(), range.contains(v("2.0.0")) + " (应为 true)");
    }

    @Test
    void prereleaseRequiresSameCoreBound() {
        VersionRange range = VersionRange.parse(">=1.0.0 <2.0.0");
        // 相邻核心版本（没有任何严格边界落在 1.5.0）的预发布不被宽区间命中
        assertFalse(range.contains(v("1.5.0-beta")));
        // 2.0.0-alpha 与严格上界 <2.0.0 同核心，且 2.0.0-alpha < 2.0.0，按语义命中
        assertTrue(range.contains(v("2.0.0-alpha")));
        VersionRange range2 = VersionRange.parse(">=1.5.0 <2.0.0");
        // 下界是闭边界，不放行预发布；且 rc1 优先级低于 1.5.0，普通比较即排除
        assertFalse(range2.contains(v("1.5.0-rc1")));
        assertFalse(range2.contains(v("1.4.0-rc1")));
        assertFalse(range2.contains(v("1.5.0-alpha")));
        // 出现与预发布同核心的严格下界时放行，再由普通比较决定
        VersionRange range3 = VersionRange.parse(">1.5.0-beta <=2.0.0");
        assertTrue(range3.contains(v("1.5.0-rc1")));
        assertTrue(range3.contains(v("1.5.0")));
        logCase("1.5.0-rc1", range3.expression(),
                range3.contains(v("1.5.0-rc1")) + " (与严格下界同核心, 应为 true)");
        logCase("1.5.0-rc1", range2.expression(),
                range2.contains(v("1.5.0-rc1")) + " (仅闭下界同核心, 应为 false)");
        logCase("2.0.0-alpha", range.expression(),
                range.contains(v("2.0.0-alpha")) + " (与严格上界同核心, 应为 true)");
        logCase("1.5.0-beta", range.expression(),
                range.contains(v("1.5.0-beta")) + " (无同核心严格边界, 应为 false)");
    }

    @Test
    void invalidRangesAreRejectedWithDistinguishableReason() {
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse(">= 1.0.0 <not-a-version"));
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse(""));
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse("=="));
        assertThrows(InvalidVersionException.class, () -> VersionRange.parse(">1.2.3.4"));
        log.info("非法区间全部拒绝通过");
    }

    private static SemanticVersion v(String s) {
        return SemanticVersion.parse(s);
    }
}
