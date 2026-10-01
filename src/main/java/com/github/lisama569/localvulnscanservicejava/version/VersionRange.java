package com.github.lisama569.localvulnscanservicejava.version;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 受影响版本区间：以逗号或空白分隔的比较式集合，版本需同时满足全部比较式（逻辑与）。
 * 支持运算符 {@code >= > <= < =}（单个裸版本等价于 {@code =}），例如
 * {@code ">=1.0.0 <2.0.0"} 或 {@code ">=1.2.0,<=1.4.2"}。
 *
 * <h3>边界语义</h3>
 * 比较在 SemVer 2.0 优先级上进行，含等号运算符为闭区间，不含等号为开区间；
 * 因此 {@code >=1.0.0} 恰好包含 {@code 1.0.0}，{@code >1.0.0} 不包含。
 *
 * <h3>预发布版本语义</h3>
 * 采用类似 npm 的预发布门槛规则：当候选版本是预发布版本（带 {@code -...}）时，
 * 仅当区间中<strong>至少一个“严格边界”（{@code >} 或 {@code <}，不含等号）与候选版本
 * 核心三段（major.minor.patch）相同</strong>时才可能命中。
 * 闭边界（{@code >= <= =}）不参与门槛放行，只按普通优先级比较——因此预发布版本
 * 不会因为恰好等于闭下界（优先级反而更低）被错误纳入。例如：
 * <ul>
 *   <li>{@code >=1.0.0 <2.0.0} 命中 {@code 2.0.0-alpha}（与开上界同核心且 2.0.0-alpha&lt;2.0.0），
 *       不命中 {@code 1.5.0-beta}（没有任何严格边界落在 1.5.0）；</li>
 *   <li>{@code >=1.5.0 <2.0.0} 不命中 {@code 1.5.0-rc1}（下界虽同核心但是闭边界，
 *       且 rc1 优先级低于 1.5.0，普通比较即排除）；</li>
 *   <li>{@code >1.5.0-beta <=2.0.0} 命中 {@code 1.5.0-rc1}（与严格下界同核心）。</li>
 * </ul>
 */
public final class VersionRange {

    private enum Op {
        GE, GT, LE, LT, EQ
    }

    private record Constraint(Op op, SemanticVersion bound) {
        boolean satisfiedBy(SemanticVersion v) {
            int cmp = v.compareTo(bound);
            return switch (op) {
                case GE -> cmp >= 0;
                case GT -> cmp > 0;
                case LE -> cmp <= 0;
                case LT -> cmp < 0;
                case EQ -> cmp == 0;
            };
        }
    }

    /** 单段比较式：可选运算符（允许运算符与版本间有空白）+ 版本。 */
    private static final Pattern TERM = Pattern.compile(
            "^\\s*(>=|<=|>|<|=)?\\s*(\\S+?)\\s*$");

    private final String expression;
    private final List<Constraint> constraints;

    private VersionRange(String expression, List<Constraint> constraints) {
        this.expression = expression;
        this.constraints = List.copyOf(constraints);
    }

    public static VersionRange parse(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            throw new InvalidVersionException("版本区间为空");
        }
        List<Constraint> constraints = new ArrayList<>();
        for (String part : expression.split("[,\\s]+")) {
            String term = part.trim();
            if (term.isEmpty()) {
                continue;
            }
            Matcher m = TERM.matcher(term);
            if (!m.matches()) {
                throw new InvalidVersionException("非法版本区间表达式: '" + expression + "'（无法解析片段 '" + term + "'）");
            }
            String opText = m.group(1);
            String verText = m.group(2);
            if (verText.equals(">") || verText.equals("<") || verText.equals(">=")
                    || verText.equals("<=") || verText.equals("=")) {
                throw new InvalidVersionException("比较式缺少版本号: '" + term + "'");
            }
            Op op = switch (opText == null ? "=" : opText) {
                case ">=" -> Op.GE;
                case ">" -> Op.GT;
                case "<=" -> Op.LE;
                case "<" -> Op.LT;
                case "=" -> Op.EQ;
                default -> throw new InvalidVersionException("未知比较运算符: '" + opText + "'");
            };
            SemanticVersion bound;
            try {
                bound = SemanticVersion.parse(verText);
            } catch (InvalidVersionException e) {
                throw new InvalidVersionException(
                        "版本区间边界不是合法语义化版本: '" + verText + "'（区间 '" + expression + "'）", e);
            }
            constraints.add(new Constraint(op, bound));
        }
        if (constraints.isEmpty()) {
            throw new InvalidVersionException("版本区间不包含任何比较式: '" + expression + "'");
        }
        return new VersionRange(expression, constraints);
    }

    public String expression() {
        return expression;
    }

    public boolean contains(SemanticVersion version) {
        if (version.isPreRelease()) {
            boolean strictBoundOnSameCore = false;
            for (Constraint c : constraints) {
                if ((c.op == Op.GT || c.op == Op.LT) && version.sameCoreAs(c.bound)) {
                    strictBoundOnSameCore = true;
                    break;
                }
            }
            if (!strictBoundOnSameCore) {
                return false;
            }
        }
        for (Constraint c : constraints) {
            if (!c.satisfiedBy(version)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return expression;
    }
}
