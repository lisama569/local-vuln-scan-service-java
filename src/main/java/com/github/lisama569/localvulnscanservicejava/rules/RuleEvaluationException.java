package com.github.lisama569.localvulnscanservicejava.rules;

/** 单条规则求值失败（如规则内区间非法）时抛出。 */
public class RuleEvaluationException extends RuntimeException {

    private final String ruleId;

    public RuleEvaluationException(String ruleId, String message, Throwable cause) {
        super(message, cause);
        this.ruleId = ruleId;
    }

    public String ruleId() {
        return ruleId;
    }
}
