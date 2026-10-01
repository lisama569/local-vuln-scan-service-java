package com.github.lisama569.localvulnscanservicejava.model;

/** 漏洞严重等级，rank 越大越严重，用于多规则命中时的确定性排序。 */
public enum Severity {
    LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

    private final int rank;

    Severity(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }
}
