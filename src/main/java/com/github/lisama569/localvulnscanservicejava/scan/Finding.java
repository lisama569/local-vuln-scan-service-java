package com.github.lisama569.localvulnscanservicejava.scan;

import com.github.lisama569.localvulnscanservicejava.model.Component;

/**
 * 一条命中结论。
 *
 * @param ruleId      命中规则
 * @param vulnId      漏洞编号
 * @param severity    严重度
 * @param component   受影响组件
 * @param explanation 判定依据（版本如何落入区间、多条规则如何仲裁）
 */
public record Finding(String ruleId, String vulnId, String severity,
                      Component component, String explanation) {
}
