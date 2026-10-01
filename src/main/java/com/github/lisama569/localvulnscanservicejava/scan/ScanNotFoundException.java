package com.github.lisama569.localvulnscanservicejava.scan;

/** 查询的扫描任务不存在。 */
public class ScanNotFoundException extends RuntimeException {
    public ScanNotFoundException(String scanId) {
        super("scan not found: " + scanId);
    }
}
