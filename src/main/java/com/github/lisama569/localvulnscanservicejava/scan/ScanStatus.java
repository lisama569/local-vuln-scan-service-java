package com.github.lisama569.localvulnscanservicejava.scan;

/** 扫描任务生命周期状态。 */
public enum ScanStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
}
