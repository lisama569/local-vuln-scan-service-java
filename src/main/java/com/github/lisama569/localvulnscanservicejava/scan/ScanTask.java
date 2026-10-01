package com.github.lisama569.localvulnscanservicejava.scan;

import java.time.Instant;

/**
 * 扫描任务实体（内存态）。所有状态迁移经 synchronized 守护，
 * 保证取消与完成不会交错产生重复或丢失的结论。
 */
public class ScanTask {

    private final String taskId;
    private final String artifactDigest;
    private final String manifestContent;
    private final Instant createdAt;

    private ScanStatus status;
    private ScanReport report;
    private boolean cancelRequested;

    public ScanTask(String taskId, String artifactDigest, String manifestContent) {
        this.taskId = taskId;
        this.artifactDigest = artifactDigest;
        this.manifestContent = manifestContent;
        this.status = ScanStatus.PENDING;
        this.createdAt = Instant.now();
    }

    public String taskId() { return taskId; }
    public String artifactDigest() { return artifactDigest; }
    public String manifestContent() { return manifestContent; }
    public Instant createdAt() { return createdAt; }

    public synchronized ScanStatus status() { return status; }
    public synchronized ScanReport report() { return report; }
    public synchronized boolean isCancelRequested() { return cancelRequested; }

    /** PENDING -> RUNNING；已被取消则返回 false。 */
    public synchronized boolean markRunning() {
        if (status != ScanStatus.PENDING) {
            return false;
        }
        status = ScanStatus.RUNNING;
        return true;
    }

    /** 请求取消：PENDING/RUNNING -> CANCELLED 标记；终态返回 false。 */
    public synchronized boolean requestCancel() {
        if (status == ScanStatus.COMPLETED || status == ScanStatus.FAILED
                || status == ScanStatus.CANCELLED) {
            return false;
        }
        cancelRequested = true;
        if (status == ScanStatus.PENDING) {
            status = ScanStatus.CANCELLED;
        }
        return true;
    }

    /** 执行线程在检查点调用：若已请求取消则转入 CANCELLED 并返回 true。 */
    public synchronized boolean cancelIfRequested() {
        if (cancelRequested && status == ScanStatus.RUNNING) {
            status = ScanStatus.CANCELLED;
            return true;
        }
        return status == ScanStatus.CANCELLED;
    }

    /** RUNNING -> COMPLETED，报告一次性写入；非 RUNNING 返回 false。 */
    public synchronized boolean complete(ScanReport report) {
        if (status != ScanStatus.RUNNING) {
            return false;
        }
        this.report = report;
        this.status = ScanStatus.COMPLETED;
        return true;
    }

    /** RUNNING -> FAILED，报告（含归一化错误）一次性写入；非 RUNNING 返回 false。 */
    public synchronized boolean fail(ScanReport report) {
        if (status != ScanStatus.RUNNING) {
            return false;
        }
        this.report = report;
        this.status = ScanStatus.FAILED;
        return true;
    }
}
