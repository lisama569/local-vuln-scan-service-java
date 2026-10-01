package com.github.lisama569.localvulnscanservicejava.scan;

import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.RuleError;
import com.github.lisama569.localvulnscanservicejava.model.RuleSet;
import com.github.lisama569.localvulnscanservicejava.model.ScanFinding;
import com.github.lisama569.localvulnscanservicejava.model.ScanStatus;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 一个扫描任务的可变聚合根：CAS 式状态迁移 + 内置锁保证
 * 取消 / 失败重试 / 重复提交不产生重复或丢失结论。
 */
public class ScanTask {

    private final String scanId;
    private final String artifactHash;
    private final String rawContent;
    private String ruleSetVersion;
    private final Instant createdAt;
    private final ReentrantLock lock = new ReentrantLock();

    private ScanStatus status = ScanStatus.PENDING;
    private Manifest manifest;
    private RuleSet ruleSet;
    private ErrorCode errorCode;
    private String errorMessage;
    private List<ScanFinding> findings = new ArrayList<>();
    private List<RuleError> ruleErrors = new ArrayList<>();
    private Instant startedAt;
    private Instant finishedAt;

    public ScanTask(String scanId, String artifactHash, String rawContent, String ruleSetVersion) {
        this.scanId = scanId;
        this.artifactHash = artifactHash;
        this.rawContent = rawContent;
        this.ruleSetVersion = ruleSetVersion;
        this.createdAt = Instant.now();
    }


    /** 重试：在任务锁内把任务恢复为一次全新执行，旧错误与旧结论整体清除。 */
    public void prepareForRetry(RuleSet newRuleSet) {
        if (status != ScanStatus.FAILED) {
            throw new IllegalStateException("仅 FAILED 任务可重试，当前 " + status);
        }
        this.status = ScanStatus.PENDING;
        this.ruleSet = newRuleSet;
        this.ruleSetVersion = newRuleSet.version();
        this.errorCode = null;
        this.errorMessage = null;
        this.findings = new ArrayList<>();
        this.ruleErrors = new ArrayList<>();
        this.manifest = null;
        this.startedAt = null;
        this.finishedAt = null;
    }

    public ReentrantLock lock() {
        return lock;
    }

    public String scanId() { return scanId; }
    public String artifactHash() { return artifactHash; }
    public String rawContent() { return rawContent; }
    public String ruleSetVersion() { return ruleSetVersion; }
    public Instant createdAt() { return createdAt; }
    public ScanStatus status() { return status; }
    public void status(ScanStatus s) { this.status = s; }
    public Manifest manifest() { return manifest; }
    public void manifest(Manifest m) { this.manifest = m; }
    public RuleSet ruleSet() { return ruleSet; }
    public void ruleSet(RuleSet r) { this.ruleSet = r; }
    public ErrorCode errorCode() { return errorCode; }
    public String errorMessage() { return errorMessage; }
    public void fail(ErrorCode code, String message) {
        this.errorCode = code;
        this.errorMessage = message;
        this.status = ScanStatus.FAILED;
        this.finishedAt = Instant.now();
    }
    public List<ScanFinding> findings() { return findings; }
    public void findings(List<ScanFinding> f) { this.findings = f; }
    public List<RuleError> ruleErrors() { return ruleErrors; }
    public void ruleErrors(List<RuleError> e) { this.ruleErrors = e; }
    public Instant startedAt() { return startedAt; }
    public void markStarted() { this.startedAt = Instant.now(); this.status = ScanStatus.RUNNING; }
    public Instant finishedAt() { return finishedAt; }
    public void complete() { this.status = ScanStatus.COMPLETED; this.finishedAt = Instant.now(); }
    public void cancel() { this.status = ScanStatus.CANCELLED; this.finishedAt = Instant.now(); }
}
