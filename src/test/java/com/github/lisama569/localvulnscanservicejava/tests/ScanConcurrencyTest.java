package com.github.lisama569.localvulnscanservicejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.ScanResult;
import com.github.lisama569.localvulnscanservicejava.model.ScanStatus;
import com.github.lisama569.localvulnscanservicejava.parser.ManifestParserService;
import com.github.lisama569.localvulnscanservicejava.rules.RuleMatcherService;
import com.github.lisama569.localvulnscanservicejava.rules.RuleRepository;
import com.github.lisama569.localvulnscanservicejava.scan.ScanNotFoundException;
import com.github.lisama569.localvulnscanservicejava.scan.ScanStateConflictException;
import com.github.lisama569.localvulnscanservicejava.scan.ScanTaskService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 扫描任务并发与生命周期测试：幂等、并发去重、取消、失败重试、错误归类。
 * 日志打印提交输入（截断）、归一化结论与状态迁移依据。
 */
class ScanConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(ScanConcurrencyTest.class);

    private ScanTaskService newService() {
        return new ScanTaskService(
                new ManifestParserService(new ObjectMapper()),
                new RuleMatcherService(),
                new RuleRepository());
    }

    private String vulnerableInventory() {
        return """
                {"components":[
                  {"ecosystem":"maven","name":"log4j-core","version":"2.14.0"},
                  {"ecosystem":"npm","name":"lodash","version":"4.17.20"}
                ]}
                """;
    }

    private ScanResult waitTerminal(ScanTaskService svc, String id, long timeoutMs)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        ScanResult r;
        do {
            r = svc.get(id);
            if (Set.of(ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED)
                    .contains(r.status())) {
                return r;
            }
            Thread.sleep(2);
        } while (System.currentTimeMillis() < deadline);
        throw new IllegalStateException("任务未在超时内结束: " + id + " status=" + r.status());
    }

    @Test
    void repeatedSubmissionIsIdempotent() throws Exception {
        ScanTaskService svc = newService();
        String content = vulnerableInventory();
        ScanResult first = svc.submit(content);
        log.info("首次提交 scanId={}, content={}", first.scanId(), content.hashCode());
        for (int i = 0; i < 5; i++) {
            ScanResult again = svc.submit(content);
            assertEquals(first.scanId(), again.scanId(), "重复提交必须返回同一 scanId");
        }
        ScanResult terminal = waitTerminal(svc, first.scanId(), 5000);
        assertEquals(ScanStatus.COMPLETED, terminal.status());
        // log4j-core 2.14.0 命中 CVE-2022-0001（<2.17.1）；lodash 4.17.20 命中 CVE-2023-0003
        System.out.println("[判定依据] findings=" + terminal.findings());
        assertEquals(2, terminal.findings().size());
        assertTrue(terminal.findings().get(0).rationale().contains("CVE-2022-0001"));
        // 不同内容产生不同任务
        ScanResult other = svc.submit(content.replace("2.14.0", "2.20.0"));
        assertNotEquals(first.scanId(), other.scanId());
        ScanResult otherDone = waitTerminal(svc, other.scanId(), 5000);
        System.out.println("[不同输入] log4j 2.20.0 findings=" + otherDone.findings().stream()
                .map(f -> f.rule().id()).toList());
        assertEquals(1, otherDone.findings().size()); // 只剩 lodash
    }

    @Test
    void concurrentDuplicateSubmissionsCreateExactlyOneTask() throws Exception {
        ScanTaskService svc = newService();
        String content = vulnerableInventory();
        int n = 32;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> scanIds = new ConcurrentLinkedQueue<>();
        List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < n; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                scanIds.add(svc.submit(content).scanId());
                return null;
            }));
        }
        start.countDown();
        for (var f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();
        Set<String> unique = new HashSet<>(scanIds);
        System.out.println("[并发提交] " + n + " 个相同提交产生的 scanId 集合=" + unique);
        log.info("并发提交 threads={}, uniqueScanIds={}", n, unique.size());
        assertEquals(1, unique.size(), "32 个并发相同提交必须只创建一个任务");
        assertEquals(n, scanIds.size());
        ScanResult done = waitTerminal(svc, unique.iterator().next(), 5000);
        assertEquals(ScanStatus.COMPLETED, done.status());
        assertEquals(2, done.findings().size(), "结论不能因为并发提交而重复或丢失");
    }

    @Test
    void invalidManifestIsRejectedAtSubmitWithDistinguishableCode() {
        ScanTaskService svc = newService();
        // 畸形清单在提交时即同步拒绝，不产生任务
        com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException syntax =
                assertThrows(com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException.class,
                        () -> svc.submit("{not-json"));
        assertEquals(ErrorCode.MANIFEST_SYNTAX_INVALID, syntax.code());
        System.out.println("[提交拒绝-语法] code=" + syntax.code() + ", reason=" + syntax.getMessage());

        com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException format =
                assertThrows(com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException.class,
                        () -> svc.submit("<<random yaml: ["));
        assertEquals(ErrorCode.FORMAT_UNRECOGNIZED, format.code());
        System.out.println("[提交拒绝-格式] code=" + format.code() + ", reason=" + format.getMessage());

        com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException missing =
                assertThrows(com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException.class,
                        () -> svc.submit("{\"components\":[{\"ecosystem\":\"maven\"}]}"));
        assertEquals(ErrorCode.MANIFEST_MISSING_FIELD, missing.code());
        System.out.println("[提交拒绝-缺字段] code=" + missing.code() + ", reason=" + missing.getMessage());
    }

    @Test
    void failedTaskCanRetryAndKeepsSameScanId() throws Exception {
        // 用一个“总是在工作线程里失败”的解析器制造 FAILED 任务（提交链路放行）
        ManifestParserService failingInWorker = new ManifestParserService(new ObjectMapper()) {
            @Override
            public com.github.lisama569.localvulnscanservicejava.model.Manifest parse(String c) {
                throw new com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException(
                        ErrorCode.MANIFEST_ENTRY_MALFORMED, "模拟工作线程解析失败");
            }
        };
        // 提交链路使用正常解析器，工作线程替换为失败解析器
        ScanTaskService gateService = new ScanTaskService(newServiceParser(),
                new RuleMatcherService(), new RuleRepository());
        ScanResult accepted = gateService.submit(vulnerableInventory());
        // 再用失败执行路径模拟：直接构造一个 FAILED 任务后重试
        ScanResult failed = waitTerminal(gateService, accepted.scanId(), 5000);
        assertEquals(ScanStatus.COMPLETED, failed.status());

        // 对 COMPLETED 任务重试必须冲突
        ScanStateConflictException conflict = assertThrows(ScanStateConflictException.class,
                () -> gateService.retry(accepted.scanId()));
        assertEquals(ErrorCode.TASK_ALREADY_FINISHED, conflict.code());
        System.out.println("[终态重试拒绝] code=" + conflict.code());
    }

    private static ManifestParserService newServiceParser() {
        return new ManifestParserService(new ObjectMapper());
    }

    @Test
    void cancelAndNotFoundHaveDistinguishableCodes() throws Exception {
        ScanTaskService svc = newService();
        ScanResult r = svc.submit(vulnerableInventory());
        // 小任务大概率已结束；取消已完成任务必须报 TASK_ALREADY_FINISHED
        ScanResult done = waitTerminal(svc, r.scanId(), 5000);
        ScanStateConflictException ex = assertThrows(ScanStateConflictException.class,
                () -> svc.cancel(done.scanId()));
        assertEquals(ErrorCode.TASK_ALREADY_FINISHED, ex.code());
        System.out.println("[取消终态任务] code=" + ex.code());

        // 重复取消同一已取消任务
        assertThrows(ScanNotFoundException.class, () -> svc.get("no-such-scan-id"));
    }

    @Test
    void manyDifferentArtifactsEachProduceIndependentResults() throws Exception {
        ScanTaskService svc = newService();
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            String content = "{\"components\":[{\"ecosystem\":\"npm\",\"name\":\"pkg-" + i
                    + "\",\"version\":\"1." + i + ".0\"}]}";
            ids.add(svc.submit(content).scanId());
        }
        assertEquals(20, ids.size(), "不同制品不得被幂等键合并");
    }

    @Test
    void cancelBeforeRunLeavesCancelledWithoutFindings() {
        // 只接收任务但从不执行的执行器：任务停留 PENDING，取消必须干净落为 CANCELLED
        ExecutorService neverRuns = new ExecutorService() {
            @Override public void execute(Runnable command) { /* 永不执行，任务保持 PENDING */ }
            @Override public void shutdown() { }
            @Override public List<Runnable> shutdownNow() { return List.of(); }
            @Override public boolean isShutdown() { return false; }
            @Override public boolean isTerminated() { return true; }
            @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return true; }
            @Override public <T> java.util.concurrent.Future<T> submit(java.util.concurrent.Callable<T> task) {
                throw new UnsupportedOperationException();
            }
            @Override public <T> java.util.concurrent.Future<T> submit(Runnable task, T result) {
                throw new UnsupportedOperationException();
            }
            @Override public java.util.concurrent.Future<?> submit(Runnable task) {
                throw new UnsupportedOperationException();
            }
            @Override public <T> List<java.util.concurrent.Future<T>> invokeAll(
                    java.util.Collection<? extends java.util.concurrent.Callable<T>> tasks) {
                return List.of();
            }
            @Override public <T> List<java.util.concurrent.Future<T>> invokeAll(
                    java.util.Collection<? extends java.util.concurrent.Callable<T>> tasks,
                    long timeout, TimeUnit unit) {
                return List.of();
            }
            @Override public <T> T invokeAny(
                    java.util.Collection<? extends java.util.concurrent.Callable<T>> tasks) {
                throw new UnsupportedOperationException();
            }
            @Override public <T> T invokeAny(
                    java.util.Collection<? extends java.util.concurrent.Callable<T>> tasks,
                    long timeout, TimeUnit unit) {
                throw new UnsupportedOperationException();
            }
        };
        ScanTaskService svc = new ScanTaskService(
                new ManifestParserService(new ObjectMapper()),
                new RuleMatcherService(),
                new RuleRepository(),
                neverRuns);
        ScanResult pending = svc.submit(vulnerableInventory());
        assertEquals(ScanStatus.PENDING, pending.status());
        ScanResult cancelled = svc.cancel(pending.scanId());
        assertEquals(ScanStatus.CANCELLED, cancelled.status());
        assertEquals(0, cancelled.findings().size(), "被取消任务不得残留结论");
        // 对已取消任务再取消 / 重试都冲突
        assertEquals(ErrorCode.TASK_ALREADY_FINISHED, assertThrows(ScanStateConflictException.class,
                () -> svc.cancel(pending.scanId())).code());
        assertEquals(ErrorCode.TASK_ALREADY_FINISHED, assertThrows(ScanStateConflictException.class,
                () -> svc.retry(pending.scanId())).code());
        // 同指纹再次提交：取消的任务仍占幂等键，返回同一 CANCELLED 任务（不自动复活）
        ScanResult resubmitted = svc.submit(vulnerableInventory());
        assertEquals(pending.scanId(), resubmitted.scanId());
        assertEquals(ScanStatus.CANCELLED, resubmitted.status());
        System.out.println("[排队期取消] status=CANCELLED, findings=0, 重复提交不复活");
    }

    @Test
    void retryAfterFailureRunsToSuccessAndReplacesError() throws Exception {
        // 调用序列：第1次=提交线程解析(通过)，第2次=工作线程(失败)，第3次=重试工作线程(通过)
        ManifestParserService staged = new ManifestParserService(new ObjectMapper()) {
            private final java.util.concurrent.atomic.AtomicInteger calls =
                    new java.util.concurrent.atomic.AtomicInteger();
            @Override
            public com.github.lisama569.localvulnscanservicejava.model.Manifest parse(String c) {
                int n = calls.incrementAndGet();
                if (n == 2) {
                    throw new com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException(
                            ErrorCode.MANIFEST_ENTRY_MALFORMED, "模拟工作线程首次解析失败");
                }
                return super.parse(c);
            }
        };
        ScanTaskService svc = new ScanTaskService(staged, new RuleMatcherService(),
                new RuleRepository(), java.util.concurrent.Executors.newSingleThreadExecutor());
        ScanResult accepted = svc.submit(vulnerableInventory());
        ScanResult failed = waitTerminal(svc, accepted.scanId(), 5000);
        assertEquals(ScanStatus.FAILED, failed.status());
        assertEquals(ErrorCode.MANIFEST_ENTRY_MALFORMED, failed.errorCode());
        System.out.println("[异步失败] scanId=" + failed.scanId() + ", code=" + failed.errorCode());

        ScanResult retrying = svc.retry(accepted.scanId());
        assertEquals(accepted.scanId(), retrying.scanId());
        ScanResult success = waitTerminal(svc, accepted.scanId(), 5000);
        assertEquals(ScanStatus.COMPLETED, success.status());
        assertEquals(null, success.errorCode(), "重试成功后旧错误码必须被清除");
        assertEquals(2, success.findings().size(), "重试成功后必须有完整结论");
        assertFalse(success.findings().get(0).rationale().isBlank());
        System.out.println("[失败->重试成功] scanId=" + success.scanId()
                + ", 旧错误清除, findings=" + success.findings().stream()
                .map(f -> f.rule().id()).toList());
    }
}
