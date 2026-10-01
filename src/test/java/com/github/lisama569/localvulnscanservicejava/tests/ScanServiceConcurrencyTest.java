package com.github.lisama569.localvulnscanservicejava.tests;

import com.github.lisama569.localvulnscanservicejava.manifest.CsvManifestParser;
import com.github.lisama569.localvulnscanservicejava.manifest.CycloneDxJsonParser;
import com.github.lisama569.localvulnscanservicejava.manifest.ManifestParserRegistry;
import com.github.lisama569.localvulnscanservicejava.manifest.SpdxJsonParser;
import com.github.lisama569.localvulnscanservicejava.rules.MatchEngine;
import com.github.lisama569.localvulnscanservicejava.rules.RuleSetRepository;
import com.github.lisama569.localvulnscanservicejava.scan.ScanErrorReason;
import com.github.lisama569.localvulnscanservicejava.scan.ScanService;
import com.github.lisama569.localvulnscanservicejava.scan.ScanStatus;
import com.github.lisama569.localvulnscanservicejava.scan.ScanTask;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 扫描任务：并发重复提交幂等、取消语义、失败归一化。 */
class ScanServiceConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(ScanServiceConcurrencyTest.class);

    private final ScanService service = new ScanService(
            new ManifestParserRegistry(List.of(
                    new CycloneDxJsonParser(), new SpdxJsonParser(), new CsvManifestParser())),
            new RuleSetRepository(),
            new MatchEngine());

    private static final String MANIFEST = """
            {"bomFormat":"CycloneDX","components":[
              {"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/x/log4j-core@2.14.1"},
              {"name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}
            ]}""";

    private static ScanTask awaitTerminal(ScanService service, String taskId) {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (System.nanoTime() < deadline) {
            ScanTask t = service.get(taskId).orElseThrow();
            ScanStatus s = t.status();
            if (s == ScanStatus.COMPLETED || s == ScanStatus.FAILED || s == ScanStatus.CANCELLED) {
                return t;
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        throw new AssertionError("task did not reach terminal state: " + taskId);
    }

    @Test
    void concurrentDuplicateSubmitIsIdempotent() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<String> taskIds = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    taskIds.add(service.submit(MANIFEST));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        log.info("输入: {} 个并发提交同一制品 | 归一化: 去重后任务数={} | 判定依据: digest 相同 -> 同一任务",
                threads, taskIds.size());
        assertEquals(1, taskIds.size(), "同一制品并发提交必须幂等到同一任务");

        ScanTask task = awaitTerminal(service, taskIds.iterator().next());
        log.info("任务终态: status={} findings={} errors={}",
                task.status(),
                task.report() == null ? null : task.report().findings().size(),
                task.report() == null ? null : task.report().errors().size());
        assertEquals(ScanStatus.COMPLETED, task.status());
        assertNotNull(task.report());
        // log4j-core 2.14.1 命中 R-LOG4J-001；lodash 4.17.20 命中 R-LODASH-001
        assertEquals(2, task.report().findings().size());
        assertEquals("2026.10.01", task.report().rulesetVersion());
        // 无重复结论
        long distinct = task.report().findings().stream()
                .map(f -> f.ruleId() + "@" + f.component().name()).distinct().count();
        assertEquals(task.report().findings().size(), distinct);
    }

    @Test
    void rejectedManifestFailsWithNormalizedErrors() {
        String bad = "not a manifest";
        String taskId = service.submit(bad);
        ScanTask task = awaitTerminal(service, taskId);
        log.info("输入: {} | 终态: {} | 归一化错误: {}",
                bad, task.status(), task.report().errors());
        assertEquals(ScanStatus.FAILED, task.status());
        assertEquals(1, task.report().errors().size());
        assertEquals(ScanErrorReason.MANIFEST_REJECTED, task.report().errors().get(0).reason());
        assertTrue(task.report().errors().get(0).message().contains("UNRECOGNIZED_FORMAT"));
    }

    @Test
    void cancelPendingOrRunningTask() {
        // 构造较大清单提高取消窗口命中率
        StringBuilder sb = new StringBuilder("ecosystem,name,version\n");
        for (int i = 0; i < 5000; i++) {
            sb.append("maven,comp-").append(i).append(",1.0.0\n");
        }
        String taskId = service.submit(sb.toString());
        service.cancel(taskId);
        ScanTask task = awaitTerminal(service, taskId);
        log.info("取消后终态: status={} report={}", task.status(), task.report());
        assertTrue(task.status() == ScanStatus.CANCELLED || task.status() == ScanStatus.COMPLETED);
        if (task.status() == ScanStatus.CANCELLED) {
            // 取消的任务不得留下半截结论
            assertTrue(task.report() == null);
        }
        // 终态任务再取消返回 false
        assertFalse(service.cancel(taskId));
    }

    @Test
    void completedTaskCannotBeCancelled() {
        String taskId = service.submit(MANIFEST);
        ScanTask task = awaitTerminal(service, taskId);
        assertEquals(ScanStatus.COMPLETED, task.status());
        assertFalse(service.cancel(taskId));
        assertEquals(ScanStatus.COMPLETED, task.status());
    }

    @Test
    void distinctManifestsGetDistinctTasks() {
        String id1 = service.submit(MANIFEST);
        String id2 = service.submit(MANIFEST + " ");
        // 内容不同（尾部空格）-> 不同 digest -> 不同任务
        log.info("输入: 两份仅空白不同的清单 | 任务: {} vs {}", id1, id2);
        assertTrue(!id1.equals(id2));
    }
}
