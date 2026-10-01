package com.github.lisama569.localvulnscanservicejava.scan;

import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.model.Manifest;
import com.github.lisama569.localvulnscanservicejava.model.RuleSet;
import com.github.lisama569.localvulnscanservicejava.model.ScanResult;
import com.github.lisama569.localvulnscanservicejava.model.ScanStatus;
import com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException;
import com.github.lisama569.localvulnscanservicejava.parser.ManifestParserService;
import com.github.lisama569.localvulnscanservicejava.rules.RuleMatcherService;
import com.github.lisama569.localvulnscanservicejava.rules.RuleRepository;
import com.github.lisama569.localvulnscanservicejava.util.Hashes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 扫描任务生命周期与并发控制。
 *
 * <h3>幂等</h3>
 * 提交内容先算 SHA-256 指纹；同一指纹的重复提交（无论并发与否）返回同一个 scanId
 * 与同一结论，绝不创建第二个任务。
 *
 * <h3>状态迁移（任务锁内 CAS）</h3>
 * <pre>
 *   PENDING -> RUNNING -> COMPLETED / FAILED / CANCELLED
 *   FAILED -> PENDING（仅 retry）；排队期间取消则工作线程直接退出
 * </pre>
 * 终态（COMPLETED/CANCELLED）不可重试或取消；非法迁移抛 TASK_ALREADY_FINISHED。
 *
 * <h3>取消与失败重试</h3>
 * 取消仅对 PENDING/RUNNING 有效；工作线程在解析完成、落结论前再次检查取消标记，
 * 取消的任务不写任何结论。FAILED 任务重试复用同一 scanId，通过 prepareForRetry
 * 把旧错误与旧结论整体清除后重新排队，不存在新旧结论并存或丢失。
 *
 * <h3>任务级失败 vs 规则级失败</h3>
 * 解析 / 规则集加载异常使任务 FAILED（携带可区分 ErrorCode）；
 * 单条规则匹配异常只出现在 result.ruleErrors 中，任务仍 COMPLETED。
 */
@Service
public class ScanTaskService {

    private static final Logger log = LoggerFactory.getLogger(ScanTaskService.class);

    private final ConcurrentHashMap<String, ScanTask> tasksById = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> scanIdByArtifact = new ConcurrentHashMap<>();
    private final ExecutorService executor;
    private final AtomicInteger inFlight = new AtomicInteger(0);
    private final ManifestParserService parserService;
    private final RuleMatcherService matcherService;
    private final RuleRepository ruleRepository;

    @Autowired
    public ScanTaskService(ManifestParserService parserService,
                           RuleMatcherService matcherService,
                           RuleRepository ruleRepository) {
        this(parserService, matcherService, ruleRepository,
                Executors.newFixedThreadPool(4, r -> {
                    Thread t = new Thread(r, "scan-worker");
                    t.setDaemon(true);
                    return t;
                }));
    }

    /** 自定义执行线程池（主要用于测试：串行执行 / 排队期取消等确定性场景）。 */
    public ScanTaskService(ManifestParserService parserService,
                    RuleMatcherService matcherService,
                    RuleRepository ruleRepository,
                    ExecutorService executor) {
        this.parserService = parserService;
        this.matcherService = matcherService;
        this.ruleRepository = ruleRepository;
        this.executor = executor;
    }

    public ScanResult submit(String content) {
        if (content == null || content.isEmpty() || content.isBlank()) {
            throw new ManifestParseException(ErrorCode.EMPTY_CONTENT, "提交内容为空");
        }
        String hash = Hashes.sha256(content);
        ScanResult[] result = new ScanResult[1];
        // compute 对同一 key（同指纹）串行化，保证重复 / 并发提交只创建一个任务
        String scanId = scanIdByArtifact.compute(hash, (key, existingId) -> {
            if (existingId != null) {
                ScanTask existing = tasksById.get(existingId);
                if (existing != null) {
                    result[0] = toResult(existing);
                    return existingId;
                }
                // 任务表缺失的陈旧映射：落到重建分支
            }
            // 同步解析校验：畸形 / 不可识别清单在提交时即拒绝（compute 内无其他 IO 锁），
            // 不创建任务，也不会被当成空清单成功
            RuleSet ruleSet = ruleRepository.current();
            Manifest parsed = parserService.parse(content);
            String id = UUID.randomUUID().toString();
            ScanTask task = new ScanTask(id, hash, content, ruleSet.version());
            task.ruleSet(ruleSet);
            task.manifest(parsed);
            tasksById.put(id, task);
            result[0] = toResult(task);
            log.info("受理新扫描: scanId={}, artifactHash={}, ruleSetVersion={}, components={}",
                    id, hash, ruleSet.version(), parsed.components().size());
            // 登记后再异步执行
            executor.execute(() -> {
                inFlight.incrementAndGet();
                try {
                    runTask(task);
                } finally {
                    inFlight.decrementAndGet();
                }
            });
            return id;
        });
        if (result[0] != null) {
            ScanTask t = tasksById.get(scanId);
            if (t != null && !result[0].scanId().equals(scanId)) {
                result[0] = toResult(t);
            }
            return result[0];
        }
        // compute 期间映射被重建（极端竞态）：读取已存在任务
        ScanTask task = tasksById.get(scanId);
        if (task == null) {
            throw new IllegalStateException("任务登记不一致: " + scanId);
        }
        log.info("并发提交去重: artifactHash={}, scanId={}", hash, scanId);
        return toResult(task);
    }

    private void schedule(ScanTask task) {
        inFlight.incrementAndGet();
        executor.execute(() -> {
            try {
                runTask(task);
            } finally {
                inFlight.decrementAndGet();
            }
        });
    }

    public ScanResult get(String scanId) {
        return toResult(requireTask(scanId));
    }

    public ScanResult cancel(String scanId) {
        ScanTask task = requireTask(scanId);
        task.lock().lock();
        try {
            return switch (task.status()) {
                case PENDING, RUNNING -> {
                    task.cancel();
                    log.info("扫描已取消: scanId={}", scanId);
                    yield toResult(task);
                }
                case COMPLETED, CANCELLED, FAILED -> throw new ScanStateConflictException(
                        ErrorCode.TASK_ALREADY_FINISHED,
                        "任务已处于终态 " + task.status() + "，无法取消: " + scanId);
            };
        } finally {
            task.lock().unlock();
        }
    }

    public ScanResult retry(String scanId) {
        ScanTask task = requireTask(scanId);
        task.lock().lock();
        try {
            if (task.status() != ScanStatus.FAILED) {
                throw new ScanStateConflictException(ErrorCode.TASK_ALREADY_FINISHED,
                        "只有 FAILED 任务可以重试，当前状态 " + task.status() + ": " + scanId);
            }
            // 重试取当前规则集版本；旧版本随旧结论已被替换，scanId 与指纹保持不变
            task.prepareForRetry(ruleRepository.current());
            log.info("扫描重新排队: scanId={}, ruleSetVersion={}",
                    scanId, task.ruleSetVersion());
        } finally {
            task.lock().unlock();
        }
        schedule(task);
        return toResult(task);
    }

    void runTask(ScanTask task) {
        task.lock().lock();
        try {
            if (task.status() != ScanStatus.PENDING) {
                // 排队期间已被取消，或已被其他线程领取
                return;
            }
            task.markStarted();
        } finally {
            task.lock().unlock();
        }
        try {
            // 提交时的解析只用于同步校验；执行阶段统一重新解析，
            // 重试（prepareForRetry 已清空 manifest）与首次执行路径保持一致
            Manifest manifest = parserService.parse(task.rawContent());
            RuleSet ruleSet = task.ruleSet() != null ? task.ruleSet() : ruleRepository.current();
            RuleMatcherService.MatchOutcome outcome = matcherService.match(manifest, ruleSet);

            task.lock().lock();
            try {
                if (task.status() == ScanStatus.CANCELLED) {
                    log.info("任务已取消，丢弃扫描结论: scanId={}", task.scanId());
                    return;
                }
                task.manifest(manifest);
                task.findings(outcome.findings());
                task.ruleErrors(outcome.ruleErrors());
                task.complete();
                log.info("扫描完成: scanId={}, findings={}, ruleErrors={}",
                        task.scanId(), outcome.findings().size(), outcome.ruleErrors().size());
            } finally {
                task.lock().unlock();
            }
        } catch (ManifestParseException e) {
            finishWithFailure(task, e.code(), "清单被拒绝: " + e.getMessage());
        } catch (RuntimeException e) {
            log.error("扫描内部错误: scanId={}", task.scanId(), e);
            finishWithFailure(task, ErrorCode.SCAN_INTERNAL_ERROR,
                    "扫描执行失败: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void finishWithFailure(ScanTask task, ErrorCode code, String message) {
        task.lock().lock();
        try {
            if (task.status() == ScanStatus.CANCELLED) {
                return;
            }
            task.fail(code, message);
            log.warn("扫描失败: scanId={}, code={}, message={}", task.scanId(), code, message);
        } finally {
            task.lock().unlock();
        }
    }

    private ScanTask requireTask(String scanId) {
        ScanTask task = tasksById.get(scanId);
        if (task == null) {
            throw new ScanNotFoundException(scanId);
        }
        return task;
    }

    private ScanResult toResult(ScanTask task) {
        task.lock().lock();
        try {
            return new ScanResult(
                    task.scanId(),
                    task.artifactHash(),
                    task.ruleSetVersion(),
                    task.status(),
                    task.status() == ScanStatus.FAILED ? task.errorCode() : null,
                    task.status() == ScanStatus.FAILED ? task.errorMessage() : null,
                    task.manifest() != null ? task.manifest().format() : null,
                    task.manifest() != null ? task.manifest().components().size() : 0,
                    List.copyOf(task.findings()),
                    List.copyOf(task.ruleErrors()),
                    task.createdAt(),
                    task.startedAt(),
                    task.finishedAt());
        } finally {
            task.lock().unlock();
        }
    }

    /** 测试辅助：阻塞到所有已提交任务执行完毕（不关闭线程池，可反复使用）。 */
    void awaitIdle(long timeoutMillis) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (inFlight.get() > 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(5);
        }
        if (inFlight.get() > 0) {
            throw new IllegalStateException("等待扫描任务空闲超时");
        }
    }
}
