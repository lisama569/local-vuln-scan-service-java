package com.github.lisama569.localvulnscanservicejava.web;

import com.github.lisama569.localvulnscanservicejava.model.ScanResult;
import com.github.lisama569.localvulnscanservicejava.scan.ScanTaskService;
import com.github.lisama569.localvulnscanservicejava.web.dto.ScanSubmitRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 扫描 REST API：
 * <ul>
 *   <li>POST /api/scans —— 提交清单（按内容哈希幂等），返回 202 + 当前结果快照</li>
 *   <li>GET /api/scans/{scanId} —— 查询扫描结果</li>
 *   <li>POST /api/scans/{scanId}/cancel —— 取消排队/运行中的任务</li>
 *   <li>POST /api/scans/{scanId}/retry —— 重试失败任务（复用同一 scanId）</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanTaskService scanTaskService;

    public ScanController(ScanTaskService scanTaskService) {
        this.scanTaskService = scanTaskService;
    }

    @PostMapping
    public ResponseEntity<ScanResult> submit(@RequestBody ScanSubmitRequest request) {
        ScanResult result = scanTaskService.submit(request == null ? null : request.content());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(result);
    }

    @GetMapping("/{scanId}")
    public ScanResult get(@PathVariable String scanId) {
        return scanTaskService.get(scanId);
    }

    @PostMapping("/{scanId}/cancel")
    public ScanResult cancel(@PathVariable String scanId) {
        return scanTaskService.cancel(scanId);
    }

    @PostMapping("/{scanId}/retry")
    public ResponseEntity<ScanResult> retry(@PathVariable String scanId) {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(scanTaskService.retry(scanId));
    }
}
