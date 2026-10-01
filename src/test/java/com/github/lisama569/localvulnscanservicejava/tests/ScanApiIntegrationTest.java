package com.github.lisama569.localvulnscanservicejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 真实 HTTP 端到端：提交/查询/取消/重试，错误归类与幂等在协议层同样成立。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ScanApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(ScanApiIntegrationTest.class);
    private final ObjectMapper json = new ObjectMapper();

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + "/api/scans" + path;
    }

    private HttpEntity<Map<String, String>> jsonBody(String content) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new HttpEntity<>(Map.of("content", content == null ? "" : content), headers);
    }

    private JsonNode submit(String content) {
        ResponseEntity<String> resp = rest.postForEntity(url(""), jsonBody(content), String.class);
        assertEquals(HttpStatus.ACCEPTED, resp.getStatusCode());
        try {
            return json.readTree(resp.getBody());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private JsonNode waitTerminal(String scanId) throws Exception {
        long deadline = System.currentTimeMillis() + 10000;
        JsonNode node;
        do {
            ResponseEntity<String> resp = rest.getForEntity(url("/" + scanId), String.class);
            node = json.readTree(resp.getBody());
            String status = node.path("status").asText();
            if (status.equals("COMPLETED") || status.equals("FAILED") || status.equals("CANCELLED")) {
                System.out.println("[HTTP 结果] " + scanId.substring(0, 8) + " status=" + status
                        + " errorCode=" + node.path("errorCode").asText(null)
                        + " findings=" + node.path("findings").size());
                return node;
            }
            Thread.sleep(10);
        } while (System.currentTimeMillis() < deadline);
        throw new IllegalStateException("等待终态超时: " + node);
    }

    @Test
    void endToEndSubmitQueryIdempotentAndReject() throws Exception {
        String content = """
                {"components":[
                  {"ecosystem":"maven","name":"log4j-core","version":"2.14.0"},
                  {"ecosystem":"npm","name":"lodash","version":"4.17.20"},
                  {"ecosystem":"pypi","name":"requests","version":"2.28.1"}
                ]}
                """;
        JsonNode first = submit(content);
        String scanId = first.path("scanId").asText();
        System.out.println("[HTTP 提交] scanId=" + scanId + ", 初始状态=" + first.path("status").asText());
        JsonNode done = waitTerminal(scanId);
        assertEquals("COMPLETED", done.path("status").asText());
        assertEquals(3, done.path("findings").size());
        assertNotNull(done.path("ruleSetVersion").asText(null));
        System.out.println("[HTTP 判定依据]");
        for (JsonNode f : done.path("findings")) {
            System.out.println("  - " + f.path("component").path("name").asText() + " => "
                    + f.path("rule").path("id").asText() + " | "
                    + f.path("rationale").asText());
        }
        log.info("端到端扫描完成 scanId={}, findings={}", scanId,
                done.path("findings").size());

        // 幂等：同样内容再提交返回同一 scanId
        JsonNode again = submit(content);
        assertEquals(scanId, again.path("scanId").asText());

        // 协议层拒绝必须带可区分 code
        ResponseEntity<String> syntaxErr = rest.postForEntity(url(""), jsonBody("{broken"),
                String.class);
        assertEquals(HttpStatus.BAD_REQUEST, syntaxErr.getStatusCode());
        JsonNode syntaxNode = json.readTree(syntaxErr.getBody());
        System.out.println("[HTTP 拒绝-语法] " + syntaxNode.path("code").asText() + ": "
                + syntaxNode.path("message").asText());
        assertEquals("MANIFEST_SYNTAX_INVALID", syntaxNode.path("code").asText());

        ResponseEntity<String> formatErr = rest.postForEntity(url(""),
                jsonBody("name: unknown-format"), String.class);
        assertEquals(HttpStatus.BAD_REQUEST, formatErr.getStatusCode());
        JsonNode formatNode = json.readTree(formatErr.getBody());
        System.out.println("[HTTP 拒绝-格式] " + formatNode.path("code").asText() + ": "
                + formatNode.path("message").asText());
        assertEquals("FORMAT_UNRECOGNIZED", formatNode.path("code").asText());

        // 不存在的任务
        ResponseEntity<String> missing = rest.getForEntity(url("/missing-id"), String.class);
        assertEquals(HttpStatus.NOT_FOUND, missing.getStatusCode());
        assertEquals("TASK_NOT_FOUND", json.readTree(missing.getBody()).path("code").asText());

        // 取消已完成任务 -> 409
        ResponseEntity<String> cancel = rest.postForEntity(url("/" + scanId + "/cancel"),
                HttpEntity.EMPTY, String.class);
        assertEquals(HttpStatus.CONFLICT, cancel.getStatusCode());
        assertEquals("TASK_ALREADY_FINISHED",
                json.readTree(cancel.getBody()).path("code").asText());

        // 不同内容 -> 不同 scanId
        JsonNode other = submit(content.replace("2.14.0", "2.20.0"));
        assertNotEquals(scanId, other.path("scanId").asText());
        JsonNode otherDone = waitTerminal(other.path("scanId").asText());
        assertEquals(2, otherDone.path("findings").size(), "升级 log4j 后应少一条命中");
        // 历史结论仍可复现：旧 scanId 的结果不变
        ResponseEntity<String> history = rest.getForEntity(url("/" + scanId), String.class);
        assertEquals(3, json.readTree(history.getBody()).path("findings").size());
    }

    @Test
    void invalidSubmitIs400AndRetryOnTerminalIs409() throws Exception {
        // 畸形清单提交时同步拒绝，不产生任务
        ResponseEntity<String> bad = rest.postForEntity(url(""), jsonBody("{not-json"),
                String.class);
        assertEquals(HttpStatus.BAD_REQUEST, bad.getStatusCode());
        assertEquals("MANIFEST_SYNTAX_INVALID",
                json.readTree(bad.getBody()).path("code").asText());
        System.out.println("[HTTP 畸形提交] 400 + MANIFEST_SYNTAX_INVALID");

        // 正常任务完成后重试 -> 409 TASK_ALREADY_FINISHED
        JsonNode node = submit("{\"components\":["
                + "{\"ecosystem\":\"maven\",\"name\":\"log4j-core\",\"version\":\"2.14.0\"}]}");
        JsonNode done = waitTerminal(node.path("scanId").asText());
        assertEquals("COMPLETED", done.path("status").asText());
        ResponseEntity<String> retry = rest.postForEntity(
                url("/" + node.path("scanId").asText() + "/retry"), HttpEntity.EMPTY, String.class);
        assertEquals(HttpStatus.CONFLICT, retry.getStatusCode());
        assertEquals("TASK_ALREADY_FINISHED",
                json.readTree(retry.getBody()).path("code").asText());
        System.out.println("[HTTP 终态重试] 409 + TASK_ALREADY_FINISHED");
    }
}
