package com.github.lisama569.localvulnscanservicejava.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256 内容指纹，用于制品幂等键与规则集版本。 */
public final class Hashes {

    private Hashes() {
    }

    public static String sha256(String content) {
        if (content == null) {
            throw new IllegalArgumentException("待哈希内容为 null");
        }
        return sha256(content.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256(byte[] content) {
        if (content == null) {
            throw new IllegalArgumentException("待哈希内容为 null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("当前 JDK 不支持 SHA-256", e);
        }
    }
}
