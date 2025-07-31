package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class ChineseEncryptor {
    // 你可以使用更完整的常用汉字表
    private static final char[] HANZI_CHARS = generateCommonChineseChars();
    private static final int BLOCK_SIZE = 11; // log2(2048) ≈ 11 bit per char
    private static final int BASE = 2048;
    private static final String AES_ALGORITHM = "AES";

    // ================= 工具入口 =================
    public static void main(String[] args) throws Exception {
        // 示例密钥（16字节）
        String key = "1234567890abcdef";
        File inputFile = new File("example.zip");
        String encrypted = encryptFile(inputFile, key);
        System.out.println("加密密文：\n" + encrypted);
        File outputFile = new File("解密恢复_" + inputFile.getName());
        decryptToFile(encrypted, key, outputFile);
        System.out.println("已解密保存为: " + outputFile.getAbsolutePath());
    }

    // ================= 加密流程 =================
    public static String encryptFile(File file, String key) throws Exception {
        byte[] content = readFile(file);
        byte[] encrypted = aesEncrypt(content, key.getBytes(StandardCharsets.UTF_8));
        // 在前缀加上文件名长度+文件名
        String filename = file.getName();
        byte[] filenameBytes = filename.getBytes(StandardCharsets.UTF_8);
        byte[] combined = new byte[1 + filenameBytes.length + encrypted.length];
        combined[0] = (byte) filenameBytes.length;
        System.arraycopy(filenameBytes, 0, combined, 1, filenameBytes.length);
        System.arraycopy(encrypted, 0, combined, 1 + filenameBytes.length, encrypted.length);
        return encodeToHanzi(combined);
    }

    public static void decryptToFile(String hanziString, String key, File outputFile) throws Exception {
        byte[] allBytes = decodeFromHanzi(hanziString);
        int filenameLen = allBytes[0] & 0xFF;
        String filename = new String(allBytes, 1, filenameLen, StandardCharsets.UTF_8);
        byte[] encrypted = Arrays.copyOfRange(allBytes, 1 + filenameLen, allBytes.length);
        byte[] decrypted = aesDecrypt(encrypted, key.getBytes(StandardCharsets.UTF_8));
        writeFile(outputFile, decrypted);
        System.out.println("提取出的文件名: " + filename);
    }

    // ================= AES 加解密 =================
    private static byte[] aesEncrypt(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(normalizeKey(key), AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private static byte[] aesDecrypt(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(normalizeKey(key), AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private static byte[] normalizeKey(byte[] key) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return Arrays.copyOf(sha.digest(key), 16); // AES 128位
    }

    // ================= 文件处理 =================
    private static byte[] readFile(File file) throws IOException {
        return java.nio.file.Files.readAllBytes(file.toPath());
    }

    private static void writeFile(File file, byte[] content) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content);
        }
    }

    // ================= Hanzi 编码实现 =================
    private static String encodeToHanzi(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsInBuffer = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsInBuffer += 8;
            while (bitsInBuffer >= BLOCK_SIZE) {
                bitsInBuffer -= BLOCK_SIZE;
                int index = (buffer >> bitsInBuffer) & (BASE - 1);
                sb.append(HANZI_CHARS[index]);
            }
        }
        if (bitsInBuffer > 0) {
            int index = (buffer << (BLOCK_SIZE - bitsInBuffer)) & (BASE - 1);
            sb.append(HANZI_CHARS[index]);
        }
        return sb.toString();
    }

    private static byte[] decodeFromHanzi(String hanziString) {
        List<Byte> result = new ArrayList<>();
        int buffer = 0;
        int bitsInBuffer = 0;
        for (char c : hanziString.toCharArray()) {
            int val = findCharIndex(c);
            if (val == -1) throw new IllegalArgumentException("非法字符: " + c);
            buffer = (buffer << BLOCK_SIZE) | val;
            bitsInBuffer += BLOCK_SIZE;
            while (bitsInBuffer >= 8) {
                bitsInBuffer -= 8;
                result.add((byte) ((buffer >> bitsInBuffer) & 0xFF));
            }
        }
        byte[] arr = new byte[result.size()];
        for (int i = 0; i < arr.length; i++) arr[i] = result.get(i);
        return arr;
    }

    // ================= 汉字表处理 =================
    private static char[] generateCommonChineseChars() {
        List<Character> chars = new ArrayList<>(BASE);
        for (char c = 0x4E00; c <= 0x9FA5; c++) {
            chars.add(c);
        }
        if (chars.size() < BASE) throw new RuntimeException("常用汉字不足2048个");
        return chars.subList(0, BASE).stream().map(Object::toString).collect(StringBuilder::new, StringBuilder::append, StringBuilder::append).toString().toCharArray();
    }

    private static int findCharIndex(char c) {
        for (int i = 0; i < HANZI_CHARS.length; i++) {
            if (HANZI_CHARS[i] == c) return i;
        }
        return -1;
    }
}