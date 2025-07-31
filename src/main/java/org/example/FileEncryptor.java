package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

public class FileEncryptor {

    private static final String AES_KEY = "1234567890abcdef"; // 16字节密钥
    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";

    /**
     * 加密任意文件并输出为 Base64 文本文件
     */
    public static void encryptFile(File inputFile, File outputFile) throws Exception {
        byte[] fileBytes = Files.readAllBytes(inputFile.toPath());

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedBytes = cipher.doFinal(fileBytes);
        String base64Encoded = Base64.getEncoder().encodeToString(encryptedBytes);

        // 将Base64字符串写入文件
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            writer.write(base64Encoded);
        }
    }

    /**
     * 解密 Base64 文本文件还原为原始文件
     */
    public static void decryptFile(File inputFile, File outputFile) throws Exception {
        String base64Content = new String(Files.readAllBytes(inputFile.toPath()), StandardCharsets.UTF_8);
        byte[] encryptedBytes = Base64.getDecoder().decode(base64Content);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // 将原始字节写入文件
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(decryptedBytes);
        }
    }

    public static void main(String[] args) {
        try {
//            File original = new File("/Users/lynn/Downloads/压缩包/sakila-db.zip");
            File encrypted = new File("example.zip.enc");
            File decrypted = new File("example_restored.zip");

            // 加密
//            encryptFile(original, encrypted);
//            System.out.println("加密完成，保存为: " + encrypted.getName());

            // 解密
            decryptFile(encrypted, decrypted);
            System.out.println("解密完成，还原为: " + decrypted.getName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
