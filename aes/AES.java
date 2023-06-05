package encryption_algorithm;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class AES {
    public static void main(String[] args) {
        String secretKey = "2020217007123456"; // 密钥

        // 加密字符串
        String plaintext = "qiming2020216774";
        System.out.println("原始字符串: " + plaintext);

        try {
            String encryptedText = encryptString(plaintext, secretKey);
            System.out.println("加密后的字符串: " + encryptedText);

            String decryptedText = decryptString(encryptedText, secretKey);
            System.out.println("解密后的字符串: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 加密图片
        String imagePath = "/home/qm/DES/test/测试图片.png";

        try {
            encryptFile(imagePath, secretKey, "/home/qm/DES/test/测试图片_aes_en.png");
            decryptFile("/home/qm/DES/test/测试图片_aes_en.png", secretKey, "/home/qm/DES/test/测试图片_aes_en.png");
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 加密文本文件
        String textFilePath = "/home/qm/DES/test/测试文本.txt";

        try {
            encryptFile(textFilePath, secretKey, "/home/qm/DES/test/测试文本_aes_en.txt");
            decryptFile("/home/qm/DES/test/测试文本_aes_en.txt", secretKey, "/home/qm/DES/test/测试文本_aes_de.txt");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 加密字符串
    public static String encryptString(String plaintext, String secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 解密字符串
    public static String decryptString(String encryptedText, String secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    // 加密文件
    public static void encryptFile(String filePath, String secretKey, String encryptedFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        try (FileInputStream fis = new FileInputStream(filePath);
             FileOutputStream fos = new FileOutputStream(encryptedFilePath);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }

    // 解密文件
    public static void decryptFile(String encryptedFilePath, String secretKey, String decryptedFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        try (FileInputStream fis = new FileInputStream(encryptedFilePath);
             CipherInputStream cis = new CipherInputStream(fis, cipher);
             FileOutputStream fos = new FileOutputStream(decryptedFilePath)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
        }
    }
}