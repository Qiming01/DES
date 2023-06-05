package rsa;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class RSA {
    private static BigInteger n, e, d;
    // 声明分块加密所需的块大小
    private static int encryptblockSize, decryptblockSize;

    // 初始化 RSA 参数
    public static void init(int bits, int blockSize) {
        // 随机数生成器
        SecureRandom random = new SecureRandom();
        // 生成两个大素数 p 和 q，每个素数的二进制位数为 bits / 2
        BigInteger p = BigInteger.probablePrime(bits / 2, random);
        BigInteger q = BigInteger.probablePrime(bits / 2, random);
        // 计算 n = p * q
        n = p.multiply(q);
        // 计算 m = (p-1) * (q-1)，小于 n 且与 n 互质的正整数个数
        BigInteger m = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        // 选择一个 e，使得 e 与 m 的最大公约数为 1，即 e 和 m 互质
        // 65537通常被选作公钥的指数（e），因为它是一个素数，且比较容易计算
        e = new BigInteger("65537");
        // 计算 d = e^(-1) mod m，即 d 为 e 模 m 的乘法逆元
        d = e.modInverse(m);
        // 根据块大小和密钥长度的关系，设置块大小
        //加密数据的长度不应超过密钥的长度
        blockSize = Math.min((bits - 1) / 8, blockSize);

        encryptblockSize = blockSize;
        //解密结果应该与密钥长度匹配
        decryptblockSize = n.bitLength() / 8 + 1;

    }

    // RSA 加密函数
    public static byte[] encrypt(byte[] message) {
        int numBlocks = (message.length + encryptblockSize - 1) / encryptblockSize;
        byte[] encryptedMessage = new byte[numBlocks * decryptblockSize];
        // 偏移量
        int offset = 0;
        // 对明文分块加密
        for (int i = 0; i < numBlocks; i++) {
            // 计算当前块的长度：当前块实际的长度或者剩余未加密的消息长度
            int len = Math.min(encryptblockSize, message.length - offset);
            // 截取当前块的字节数组
            byte[] block = Arrays.copyOfRange(message, offset, offset + len);

            // 将块转化为大整数
            BigInteger blockBigInt = new BigInteger(1, block);

            // 计算加密后的大整数，e次幂 mod n
            BigInteger encryptedBlockBigInt = blockBigInt.modPow(e, n);

            // 将加密后的大整数转化为字节数组
            byte[] encryptedBlock = encryptedBlockBigInt.toByteArray();

            // 如果加密后的块长度小于块的长度，则进行填充
            if (encryptedBlock.length < decryptblockSize) {
                // 创建填充后的字节数组
                byte[] paddedBlock = new byte[decryptblockSize];
                // 将加密后的块拼接到填充后的字节数数组
                System.arraycopy(encryptedBlock, 0, paddedBlock, decryptblockSize - encryptedBlock.length,
                        encryptedBlock.length);
                encryptedBlock = paddedBlock;
            }

            // 将加密后的块拼接到密文中
            System.arraycopy(encryptedBlock, 0, encryptedMessage, i * decryptblockSize, decryptblockSize);
            // 更新偏移量
            offset += encryptblockSize;

        }
        return encryptedMessage;
    }

    // RSA 解密函数
    public static byte[] decrypt(byte[] encryptedMessage) {

        int numBlocks = encryptedMessage.length / decryptblockSize;
        byte[] decryptedMessage = new byte[numBlocks * decryptblockSize];
        int offset = 0;

        // 对密文分块解密
        for (int i = 0; i < numBlocks; i++) {
            // 获取当前块的密文
            byte[] block = Arrays.copyOfRange(encryptedMessage, i * decryptblockSize, (i + 1) * decryptblockSize);
            // 将密文转化为大整数
            BigInteger encryptedBlockBigInt = new BigInteger(1, block);
            // 计算解密后的大整数, d次幂 mod n
            BigInteger decryptedBlockBigInt = encryptedBlockBigInt.modPow(d, n);
            // 将解密后的大整数转化为字节数组
            byte[] decryptedBlock = decryptedBlockBigInt.toByteArray();
            // 计算解密后的块长度
            int length = Math.min(decryptblockSize, decryptedBlock.length);
            // 将解密后的块拼接到明文中
            if (decryptedBlock[0] == 0) {
                // 如果解密后的第一个字节为0，则表示有填充，需要去除填充
                System.arraycopy(decryptedBlock, 1, decryptedMessage, offset, length - 1);
                // 将去除填充后的数据拷贝到解密后的明文数组中
                offset += length - 1;
                // 更新偏移量
            } else {
                // 如果解密后的第一个字节不为0，则表示没有填充，直接拷贝数据
                System.arraycopy(decryptedBlock, 0, decryptedMessage, offset, length);
                // 将解密后的数据拷贝到解密后的明文数组中
                offset += length;
                // 更新偏移量
            }
        }

        // 截掉填充的字节
        return Arrays.copyOfRange(decryptedMessage, 0, offset);
    }

    /**
     * 加密
     */
    public static byte[] encryptText(String inputText) {
        byte[] inputData = inputText.getBytes();
        byte[] encryptedData = encrypt(inputData);
        return encryptedData;
    }

    /**
     * 解密字节数组为字符串
     */
    public static String decryptText(byte[] encryptedText) {
        byte[] decryptedData = decrypt(encryptedText);
        return new String(decryptedData);
    }


    public static void main(String[] args) throws IOException {
        try {
            init(2048, 512);
            String str = "qiming2020216774"; // 待加密的字符串
            System.out.println("原始明文：" + str);
            byte[] cipher = encryptText(str); // 对字符串进行RSA加密
            String plain = decryptText(cipher); // 对密文进行RSA解密
            System.out.println("RSA加密后：" + cipher); 
            System.out.println("RSA解密后：" + plain); 
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

