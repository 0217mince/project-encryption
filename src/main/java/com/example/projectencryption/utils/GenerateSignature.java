package com.example.projectencryption.utils;

import com.alibaba.fastjson.JSONObject;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 * @author 小凡
 */
public class GenerateSignature {
    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.print("请输入私钥: ");
            String privateKeyString = scanner.nextLine();
            System.out.print("请输入签名有效期(yyyy-MM-dd HH:mm:ss): ");
            String effectiveTimeString = scanner.nextLine();
            System.out.print("请输入过期时间(yyyy-MM-dd HH:mm:ss): ");
            String expirationTimeString = scanner.nextLine();
            System.out.print("请输入IP地址: ");
            String ipAddress = scanner.nextLine();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            byte[] signatureBytes = signature.sign();
            String signatureString = Base64.getEncoder().encodeToString(signatureBytes);

            String encryptedPublicKeyString = "";
            // 从字符串中恢复公钥
            byte[] encodedPublicKey = Base64.getDecoder().decode(encryptedPublicKeyString);
            PublicKey encryptedPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
            Map<String,Object> keyMap = new HashMap<>();
            keyMap.put("effectiveTime", effectiveTimeString);
            if (!expirationTimeString.isEmpty()) {
                keyMap.put("expirationTime", expirationTimeString);
            }
            if (!ipAddress.isEmpty()) {
                keyMap.put("ip", ipAddress);
            }

            // 原始数据
            byte[] originalData = JSONObject.toJSONString(keyMap).getBytes();

            // 加密
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, encryptedPublicKey);
            byte[] encryptedData = cipher.doFinal(originalData);
            String encryptedDataString = Base64.getEncoder().encodeToString(encryptedData);

            System.out.println("签名: " + signatureString + "|" + encryptedDataString);
            System.out.print("输入回车结束程序：");
            scanner.nextLine();
            scanner.close();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
