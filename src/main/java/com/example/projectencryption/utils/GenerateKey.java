package com.example.projectencryption.utils;

import java.security.*;
import java.util.Base64;
import java.util.Scanner;

/**
 * @author 小凡
 */
public class GenerateKey {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("公钥: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("私钥: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        Scanner scanner = new Scanner(System.in);
        System.out.print("输入回车结束程序：");
        scanner.nextLine();
        scanner.close();
    }
}
