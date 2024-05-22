package com.example.projectencryption.listener;

import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSONObject;
import lombok.NonNull;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author 小凡
 */
@Component
public class SignatureVerificationListener implements ApplicationListener<ApplicationReadyEvent> {

    private static final String VERIFY_KEY = "";
    private static final String DECRYPT_KEY = "";


    @Override
    public void onApplicationEvent(@NonNull ApplicationReadyEvent event) {
        // 在应用程序启动前执行签名验证逻辑
        if (!verifySignature()) {
            System.out.println("签名验证失败，应用程序启动被中止");
            // 中止应用程序的启动
            System.exit(0);
        }

        // 签名验证通过，继续启动应用程序
        System.out.println("签名验证通过，应用程序启动");
    }

    private boolean verifySignature() {
        String signature = "";
        String mapText = "";
        File file = new File("/app/signature.txt");
        try (FileReader reader = new FileReader(file);
             BufferedReader bufferedReader = new BufferedReader(reader)) {
            String text = bufferedReader.readLine();
            signature = text.split("\\|")[0];
            mapText = text.split("\\|")[1];
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

        // 进行签名验证逻辑，例如与预设的签名进行比较
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedPublicKey = Base64.getDecoder().decode(VERIFY_KEY);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
            byte[] signatureBytes = Base64.getDecoder().decode(signature);

            // 验证签名
            Signature verification = Signature.getInstance("SHA256withRSA");
            verification.initVerify(publicKey);

            if (verification.verify(signatureBytes)) {
                // 验证参数
                return paramVerify(keyFactory, mapText);
            } else {
                return false;
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    private boolean paramVerify(KeyFactory keyFactory, String mapText) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(DECRYPT_KEY));
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        String mapString = new String(cipher.doFinal(Base64.getDecoder().decode(mapText)));
        Map<String, Object> map = JSONObject.parseObject(mapString);
        String effectiveTimeText = (String) map.get("effectiveTime");
        String ipText = (String) map.get("ip");
        String expirationTimeText = (String) map.get("expirationTime");
        if (StrUtil.isBlank(effectiveTimeText) || !verifyStartTime(effectiveTimeText)) {
            return false;
        }
        if (StrUtil.isNotBlank(ipText) && !verifyIpAddress(ipText)) {
            return false;
        }
        if (StrUtil.isNotBlank(expirationTimeText) && !verifyExpirationDateTime(expirationTimeText)) {
            return false;
        }
        return true;
    }

    private boolean verifyStartTime(String effectiveTimeText) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime effectiveTime = LocalDateTime.parse(effectiveTimeText, formatter);
        LocalDateTime now = LocalDateTime.now();
        return now.isBefore(effectiveTime);
    }

    private boolean verifyExpirationDateTime(String expirationTimeText) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime expirationTime = LocalDateTime.parse(expirationTimeText, formatter);
        // 随机设定下周的某个时间点再次校验过期时间
        executeScheduledTasks(expirationTime);
        return LocalDateTime.now().isBefore(expirationTime);
    }

    private boolean verifyIpAddress(String ipText) {

        String ipAddress = "";
        try {
            InetAddress inetAddress = InetAddress.getLocalHost();
            ipAddress = inetAddress.getHostAddress();
            System.out.println("主机的IP地址是: " + ipAddress);

        } catch (UnknownHostException e) {
            System.out.println(e.getMessage());
        }
        return ipText.equals(ipAddress);
    }
    private void executeScheduledTasks(LocalDateTime expirationTime) {

        // 创建ScheduledExecutorService
        ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();

        // 生成随机的执行时间
        LocalDateTime nextExecutionTime = generateRandomExecutionTime();

        // 计算下次执行的延迟时间
        long delay = Duration.between(LocalDateTime.now(), nextExecutionTime).toMillis();
        if (delay < 0) {
            // 如果计算得到的下次执行时间已经过去，则将延迟设置为0，立即触发下一次任务
            delay = 0;
        }

        // 使用ScheduledExecutorService执行下一次任务
        executorService.schedule(() -> {
            LocalDateTime now = LocalDateTime.now();
            if (now.isAfter(expirationTime)) {
                // 退出程序
                System.exit(0);
            }

            // 递归调用重新调度下一次任务
            executeScheduledTasks(expirationTime);
        }, delay, TimeUnit.MILLISECONDS);

    }

    private LocalDateTime generateRandomExecutionTime() {
        // 生成随机的时间点
        Random random = new Random();
        // 随机小时
        int hour = random.nextInt(24);
        // 随机分钟
        int minute = random.nextInt(60);
        // 随机秒钟
        int second = random.nextInt(60);

        // 计算下次执行的日期时间
        LocalDateTime now = LocalDateTime.now();

        return now.plusWeeks(1).withHour(hour).withMinute(minute).withSecond(second);
    }

}
