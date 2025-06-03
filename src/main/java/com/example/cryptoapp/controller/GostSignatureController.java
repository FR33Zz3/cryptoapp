package com.example.cryptoapp.controller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = {"https://yourcryptoapp.netlify.app/sign", "https://cryptoapp-1-w7m2.onrender.com"})
@RestController
@RequestMapping("/api")
public class GostSignatureController {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @PostMapping("/sign")
    public ResponseEntity<Map<String, String>> signDocument(@RequestBody Map<String, String> payload) {
        try {
            String document = payload.get("document");

            // Генерация ключевой пары ГОСТ Р 34.10-2012
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
            ECGenParameterSpec gostSpec = new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA");
            keyGen.initialize(gostSpec, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            // Создание подписи
            Signature signature = Signature.getInstance("ECGOST3410-2012-512", "BC");
            signature.initSign(keyPair.getPrivate());
            signature.update(document.getBytes("UTF-8"));
            byte[] signatureBytes = signature.sign();

            // Подготовка ответа
            Map<String, String> response = new HashMap<>();
            response.put("signature", Base64.getEncoder().encodeToString(signatureBytes));
            response.put("publicKey", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Boolean>> verifyDocument(@RequestBody Map<String, String> payload) {
        try {
            String document = payload.get("document");
            String signatureStr = payload.get("signature");
            String publicKeyStr = payload.get("publicKey");

            // Декодирование ключа
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("ECGOST3410-2012", "BC");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            // Проверка подписи
            Signature signature = Signature.getInstance("ECGOST3410-2012-512", "BC");
            signature.initVerify(publicKey);
            signature.update(document.getBytes("UTF-8"));
            byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
            boolean isValid = signature.verify(signatureBytes);

            return ResponseEntity.ok(Map.of("isValid", isValid));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("isValid", false));
        }
    }
}