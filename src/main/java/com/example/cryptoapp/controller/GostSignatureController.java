package com.example.cryptoapp.controller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@CrossOrigin(
        origins = {"https://yourcryptoapp.netlify.app", "http://85.235.205.223:8080"},
        methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.OPTIONS},
        allowedHeaders = "*",
        allowCredentials = "false"
)
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
            if (document == null || document.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Document content is required"));
            }

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
            ECGenParameterSpec gostSpec = new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA");
            keyGen.initialize(gostSpec, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            Signature signature = Signature.getInstance("ECGOST3410-2012-512", "BC");
            signature.initSign(keyPair.getPrivate());
            signature.update(document.getBytes("UTF-8"));
            byte[] signatureBytes = signature.sign();

            Map<String, String> response = new HashMap<>();
            response.put("signature", Base64.getEncoder().encodeToString(signatureBytes));
            response.put("publicKey", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace(); // Можно временно оставить для отладки
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Signature generation failed: " + e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Serializable>> verifyDocument(@RequestBody Map<String, String> payload) {
        try {
            String document = payload.get("document");
            String signatureStr = payload.get("signature");
            String publicKeyStr = payload.get("publicKey");

            if (document == null || signatureStr == null || publicKeyStr == null) {
                return ResponseEntity.badRequest().body(Map.of("isValid", false, "error", "Missing input fields"));
            }

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("ECGOST3410-2012", "BC");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            Signature signature = Signature.getInstance("ECGOST3410-2012-512", "BC");
            signature.initVerify(publicKey);
            signature.update(document.getBytes("UTF-8"));
            byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
            boolean isValid = signature.verify(signatureBytes);

            return ResponseEntity.ok(Map.of("isValid", isValid));
        } catch (Exception e) {
            e.printStackTrace(); // Можно временно оставить
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("isValid", false, "error", e.getMessage()));
        }
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleAllExceptions(Exception ex) {
        ex.printStackTrace(); // логирование
        Map<String, String> response = new HashMap<>();
        response.put("error", ex.getMessage());
        response.put("status", "error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
