package com.coindirect.webhooks;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class WebhookValidator {
    public String getBodyToHash(String webhookUrl, String contentType, String payload) throws URISyntaxException {
        URI uri = new URI(webhookUrl);

        StringBuilder hashBody = new StringBuilder();
        hashBody.append(uri.getPath());
        if (uri.getRawQuery() != null) {
            hashBody.append(uri.getRawQuery());
        }

        if (contentType != null) {
            hashBody.append(contentType);
        }


        if (payload != null) {
            hashBody.append(payload);
        }

        return hashBody.toString();
    }

    public String generateSignatureCommons(final String secret, String hashBody) {
        return toHex(new HmacUtils(HmacAlgorithms.HMAC_SHA_256, secret).hmac(hashBody));
    }

    String generateSignatureInternal(String key, String data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        return toHex(sha256_HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    boolean validateWebhook(String secret, String webhookUrl, String contentType, String payload, String signatureFromHeader) throws URISyntaxException, NoSuchAlgorithmException, InvalidKeyException {
        String body = getBodyToHash(webhookUrl, contentType, payload);
        String signature = generateSignatureInternal(secret, body);

        return signature.equalsIgnoreCase(signatureFromHeader);
    }
}
