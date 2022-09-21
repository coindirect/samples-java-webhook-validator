package com.coindirect.webhooks;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Collectors;

public class SignatureTest {

    @Test
    void testSignature() throws URISyntaxException, IOException, NoSuchAlgorithmException, InvalidKeyException {
        String payload = getResourceFileAsString("sample-webhook.json");
        WebhookValidator webhookValidator = new WebhookValidator();
        String hashBody = webhookValidator.getBodyToHash("https://webhook.site/866ccda9-636d-40fb-acd2-37b40601a3eb", "application/json", payload);

        String signature1 = webhookValidator.generateSignatureCommons("ODFjZWIyODctYjE3NC00NDc0LTk2M2QtYTlmOWZhODRhZTQ2NjFhYmUxYzMtYWNlZC00ZTJlLWI2ODctYmRmNTY3NDdlZWY3", hashBody);
        String signature2 = webhookValidator.generateSignatureInternal("ODFjZWIyODctYjE3NC00NDc0LTk2M2QtYTlmOWZhODRhZTQ2NjFhYmUxYzMtYWNlZC00ZTJlLWI2ODctYmRmNTY3NDdlZWY3", hashBody);

        assert signature1.equals("4e783cfe17791e349be75a6374da168806f480cb2f60ae6b602cc531cf1ff672");
        assert signature2.equals("4e783cfe17791e349be75a6374da168806f480cb2f60ae6b602cc531cf1ff672");
    }


    @Test
    void testValidator() throws URISyntaxException, IOException, NoSuchAlgorithmException, InvalidKeyException {
        String payload = getResourceFileAsString("sample-webhook.json");
        WebhookValidator webhookValidator = new WebhookValidator();
        boolean valid = webhookValidator.validateWebhook("ODFjZWIyODctYjE3NC00NDc0LTk2M2QtYTlmOWZhODRhZTQ2NjFhYmUxYzMtYWNlZC00ZTJlLWI2ODctYmRmNTY3NDdlZWY3", "https://webhook.site/866ccda9-636d-40fb-acd2-37b40601a3eb", "application/json", payload, "4e783cfe17791e349be75a6374da168806f480cb2f60ae6b602cc531cf1ff672");

        assert valid;
    }

    @Test
    void testInvalid() throws URISyntaxException, IOException, NoSuchAlgorithmException, InvalidKeyException {
        String payload = getResourceFileAsString("sample-webhook.json") + "garbage";
        WebhookValidator webhookValidator = new WebhookValidator();
        boolean valid = webhookValidator.validateWebhook("ODFjZWIyODctYjE3NC00NDc0LTk2M2QtYTlmOWZhODRhZTQ2NjFhYmUxYzMtYWNlZC00ZTJlLWI2ODctYmRmNTY3NDdlZWY3", "https://webhook.site/866ccda9-636d-40fb-acd2-37b40601a3eb", "application/json", payload, "4e783cfe17791e349be75a6374da168806f480cb2f60ae6b602cc531cf1ff672");

        assert !valid;
    }

    static String getResourceFileAsString(String fileName) throws IOException {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        try (InputStream is = classLoader.getResourceAsStream(fileName)) {
            if (is == null) return null;
            try (InputStreamReader isr = new InputStreamReader(is);
                 BufferedReader reader = new BufferedReader(isr)) {
                return reader.lines().collect(Collectors.joining(System.lineSeparator()));
            }
        }
    }
}
