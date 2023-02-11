package org.brody.tests;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TestRSADecrypt {

    public static void main(String[] args) throws Exception {
        //String publicKeyBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnQIqNmNewoWKwIDxmG2n4evYuoZqGo09ifHfryo42Irk/yrQuIbfGlFiFduwhJPyqSzTHzo0VbukebH2h2g+HWtB1cG9IQt62PqVHt/nplGqIGeevFDufqbJPgmIrPx3FKol4lhXBdm0PcW0/VYzxtbHlphfYjqNRPeVun7xixwIDAQAB";
        String privateKeyBase64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKdAio2Y17ChYrAgPGYbafh69i6hmoajT2J8d+vKjjYiuT/KtC4ht8aUWIV27CEk/KpLNMfOjRVu6R5sfaHaD4da0HVwb0hC3rY+pUe3+emUaogZ568UO5+psk+CYis/HcUqiXiWFcF2bQ9xbT9VjPG1seWmF9iOo1E95W6fvGLHAgMBAAECgYABhGXdW/YU7ZnaFCjIGlaPQPpLuP6QWxnkwFFMK8W3ewAoMnwI8RhcLktRRp9ku5OpLc54Q4jnGV72/i/zkGlUoq10PnLTdNq0bWeB4e3iZexWAg+Ce9oclZ+WnxUWVXVVrOfEMyxto2RCRke2xjHOOICsHza63Z5W5HiyDrNbZQJBAKtA6qthpZOCj08Z7ptRKsbyowe/XLVImrs6zYwMDEg5r+V+2/36AL5Rgj3Q2zuUly25rJnAArhCd9zS5YQcdiUCQQD6BLPvcEl4YyLMQxjDMRvl6ZtD4sIsvd2k+QRdYOwh4Tn73LS8Am15ESUxCDyGPDY6ExUkFzV/vJCv1jy3+XN7AkAOirOim+cQcIy0vdH6FFlajW30kXZQ2npxHZwooTlFxMg/55bMqTb48jjqANss4wA3XMXgRGK2vMYq1SmyHyyVAkEAnhMzIQRBr5gefD8//Mmj9e2JeZZ5Zoh1BsVa+R86rQEWBCQ7MVPnm1A3z5SBj+2p63X9O+Bgtu6mHEa8BSX22QJANIsdlY+ypfj5xvHd6cvMqT7BN/gBecqvkcMEA+P1NDhchln5mNM+a/CwvA2iGElzgsQF3qtbqfdvuf9V+hkC7Q==";

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodeKey = Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodeKey));

        String encryptedData = "j4RXmE2GEkla9psNhutzFJN3sjLXEcKa0fYAc4xko5LVyrpkh/H3zX1oVTi5dsu69lTgl+xsP0IEoqKD+/7scHG+s6MP8nzlqgB9azOdXuJkTwRxfG3yiTWkEJX+gI5KFvzXYCadxPvIEHS3Ai/r4jirNaqzLt9UuCPgfcuvlD4=";
        System.out.println("Encrypted Data : "+encryptedData);

        byte[] decodeEncryptedData = Base64.getDecoder().decode(encryptedData);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        System.out.println("Decrypted data");
        System.out.println(new String(decryptedBytes));
    }
}
