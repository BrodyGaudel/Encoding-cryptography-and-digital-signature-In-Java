package org.brody.tests;

import org.brody.encryption.CryptoUtilImpl;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class TestRSA {

    public static void main(String[] args) throws Exception {
        /*
        ----------------Private Key In Base64-------------------
        MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKdAio2Y17ChYrAgPGYbafh69i6hmoajT2J8d+vKjjYiuT/KtC4ht8aUWIV27CEk/KpLNMfOjRVu6R5sfaHaD4da0HVwb0hC3rY+pUe3+emUaogZ568UO5+psk+CYis/HcUqiXiWFcF2bQ9xbT9VjPG1seWmF9iOo1E95W6fvGLHAgMBAAECgYABhGXdW/YU7ZnaFCjIGlaPQPpLuP6QWxnkwFFMK8W3ewAoMnwI8RhcLktRRp9ku5OpLc54Q4jnGV72/i/zkGlUoq10PnLTdNq0bWeB4e3iZexWAg+Ce9oclZ+WnxUWVXVVrOfEMyxto2RCRke2xjHOOICsHza63Z5W5HiyDrNbZQJBAKtA6qthpZOCj08Z7ptRKsbyowe/XLVImrs6zYwMDEg5r+V+2/36AL5Rgj3Q2zuUly25rJnAArhCd9zS5YQcdiUCQQD6BLPvcEl4YyLMQxjDMRvl6ZtD4sIsvd2k+QRdYOwh4Tn73LS8Am15ESUxCDyGPDY6ExUkFzV/vJCv1jy3+XN7AkAOirOim+cQcIy0vdH6FFlajW30kXZQ2npxHZwooTlFxMg/55bMqTb48jjqANss4wA3XMXgRGK2vMYq1SmyHyyVAkEAnhMzIQRBr5gefD8//Mmj9e2JeZZ5Zoh1BsVa+R86rQEWBCQ7MVPnm1A3z5SBj+2p63X9O+Bgtu6mHEa8BSX22QJANIsdlY+ypfj5xvHd6cvMqT7BN/gBecqvkcMEA+P1NDhchln5mNM+a/CwvA2iGElzgsQF3qtbqfdvuf9V+hkC7Q==
        -------------------Public Key In Base64---------------

        -------------------------------------------------------
        * */

        String publicKeyBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnQIqNmNewoWKwIDxmG2n4evYuoZqGo09ifHfryo42Irk/yrQuIbfGlFiFduwhJPyqSzTHzo0VbukebH2h2g+HWtB1cG9IQt62PqVHt/nplGqIGeevFDufqbJPgmIrPx3FKol4lhXBdm0PcW0/VYzxtbHlphfYjqNRPeVun7xixwIDAQAB";

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodeKey = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodeKey));

        String data = "here is my clear message to encrypt";
        System.out.println("message : "+data);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        System.out.println("Encrypted message");
        System.out.println(Base64.getEncoder().encodeToString(encryptedBytes));


    }
}
