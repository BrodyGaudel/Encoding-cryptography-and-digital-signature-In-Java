package org.brody.tests;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class DecryptedAESTest {

    private static final String AES = "AES";

    public static void main(String[] args) throws Exception {

        String recieveMessage = "WiehfbJ7GaOxGo0ZLOssYkqxuF32Pzaaatbwq9cGh9c=";
        byte[] decodedEncryptedData = Base64.getDecoder().decode(recieveMessage);

        String mySecret = "azerty_azerty_az";
        SecretKey secretKey = new SecretKeySpec(mySecret.getBytes(), 0, mySecret.length(), AES);
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        //decrypter
        byte[] decryptedData = cipher.doFinal(decodedEncryptedData);
        System.out.println(new String(decryptedData));
    }
}
