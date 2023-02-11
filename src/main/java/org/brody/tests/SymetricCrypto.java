package org.brody.tests;

import org.brody.encryption.CryptoUtilImpl;

import javax.crypto.SecretKey;

public class SymetricCrypto {
    public static void main(String[] args) throws Exception {

        CryptoUtilImpl cryptoUtilImpl = new CryptoUtilImpl();
        String data = "Software Engeenering";

        SecretKey secretKey = cryptoUtilImpl.generateSecretKey("azerty_azerty_az");
        byte[] secretKeyByte = secretKey.getEncoded();

        System.out.println("Secret Key : "+ new String(secretKeyByte));
        System.out.println("Data : "+data);

        String encryptedData = cryptoUtilImpl.encryptAES(data.getBytes(), secretKey);
        System.out.println("Encrypted Data : "+encryptedData);

        byte[] decryptedData = cryptoUtilImpl.decryptAES(encryptedData, secretKey);
        System.out.println("Decrypted Data : "+new String(decryptedData));


    }
}
