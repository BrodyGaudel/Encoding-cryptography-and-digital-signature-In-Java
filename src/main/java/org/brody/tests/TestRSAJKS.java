package org.brody.tests;

import org.brody.encryption.CryptoUtilImpl;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestRSAJKS {

    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        PublicKey publicKey =  cryptoUtil.publicKeyFromCertificate("publickey.cert");
        System.out.println(cryptoUtil.encodeToBase64(publicKey.getEncoded()));
        PrivateKey privateKey = cryptoUtil.privateKeyFromJKS("brody.jks", "123456", "brody");
        System.out.println(cryptoUtil.encodeToBase64(privateKey.getEncoded()));
        System.out.println(".................................................................");

        String data = "My secret Message";
        System.out.println(data);
        String encrypted = cryptoUtil.encryptRSA(data.getBytes(), publicKey);
        System.out.println("ENCRYPTED :");
        System.out.println(encrypted);

        System.out.println(".................................................................");
        byte[] decryptedBytes = cryptoUtil.decryptRSA(encrypted, privateKey);
        System.out.println("DECRYPTED :");
        System.out.println(new String(decryptedBytes));




    }

}
