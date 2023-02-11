package org.brody.tests;

import org.brody.encryption.CryptoUtilImpl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class GenerateRSAKey {
    public static void main(String[] args)throws Exception{
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        KeyPair keyPair = cryptoUtil.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        //System.out.println("-----------------Private Key-------------------------");
        //System.out.println(Arrays.toString(privateKey.getEncoded()));
        System.out.println("----------------Private Key In Base64-------------------");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        //System.out.println("----------------Public Key-------------------------");
        //System.out.println(Arrays.toString(publicKey.getEncoded()));
        System.out.println("-------------------Public Key In Base64---------------");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("-------------------------------------------------------");
    }
}
