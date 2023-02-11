package org.brody.tests;

import org.brody.encryption.CryptoUtilImpl;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestSignatureRSA {

    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        PrivateKey privateKey = cryptoUtil.
                privateKeyFromJKS("brody.jks","123456","brody");

        String data = "This is my message";
        String signature = cryptoUtil.rsaSign(data.getBytes(), privateKey);
        String signedDoc = data+"_.._"+signature;
        System.out.println(signedDoc);
        System.out.println("=============================vérification de la signature=======================");
        String signedDocReceived = "This is my message_.._Qbzp2ma1/Ht2GadUbnTXAUTkDDgE2xrdSVPU6Ohs9U6D+NApTVpUoa/nuXA7Y4m+5GxKjEdhzKYaT1eOzfA1rK35QxZBia1WkZTN5PHF56DagnvbGz6BVwy2jkwXIpWb3kxY48+xGRP8+HKFbyyrOgMYEPUNvgMVvwRNf2SsNl+oVH9SfbiC2f1IexU+lWunkVLv2fU64ObNO2Kzd9CQwz9xbCotxaFQWI5v3ePm7aD8QuxPkZ3jnIgywXeT1EyUjZRHLAt+wJzB4u5DJjeMR3zkWhbjGY33GdtHWRrhy9L2iv6K6KV92xrxg75B4EpXDzfcybO+6lPDvRxnOOt+7w==";

        PublicKey publicKey = cryptoUtil.publicKeyFromCertificate("publickey.cert");
        boolean isVerify = cryptoUtil.rsaSignVerify(signedDocReceived, publicKey);
        System.out.println(isVerify==true?"Signature Ok":"Signature Not Ok");


    }
}
