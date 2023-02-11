package org.brody.tests;

import org.brody.encryption.CryptoUtilImpl;

public class TestSignature {

    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        String secret = "azerty";
        String document = "Hello World";
        String signature = cryptoUtil.hmacSign(document.getBytes(), secret);
        String signedDocument = document+"_.._"+signature;
        System.out.println(signedDocument);
        System.out.println("=========================verification de la signature============================");
        boolean isVerify = cryptoUtil.hmacSignVerify(signedDocument, "azerty");
        System.out.println(isVerify==true?"Signature Ok":"Signature Not Ok");
    }
}
