package org.brody.tests;

import org.brody.encryption.CryptoUtilImpl;

import java.util.Arrays;

public class Test1 {
    public static void main(String[] args) {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        String data = "Hello World, my name is brody>>>";
        String dataBase64 = cryptoUtil.encodeToBase64(data.getBytes());
        String dataBase64Url = cryptoUtil.encodeToBase64Url(data.getBytes());
        System.out.println(dataBase64);
        System.out.println(dataBase64Url);

        byte[] decodedbytes = cryptoUtil.decodeFromBase64(dataBase64);
        byte[] decodedbytesUrl = cryptoUtil.decodeFromBase64Url(dataBase64Url);
        System.out.println(new String(decodedbytes));
        System.out.println(new String(decodedbytesUrl));

        byte[] dataBytes = dataBase64.getBytes();
        System.out.println(Arrays.toString(dataBytes));

        String s = cryptoUtil.encodeToHex(data.getBytes());
        System.out.println(s);

        String s1 = cryptoUtil.encodeToHexNative(data.getBytes());
        System.out.println(s1);
    }
}
