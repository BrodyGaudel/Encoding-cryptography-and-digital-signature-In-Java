package org.brody.encryption;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

public class CryptoUtilImpl {

    private static final int KEY_SIZE = 1024;
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";


    /**
     * encode data from byte[] to String
     * @param data byte[]
     * @return String
     */
    public String encodeToBase64(byte[] data) {

        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * decode data from String Base64 to byte[]
     * @param dataBase64 String
     * @return byte[]
     */
    public byte[] decodeFromBase64(String dataBase64) {

        return Base64.getDecoder().decode(dataBase64.getBytes());
    }

    /**
     * encode data from byte[] to String Base64Url
     * @param data byte[]
     * @return String
     */
    public String encodeToBase64Url(byte[] data) {

        return Base64.getUrlEncoder().encodeToString(data);
    }

    /**
     * decode data from String Base64Url to byte[]
     * @param dataBase64 String
     * @return byte[]
     */
    public byte[] decodeFromBase64Url(String dataBase64) {
        if(dataBase64==null){
            return new byte[0];
        }else{
            return Base64.getUrlDecoder().decode(dataBase64.getBytes());
        }
    }

    /**
     * encode data from byte[] to Hexa String with library
     * @param data byte[]
     * @return String
     */
    public String encodeToHex(byte[] data) {
        return Hex.encodeHexString(data);
    }

    /**
     * encode data from byte[] to Hexa String without library
     * @param data byte[]
     * @return String
     */
    public String encodeToHexNative(byte[] data) {
        Formatter formatter = new Formatter();
        for(byte b: data) {
            formatter.format("%02x",b);
        }
        return formatter.toString();
    }

    /**
     * Generate AES Secret Key initialized to 256 bits
     * @return SecretKey
     * @throws Exception Exception
     */
    public SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(256);
        return keyGenerator.generateKey();

    }

    /**
     * Generate AES Secret Key
     * @param secret SecretKey
     * @return SecretKey Secret Key
     */
    public SecretKey generateSecretKey(String secret){
        return new SecretKeySpec(secret.getBytes(), 0, secret.length(), AES);
    }

    /**
     * encrypt AES
     * @param data byte[]
     * @param secretKey SecretKey
     * @return encrypted data
     * @throws Exception Exception
     */
    public String encryptAES(byte[] data, SecretKey secretKey) throws Exception {

        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedData);

    }

    /**
     * Decrypted AES
     * @param encodedEncryptedData String
     * @param secretKey SecretKey
     * @return decrypted data
     * @throws Exception Exception
     */
    public byte[] decryptAES(String encodedEncryptedData, SecretKey secretKey) throws Exception {

        byte[] decodedEncryptedData = Base64.getDecoder().decode(encodedEncryptedData);
        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(decodedEncryptedData);
    }

    /**
     *  to generate Key Pair
     * @return KeyPair
     */
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(KEY_SIZE); //set key size
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * generate Public Key FromBase64
     * @param publicKeyBase64 type String in Base64
     * @return PublicKey
     * @throws Exception No Such Algorithm Exception
     */
    public PublicKey generatePublicKeyFromBase64(String publicKeyBase64) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        byte[] decodedPK = Base64.getDecoder().decode(publicKeyBase64);
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedPK));
    }

    /**
     * generate private key FromBase64
     * @param publicKeyBase64 String
     * @return PrivateKey
     * @throws Exception exception
     */
    public PrivateKey generatePrivateKeyFromBase64(String publicKeyBase64) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        byte[] decodedPK = Base64.getDecoder().decode(publicKeyBase64);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedPK));
    }

    /**
     * encrypt data with RSA
     * @param data byte[]
     * @param publicKey PublicKey
     * @return String
     * @throws Exception Exception
     */
    public String encryptRSA(byte[] data, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(data);
        return encodeToBase64(bytes);
    }

    /**
     * decrypt data with RSA
     * @param dataBase64 String
     * @param privateKey PrivateKey
     * @return byte[]
     * @throws Exception Exception
     */
    public byte[] decryptRSA(String dataBase64, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedEncryptedData = decodeFromBase64(dataBase64);
        return cipher.doFinal(decodedEncryptedData);
    }

    /**
     * read Public key from certificate file
     * @param fileName String
     * @return PublicKey
     * @throws Exception Exception
     */
    public PublicKey publicKeyFromCertificate(String fileName) throws Exception{
        FileInputStream fileInputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        return certificate.getPublicKey();
    }

    /**
     * read Private key from Java Key Store
     * @param fileName String
     * @param jksPassword String (java keystore password)
     * @param alias String
     * @return PrivateKey
     * @throws Exception Exception
     */
    public PrivateKey privateKeyFromJKS(String fileName, String jksPassword, String alias) throws Exception{
        FileInputStream fileInputStream = new FileInputStream(fileName);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream, jksPassword.toCharArray());
        Key key = keyStore.getKey(alias, jksPassword.toCharArray());
        return (PrivateKey) key;
    }

    /**
     * generate HMAC Signature
     * @param data byte[]
     * @param privateSecret String
     * @return Signature  String
     * @throws Exception Exception
     */
    public String hmacSign(byte[] data, String privateSecret) throws Exception{
        SecretKeySpec secretKeySpec = new SecretKeySpec(privateSecret.getBytes(), HMAC_SHA256);
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(secretKeySpec);
        byte[] signature = mac.doFinal(data);
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * verify if document is sign by hmac signature
     * @param signedDocument String
     * @param secret String
     * @return true or false as a boolean
     * @throws Exception Exception
     */
    public boolean hmacSignVerify(String signedDocument, String secret) throws Exception{
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), HMAC_SHA256);
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(secretKeySpec);
        String[] splitedDocument = signedDocument.split("_.._");
        String document = splitedDocument[0];
        String documentSignature = splitedDocument[1];
        byte[] sign = mac.doFinal(document.getBytes());
        String signBase64 = Base64.getEncoder().encodeToString(sign);
        return (signBase64.equals(documentSignature));
    }

    /**
     * generate RSA Signature
     * @param data byte[]
     * @param privateKey PrivateKey
     * @return signature String
     * @throws Exception Exception
     */
    public String rsaSign(byte[] data, PrivateKey privateKey)throws Exception{
        Signature signature = Signature.getInstance(SHA256_WITH_RSA);
        signature.initSign(privateKey, new SecureRandom());
        signature.update(data);
        byte[] sign = signature.sign();
        return Base64.getEncoder().encodeToString(sign);
    }

    /**
     * verify if document is sign by RSA signature
     * @param signedDoc String
     * @param publicKey PublicKey
     * @return true or false as a boolean
     * @throws Exception Exception
     */
    public boolean rsaSignVerify(String signedDoc, PublicKey publicKey)throws Exception {
        Signature signature = Signature.getInstance(SHA256_WITH_RSA);
        signature.initVerify(publicKey);
        String[] data = signedDoc.split("_.._");
        String document = data[0];
        String sign = data[1];
        byte[] decodeSignature = Base64.getDecoder().decode(sign);
        signature.update(document.getBytes());
        return signature.verify(decodeSignature);
    }
}
