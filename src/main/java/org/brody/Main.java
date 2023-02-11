/**
 * Command keytool to generate keystore and certificate
 *
 *         keytool -genkey -alias brody -keyalg RSA -keystore brody.jks -keysize 2048
 *         keytool -export -alias brody -keystore brody.jks -rfc -file publickey.cert
 */

package org.brody;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello world!");

    }
}