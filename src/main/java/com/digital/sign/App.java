package com.digital.sign;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;

public class App {
    public static void main(String args[]) throws Exception{
        //Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

        //Initializing the KeyPairGenerator
        keyPairGen.initialize(2048);

        //Generating the pair of keys
        KeyPair pair = keyPairGen.generateKeyPair();

        //Getting the private key from the key pair
        PrivateKey privKey = pair.getPrivate();

        //Getting the public key from the key pair
        PublicKey publicKey = pair.getPublic();

        //Getting the bytes
        byte[] prvBytes = privKey.getEncoded();
        byte[] pubBytes = publicKey.getEncoded();

        //Getting certificate content
        String encodedPrivateKey = Base64.encodeBase64String(prvBytes);
        String encodedPublicKey = Base64.encodeBase64String(pubBytes);

        System.out.println("Private Key: \n" + encodedPrivateKey);
        System.out.println();
        System.out.println();
        System.out.println("Public Key: \n" + encodedPublicKey);
        System.out.println();
        System.out.println();

        //Getting certificate content
        String payload = "{    \"header\": {        \"messageID\": \"b5bcb82b-f3d6-417c-9c3a-2a3f54aaa02c\",        \"originatorConversationID\": "
            + "\"31634621-33cf-4b25-9fca-44fac112bedf\",        \"channelCode\": \"202\",        \"timeStamp\": \"2022012514210981\"    },    "
            + "\"requestPayload\": {        \"primaryData\": {            \"businessKey\": \"100400\",            "
            + "\"businessKeyType\": \"notifyBiller\"        },        \"additionalData\": {            \"notificationData\": "
            + "{                \"businessKey\": \"AB9736C\",                \"businessKeyType\": \"BillReferenceNumber\",                "
            + "\"debitMSISDN\": \"254722520441\",                \"transactionAmt\": \"10\",                "
            + "\"transactionDate\": \"2020-10-13\",                \"transactionID\": \"43te4dwedwedwewfwt334\",               "
            + " \"firstName\": \"Elk\",                \"middleName\": \"NA\",                \"lastName\": \"Test\",                "
            + "\"currency\": \"KES\",                \"narration\": \"\",                \"transactionType\": \"vooma\",                "
            + "\"balance\": \"0\"            }        }    }}";

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privKey);
        signature.update(payload.getBytes());
        byte[] signed = signature.sign();

        String base64Signature = DatatypeConverter.printBase64Binary(signed);

        System.out.println("Signature: " + base64Signature);
        System.out.println();
        System.out.println();
        System.out.println(verifySig(payload, base64Signature, encodedPublicKey));
    }


    private static boolean verifySig(String payload, String signature,  String publicKey) throws GeneralSecurityException{
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(DatatypeConverter.parseBase64Binary(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(payload.getBytes());
        return sig.verify(DatatypeConverter.parseBase64Binary(signature));
    }
}
