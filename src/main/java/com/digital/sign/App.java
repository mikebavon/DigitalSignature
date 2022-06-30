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

    public static void main(String[] args) throws Exception {

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

        System.out.println("Generated Private Key: \n" + encodedPrivateKey);
        System.out.println();
        System.out.println();
        System.out.println("Generated Public Key: \n" + encodedPublicKey);
        System.out.println();
        System.out.println();

        //Getting certificate content
        String kcbPayload = "{    \"header\": {        \"messageID\": \"b5bcb82b-f3d6-417c-9c3a-2a3f54aaa02c\",        \"originatorConversationID\": "
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
        signature.update(kcbPayload.getBytes());
        byte[] signed = signature.sign();

        String base64Signature = DatatypeConverter.printBase64Binary(signed);

        System.out.println("Generated Signature: " + base64Signature);
        System.out.println();
        System.out.println("************* Testing Payload Using Generated My Public Key ****************");
        System.out.println("Verified With public Key As String? " + verifySig(kcbPayload, base64Signature, encodedPublicKey));
        System.out.println("Verified PublicKey Object? " + verifySig(kcbPayload, base64Signature, publicKey));
        System.out.println("*** works fine *****");


        System.out.println("************* Testing Using KCB provided Public Key,Signature and Payload ****************");
        // Loading kcb public key...i renamed it to publickey.pem
        PemFile pemFile = new PemFile("publickey.pem");
        byte[] pemFileContent = pemFile.getPemObject().getContent();

        X509EncodedKeySpec  keySpec = new X509EncodedKeySpec(pemFileContent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKeyFromPem = kf.generatePublic(keySpec);

        //This is the signature you shared with me using skype.....
        String kcbSignature = "xgC6U/4BDuwjfhkvNohTVYh3y4lYQlFzhuCjaVJvLPwXs5taA1I0+vxPFvcB3/6SSbqBegs/"
            + "XsOD4hczmOltOxSC0Beu1LVj40rHJXHPGi5b2gwGwNEWsLnvMHJEJsgpk3XH3hDjB0HVU7i2T9XEpIy5Olvz"
            + "BB1rcR9JNSCjoSpQl50SZLGixMS+oOfZyaJtm7Yt2zvyFt08L/5Bx2Bj+9d/StxQhq5M3VpSdMdPF3E6P4AAG"
            + "HoQOL8KNAgbCfl3jat8uuqkew9ZbNvS0T8blhUGJVlv2plavW+Hblxb113tHyfP9aNfngNKCQloMu1PID/Rax"
            + "ojpISsmXHh5lGUrg==";

        //verifying the payload, with the signature and public key from the pem file
        System.out.println("Signature correct: " + verifySig(kcbPayload, kcbSignature, publicKeyFromPem));

        //results is false....it seems
    }

    private static boolean verifySig(String payload, String signature, String publicKey) throws GeneralSecurityException{
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(DatatypeConverter.parseBase64Binary(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(payload.getBytes());
        return sig.verify(DatatypeConverter.parseBase64Binary(signature));
    }

    private static boolean verifySig(String payload, String signature, PublicKey publicKey) throws GeneralSecurityException{
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(payload.getBytes());
        return sig.verify(DatatypeConverter.parseBase64Binary(signature));
    }

}
