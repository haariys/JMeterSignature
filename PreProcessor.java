import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.Signature;
import java.security.SignatureException;
import java.security.PrivateKey;
import java.security.*;

import java.util.Date;
import java.util.TimeZone;
import java.util.Base64;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;

import org.apache.jmeter.services.FileServer;
import org.apache.jmeter.util.JMeterUtils;
import org.apache.jmeter.protocol.http.control.Header;
import org.apache.jmeter.protocol.http.control.HeaderManager;

import java.text.SimpleDateFormat;



        final static String PRIVATE_KEY="";
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // get header object
        HeaderManager headerManager = sampler.getHeaderManager();

        // get current timestamp
        String timestamp = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX").format(new Date());
        // Adjust for UTC
        timestamp = timestamp.replace("Z","+00:00"); 
        // add header
        headerManager.add(new Header("Signature-Date",timestamp));

        // replace variable in message body
        String myUUID = UUID.randomUUID().toString();
        long numbermpxn1 = (long) Math.floor(Math.random() * 9000000000000L) + 1000000000000L;
        String numbermpxn = String.valueOf(numbermpxn1);  


	      vars.put("mpxn", numbermpxn);
	      long mpxnfinal = vars.get("mpxn");

        // Set the UUID to a JMeter variable
        vars.put("myGUUID", myUUID);

        // Get the UUID from JMeter variables
        String uuide = vars.get("myGUUID");

        String messageBody=sampler.getArguments().getArgument(0).getValue();
        messageBody = messageBody.replace("{{myGUUID}}",uuide );
        messageBody = messageBody.replace("{{mpxn}}",mpxnfinal );

        // generate hash from message body
        byte[] hash = digest.digest(messageBody.getBytes(StandardCharsets.UTF_8));
        String encodedHash = new String(Base64.encodeBase64(hash));

        // add header
        headerManager.add(new Header("Content-Hash",encodedHash));


        String Url = "*******.execute-api.eu-west-2.amazonaws.com";
        String httpMethod = "POST";
        String prefix = httpMethod + ";" + "https://" + Url + ";" + timestamp + ";" + encodedHash;

        // certificate and message signing
        String privateCertKey = "**************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "****************************************************************"+
        "*******************";


        byte[] privateKeyBytes = Base64.decodeBase64(privateCertKey.getBytes());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);


        Signature signature = Signature.getInstance("SHA256withRSA"); 
        signature.initSign(privateKey);
        signature.update(prefix.getBytes(StandardCharsets.UTF_8));
        byte[] signBytes = signature.sign();
        String encodedSignature = new String(Base64.encodeBase64(signBytes));
        headerManager.add(new Header("Signature",encodedSignature));


