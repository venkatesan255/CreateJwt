package com.neoload.demo;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.shaded.json.JSONObject;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class CreateJWT {

    public String getJWT(String issuer, String subject, String audience, int jwt_validity_in_minutes, String signing_private_key) {
        String requestToken = null;
        long nowSeconds = new Date().getTime() / 1000;
        try {
            Map<String, Object> attributes = new HashMap<>();

            attributes.put("iss", issuer);
            attributes.put("sub", subject);
            attributes.put("aud", audience);
            attributes.put("exp", nowSeconds + (60L * jwt_validity_in_minutes));

            JWSObject jwsObject = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(new JOSEObjectType("JWT"))
                            .build(),
                    new Payload(new JSONObject(attributes).toString())
            );

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(signing_private_key));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(keySpec);
            JWSSigner jwsSigner = new RSASSASigner(privateKey);
            jwsObject.sign(jwsSigner);
            requestToken = jwsObject.serialize();
            System.out.println(requestToken);

        } catch (Exception e) {
            System.out.println("Exception " + e );
        }

        return requestToken;
    }

}
