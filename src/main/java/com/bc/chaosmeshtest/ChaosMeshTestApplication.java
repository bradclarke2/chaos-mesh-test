package com.bc.chaosmeshtest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import dev.paseto.jpaseto.Paseto;
import dev.paseto.jpaseto.PasetoParser;
import dev.paseto.jpaseto.Pasetos;
import dev.paseto.jpaseto.Pasetos.V2;
import dev.paseto.jpaseto.Version;
import dev.paseto.jpaseto.lang.Keys;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@SpringBootApplication
public class ChaosMeshTestApplication {

    public static final String CUSTOM_FORMAT_CHARACTER = ":";
    public static final String STANDARD_FORMAT_CHARACTER = "\\.";

    public static void main(String[] args)
            throws JOSEException, NoSuchAlgorithmException, NoSuchProviderException, IOException, DecoderException, ParseException, InvalidKeyException {
        hmacTest();
        jwtTest();
        pasetoTest();
        //		SpringApplication.run(ChaosMeshTestApplication.class, args);
    }

    private static void hmacTest() throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        System.out.println("------HMAC-------");

        CustomClaims customClaims = new CustomClaims(UUID.randomUUID().toString(), Instant.now().toEpochMilli());
        String key = UUID.randomUUID().toString();
        String algorithm = "HmacSHA256";
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);

        ObjectMapper mapper = new CBORMapper();
        byte[] bytes = mapper.writeValueAsBytes(customClaims);

        byte[] encodedClaims = Base64.getEncoder().withoutPadding().encode(bytes);
        byte[] encodedSignature = Base64.getEncoder().withoutPadding().encode(mac.doFinal(bytes));

        String encodedClaimsString = new String(encodedClaims, StandardCharsets.UTF_8);
        String encodedSignatureString = new String(encodedSignature, StandardCharsets.UTF_8);

        String concatPayload = encodedClaimsString + "-" + encodedSignatureString;

        System.out.println(concatPayload);

        byte[] decoded = Base64.getDecoder().decode(encodedSignatureString);

        CustomClaims customClaimsDecoded = mapper.readValue(decoded, CustomClaims.class);

        System.out.println(customClaimsDecoded.toString());
    }

    private static void jwtTest() throws JOSEException, IOException, DecoderException, ParseException {
        System.out.println("------JWT-------");

        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("identity-key")
                .keyUse(KeyUse.SIGNATURE)
                .generate();

        System.out.println("private key: " + rsaKey.toString());

        RSAKey rsaPublicJWK = rsaKey.toPublicJWK();


        System.out.println("public key: " + rsaPublicJWK.toString());
        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaKey);
        // Prepare JWS object with simple string as payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                new Payload(Map.of(
                        "jti", "token",
                        "exp", 1655132430
                )));

        // Compute the RSA signature
        jwsObject.sign(signer);

        String newlyFormedJwt = jwsObject.serialize();



//        ObjectMapper mapper = new CBORMapper();
//        byte[] bytes = mapper.writeValueAsBytes(newlyFormedJwt);
        String token = Hex.encodeHexString(newlyFormedJwt.getBytes(StandardCharsets.UTF_8));

        System.out.println(token);

		byte[] decodeHex = Hex.decodeHex(token);

//		String readValue = mapper.readValue(decodeHex, String.class);



        JWSVerifier verifier = new RSASSAVerifier(rsaPublicJWK);
        String decodedHExString = new String(decodeHex);
        System.out.println(decodedHExString);
        SignedJWT signedJWT = SignedJWT.parse(decodedHExString);

        signedJWT.verify(verifier);

        System.out.println(signedJWT.getJWTClaimsSet().toString());


//        JWK jwk = new RSAKey.Builder((RSAPublicKey)rsaKey.toKeyPair().getPublic())
//                .privateKey((RSAPrivateKey)rsaKey.toKeyPair().getPrivate())
//                .keyUse(KeyUse.SIGNATURE)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//
//        JWKSecurityContext jwkSecurityContext = new JWKSecurityContext(List.of(jwk));
//
//        JWKSource<JWKSecurityContext> contextJWKSource = JWKSource
//
//        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
//        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
//        jwtProcessor.setJWEKeySelector(new JWSVerificationKeySelector<>(expectedJWSAlg, rsaPublicJWK));
    }

    private static final KeyPair KEY_PAIR = Keys.keyPairFor(Version.V2);

    private static void pasetoTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("------PASETO-------");
        Instant now = Instant.now();
        String paseto =
                V2.PUBLIC.builder().setPrivateKey(KEY_PAIR.getPrivate())
                        .setTokenId("paseto-token")
                        .setIssuedAt(now)
//                        .setNotBefore(Instant.now().plus(5, ChronoUnit.MINUTES))
                        .setExpiration(now.plus(1, ChronoUnit.HOURS))
                        .setIssuer("identity")
                        .compact();

        System.out.println("Paseto: " + paseto);

        //		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");

        PasetoParser parser = Pasetos.parserBuilder()
                .setPublicKey(KEY_PAIR.getPublic())
                .requireIssuer("identity")
                .requireNotBefore(Instant.now())
                //				.setPublicKey(keyGen.generateKeyPair().getPublic())
                .build();

        Paseto parsedResult = parser.parse(paseto);

        parsedResult.getClaims().forEach((key, value) -> System.out.println("key: " + key + " value: " + value));
    }



    private static String pasteoToCustomFormat(String paseto) {
        return paseto.replaceAll(STANDARD_FORMAT_CHARACTER, CUSTOM_FORMAT_CHARACTER);
    }

    private static String pasteoFromCustomFormat(String paseto) {
        return paseto.replaceAll(CUSTOM_FORMAT_CHARACTER, STANDARD_FORMAT_CHARACTER);
    }
}
