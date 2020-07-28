/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.openobject.labs.shiro.karaf.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.shiro.lang.codec.Hex;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

public class ProtectedServiceTest {

    @Test
    public void testGeneratedKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String hexPrivateKey = Hex.encodeToString(privateKey.getEncoded());
        String hexPublicKey = Hex.encodeToString(publicKey.getEncoded());
        System.out.println("privateKey :: " + hexPrivateKey);
        System.out.println("publicKey :: " + hexPublicKey);

        X509EncodedKeySpec x509 = new X509EncodedKeySpec(Hex.decode(hexPublicKey));
        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(Hex.decode(hexPrivateKey));

        System.out.println("privateKey-pkcs8 :: " + pkcs8.getEncoded());
        System.out.println("publicKey-x509 :: " + x509.getEncoded());

        PrivateKey loadPrivateKey = KeyFactory.getInstance(SignatureAlgorithm.RS256.getFamilyName()).generatePrivate(pkcs8);
        PublicKey loadPublicKey = KeyFactory.getInstance(SignatureAlgorithm.RS256.getFamilyName()).generatePublic(x509);

        JwtBuilder builder = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setIssuer("apache")
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(30, ChronoUnit.DAYS)))
                .setAudience("karaf-shiro")
                .setSubject("john")
                .signWith(loadPrivateKey)
                .compressWith(CompressionCodecs.GZIP);

        System.out.println("token :: " + builder.compact());

        Jws<Claims> jws = Jwts.parser().setSigningKey(loadPublicKey).parseClaimsJws(builder.compact());

        System.out.println("claim.signature :: " + jws.getSignature());
        System.out.println("claim.subject :: " + jws.getBody().getSubject());
        System.out.println("claim.subject.id :: " + jws.getBody().getId());
        System.out.println("claim.subject.issuer :: " + jws.getBody().getIssuer());
        System.out.println("claim.subject.issueAt :: " + jws.getBody().getIssuedAt());
        System.out.println("claim.subject.audience :: " + jws.getBody().getAudience());
        System.out.println("claim.subject.expiration :: " + jws.getBody().getExpiration());
        System.out.println("claim.header.algorithm :: " + jws.getHeader().getAlgorithm());
        System.out.println("claim.header.compressionAlgorithm :: " + jws.getHeader().getCompressionAlgorithm());
    }

    @Test
    public void testSaveKey() {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String hexPrivateKey = Hex.encodeToString(privateKey.getEncoded());
        String hexPublicKey = Hex.encodeToString(publicKey.getEncoded());
        System.out.println("privateKey :: " + hexPrivateKey);
        System.out.println("publicKey :: " + hexPublicKey);

        X509EncodedKeySpec x509 = new X509EncodedKeySpec(publicKey.getEncoded());
        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(privateKey.getEncoded());

        System.out.println("privateKey-pkcs8 :: " + pkcs8.getEncoded());
        System.out.println("publicKey-x509 :: " + x509.getEncoded());
    }


}
