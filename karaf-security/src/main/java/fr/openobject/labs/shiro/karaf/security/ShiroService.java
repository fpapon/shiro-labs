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

import fr.openobject.labs.shiro.karaf.security.api.AuthenticateService;
import fr.openobject.labs.shiro.karaf.security.realm.JpaRealm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.env.DefaultEnvironment;
import org.apache.shiro.lang.codec.Hex;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component(immediate = true, name = "fr.openobject.labs.shiro.karaf.security")
public class ShiroService implements AuthenticateService {

    private Logger logger = LoggerFactory.getLogger(ShiroService.class);

    private DefaultEnvironment environment;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private SignatureAlgorithm algorithm;

    @Reference
    private JpaRealm realm;

    @Activate
    public void activate(ComponentContext componentContext) throws Exception {

        Dictionary<String, Object> properties = componentContext.getProperties();
        String hexPrivateKey = String.class.cast(properties.get("security.privateKey"));
        String hexPublicKey = String.class.cast(properties.get("security.publicKey"));
        String propAlgorithm = String.class.cast(properties.get("security.algorithm"));

        if (propAlgorithm != null && !propAlgorithm.equals("")) {
            this.algorithm = SignatureAlgorithm.forName(propAlgorithm);
        } else {
            logger.info("No signature algorithm found, using RS512...");
            this.algorithm = SignatureAlgorithm.RS512;
        }

        if (hexPrivateKey == null || hexPrivateKey.equals("") || hexPublicKey == null || hexPublicKey.equals("") ) {
            logger.info("Missing private / public key configuration, generating one...");
            Map<String, String> keys = generateKeyPair();
            hexPrivateKey = keys.get("private-key");
            hexPublicKey = keys.get("public-key");
        }

        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(Hex.decode(hexPrivateKey));
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(Hex.decode(hexPublicKey));

        this.privateKey = KeyFactory.getInstance(this.algorithm.getFamilyName()).generatePrivate(pkcs8);
        this.publicKey = KeyFactory.getInstance(this.algorithm.getFamilyName()).generatePublic(x509);

        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealm(this.realm);

        this.environment = new DefaultEnvironment();
        this.environment.setSecurityManager(securityManager);

        SecurityUtils.setSecurityManager(securityManager);
    }

    @Deactivate
    public void deactivate() {
        // do nothing
    }

    @Override
    public String validateToken(String token) {
        Jws<Claims> jws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
        logger.info("validateToken :: " + jws.getBody().getSubject());
        return jws.getBody().toString();
    }

    @Override
    public String createToken(String user, String password) {

        String bearerToken = "N/A";
        UsernamePasswordToken userToken = new UsernamePasswordToken();
        userToken.setUsername(user);
        userToken.setPassword(password.toCharArray());
        SecurityUtils.getSubject().login(userToken);
        Subject subject = SecurityUtils.getSubject();

        if (subject.isAuthenticated()) {
            JwtBuilder builder = Jwts.builder()
                    .setId(UUID.randomUUID().toString())
                    .setIssuer("apache")
                    .setIssuedAt(new Date())
                    .setExpiration(Date.from(Instant.now().plus(30, ChronoUnit.DAYS)))
                    .setAudience("karaf-shiro")
                    .setSubject(subject.getPrincipal().toString())
                    .signWith(privateKey)
                    .compressWith(CompressionCodecs.GZIP);

            bearerToken = builder.compact();
        }

        return bearerToken;
    }

    @Override
    public Map<String, String> generateKeyPair() {
        Map<String, String> keys = new HashMap<>();
        KeyPair keyPair = Keys.keyPairFor(this.algorithm);
        String hexPrivateKey = Hex.encodeToString(keyPair.getPrivate().getEncoded());
        String hexPublicKey = Hex.encodeToString(keyPair.getPublic().getEncoded());
        keys.put("private-key", hexPrivateKey);
        keys.put("public-key", hexPublicKey);
        return keys;
    }

}
