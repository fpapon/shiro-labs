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
package fr.openobject.labs.shiro.karaf.jaxrs;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.Dictionary;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.BearerToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(immediate = true, name = "fr.openobject.labs.shiro.karaf.jaxrs.jwtrealm", service = JwtRealm.class)
public class JwtRealm extends AuthorizingRealm {

    private Logger logger = LoggerFactory.getLogger(JwtRealm.class);

    private PublicKey publicKey;
    private SignatureAlgorithm algorithm;

    public JwtRealm() {
        this.setAuthenticationTokenClass(BearerToken.class);
    }

    @Activate
    public void activate(ComponentContext componentContext) throws Exception {

        Dictionary<String, Object> properties = componentContext.getProperties();
        String hexPublicKey = String.class.cast(properties.get("security.publicKey"));
        String propAlgorithm = String.class.cast(properties.get("security.algorithm"));

        if (propAlgorithm != null && !propAlgorithm.equals("")) {
            this.algorithm = SignatureAlgorithm.forName(propAlgorithm);
        } else {
            logger.info("No signature algorithm found, using RS512...");
            this.algorithm = SignatureAlgorithm.RS512;
        }

        if (hexPublicKey == null || hexPublicKey.equals("") ) {
            logger.info("Missing public key configuration!");
            throw new ConfigurationException("security.publicKey", "Missing public key");
        }

        X509EncodedKeySpec x509 = new X509EncodedKeySpec(Hex.decode(hexPublicKey));

        this.publicKey = KeyFactory.getInstance(this.algorithm.getFamilyName()).generatePublic(x509);

        this.setCredentialsMatcher(new AllowAllCredentialsMatcher());
    }

    @Deactivate
    public void deactivate() {
        // do nothing
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        SimpleAccount account = null;
        BearerToken bearerToken = BearerToken.class.cast(authenticationToken);

        if (bearerToken != null) {
            Jws<Claims> jws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(bearerToken.getToken().replaceFirst("Bearer ", ""));
            if (jws != null && jws.getBody() != null && jws.getBody().getExpiration().after(Date.from(Instant.now()))) {
                account = new SimpleAccount(jws.getBody().getSubject(), jws.getBody().getId(), "SHIRO");
            }
        }
        return account;
    }
}
