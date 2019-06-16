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
package fr.openobject.labs.shiro.karaf.security.realm;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.aries.jpa.template.JpaTemplate;
import org.apache.aries.jpa.template.TransactionType;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;

@Component(service = JpaRealm.class, immediate = true)
public class JpaRealm extends AuthorizingRealm {

    @Reference(target = "(osgi.unit.name=shiro)")
    private JpaTemplate jpaTemplate;

    @Activate
    public void activate(ComponentContext componentContext) throws Exception {
        System.out.println("JpaRealm -> em is open = " + jpaTemplate.txExpr(EntityManager::isOpen));
    }

    @Deactivate
    public void deactivate() {
        // do nothing
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        UserEntity entity =
                jpaTemplate.txExpr(
                        TransactionType.Supports,
                        entityManager -> entityManager.find(UserEntity.class, principalCollection.getPrimaryPrincipal().toString()));

        Set<String> roles = new HashSet<>();
        Set<String> permissions = new HashSet<>();

        if (entity != null) {

            for (RoleEntity role : entity.getRoles()) {
                roles.add(role.getRole());
                for (PermissionEntity perm : role.getPermissions()) {
                    permissions.add(perm.getPermission());
                }
            }
            SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
            info.setRoles(roles);
            info.setStringPermissions(permissions);
            return info;
        }

        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        UsernamePasswordToken token = UsernamePasswordToken.class.cast(authenticationToken);

        List<UserEntity> list =
                jpaTemplate.txExpr(
                        TransactionType.Supports,
                        entityManager ->
                                entityManager
                                        .createQuery(
                                                "SELECT u FROM UserEntity u where u.username = :username and u.password = :password",
                                                UserEntity.class)
                                        .setParameter("username", token.getUsername())
                                        .setParameter("password", String.valueOf(token.getPassword()))
                                        .getResultList());
        if (!list.isEmpty() && list.size() == 1) {
            UserEntity user = list.get(0);
            SimpleAccount account = new SimpleAccount(user.getUsername(), user.getPassword(), "SHIRO");
            return account;
        }
        return null;
    }
}
