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

import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;

@Path("/")
public class ProtectedService {

    @Path("token")
    @Produces(MediaType.TEXT_PLAIN)
    @GET
    @RequiresGuest
    public String getToken(@HeaderParam("Authorization") String authorization) {
        AuthenticationToken token = new UsernamePasswordToken();
        ((UsernamePasswordToken) token).setUsername(authorization.split(":")[0]);
        ((UsernamePasswordToken) token).setPassword(authorization.split(":")[1].toCharArray());
        AuthenticationInfo authenticationInfo = SecurityUtils.getSecurityManager().authenticate(token);

        Subject subject = SecurityUtils.getSubject();
        subject.login(token);

        return SecurityUtils.getSubject().getPrincipal().toString();
    }

    @Path("infos")
    @Produces(MediaType.APPLICATION_JSON)
    @GET
    @RequiresRoles("admin")
    public Response getInfos() {
        Map<String, String> infos = new HashMap<>();
        infos.put("key1", "value1");
        return Response.ok(infos).build();
    }
}
