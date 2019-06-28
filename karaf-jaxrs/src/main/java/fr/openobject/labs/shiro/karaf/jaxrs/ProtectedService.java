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
import org.apache.shiro.authc.BearerToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/")
public class ProtectedService {

    private Logger logger = LoggerFactory.getLogger(ProtectedService.class);

    @Path("infos")
    @Produces(MediaType.APPLICATION_JSON)
    @GET
    public Response getInfos(@HeaderParam("Authorization") String token) {

        Map<String, String> infos = new HashMap<>();
        Subject subject = SecurityUtils.getSubject();
        BearerToken bearerToken = new BearerToken(token);
        subject.login(bearerToken);

        if (subject.isAuthenticated()) {
            infos.put("is-authenticated", String.valueOf(subject.isAuthenticated()));
            infos.put("user-principal", subject.getPrincipal().toString());
            infos.put("session-id", SecurityUtils.getSubject().getSession().getId().toString());
            return Response.ok(infos).build();
        } else {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }


    }
}
