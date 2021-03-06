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
package fr.openobject.labs.shiro.tomcat.jaxrs;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresRoles;

@Path("/")
public class ProtectedService {

    @Path("token")
    @Produces(MediaType.TEXT_PLAIN)
    @GET
    @RequiresGuest
    public String getToken() {
        return UUID.randomUUID().toString();
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
