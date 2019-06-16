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
package fr.openobject.labs.shiro.karaf.security.rest;

import fr.openobject.labs.shiro.karaf.security.api.AuthenticateService;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Path("/")
public class AuthenticateServiceRest {

    private Logger logger = LoggerFactory.getLogger(AuthenticateServiceRest.class);

    private AuthenticateService authenticateService;

    public void setAuthenticateService(AuthenticateService authenticateService) {
        this.authenticateService = authenticateService;
    }

    @Path("token")
    @Produces(MediaType.TEXT_PLAIN)
    @POST
    public String getToken(@FormParam("username") String username, @FormParam("password") String password) {
        logger.debug("create token for :: username = " + username);
        return this.authenticateService.createToken(username, password);
    }

    @Path("validate")
    @Produces(MediaType.APPLICATION_JSON)
    @GET
    public String validateToken(@HeaderParam("Authorization") String token) {
        logger.debug("validate token for :: " + token);
        return "subject: " + this.authenticateService.validateToken(
                token.replace("Bearer ", ""))
                .replaceAll("=", ":'")
                .replaceAll(",", "',")
                .replaceAll("}", "'}");
    }

}
