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
package fr.openobject.labs.shiro.karaf.security.command;

import fr.openobject.labs.shiro.karaf.security.api.AuthenticateService;
import org.apache.karaf.shell.api.action.Action;
import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;

@Service
@Command(scope = "shiro-labs", name = "token-validate", description = "Validate token")
public class ValidateTokenCommand implements Action {

    @Reference private AuthenticateService authenticateService;

    @Argument(
            index = 0,
            name = "token",
            description = "Token",
            required = true,
            multiValued = false)
    String token;

    @Override
    public Object execute() throws Exception {
        System.out.println(authenticateService.validateToken(token));
        return null;
    }
}
