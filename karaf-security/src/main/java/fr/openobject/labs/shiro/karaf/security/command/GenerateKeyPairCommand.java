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
import java.util.Map;
import org.apache.karaf.shell.api.action.Action;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;

@Service
@Command(scope = "shiro-labs", name = "generate-keys", description = "Generate Asymetric KeyPair")
public class GenerateKeyPairCommand implements Action {

    @Reference private AuthenticateService authenticateService;

    @Override
    public Object execute() throws Exception {
        Map<String, String> keys = authenticateService.generateKeyPair();
        keys.entrySet().stream().forEach(entry -> System.out.println("{" + entry + "}"));
        return null;
    }
}
