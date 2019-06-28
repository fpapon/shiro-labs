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

import javax.servlet.ServletContext;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.Ini;
import org.apache.shiro.web.env.EnvironmentLoader;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(immediate = true)
public class ShiroService {

    private Logger logger = LoggerFactory.getLogger(ShiroService.class);

    private IniWebEnvironment environment;

    @Reference
    private ServletContext servletContext;

    @Reference
    private JwtRealm realm;

    @Activate
    public void activate(ComponentContext componentContext) throws Exception {

        Ini ini = Ini.fromResourcePath(System.getProperty("karaf.etc") + "/shiro.ini");
        this.environment = new IniWebEnvironment();
        environment.setIni(ini);
        environment.setServletContext(servletContext);
        environment.init();

        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setSessionIdUrlRewritingEnabled(true);

        DefaultWebSecurityManager.class.cast(environment.getWebSecurityManager()).setSessionManager(sessionManager);
        DefaultWebSecurityManager.class.cast(environment.getWebSecurityManager()).setRealm(this.realm);

        SecurityUtils.setSecurityManager(environment.getWebSecurityManager());

        servletContext.setAttribute(EnvironmentLoader.ENVIRONMENT_ATTRIBUTE_KEY, environment);
    }

    @Deactivate
    public void deactivate() {
        // do nothing
    }

}
