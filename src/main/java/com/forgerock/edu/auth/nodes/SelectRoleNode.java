/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */


package com.forgerock.edu.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/** 
 * A node that checks to see if zero-page login headers have specified username and shared key 
 * for this request. 
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = SelectRoleNode.Config.class)
public class SelectRoleNode extends AbstractDecisionNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "SelectRoleNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String usernameHeader() {
            return "X-OpenAM-Username";
        }

        @Attribute(order = 200)
        default String passwordHeader() {
            return "X-OpenAM-Password";
        }

        @Attribute(order = 300)
        default String secretKey() {
            return "secretKey";
        }
    }


    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public SelectRoleNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        boolean hasUsername = context.request.headers.containsKey(config.usernameHeader());
        boolean hasPassword = context.request.headers.containsKey(config.passwordHeader());

        if (!hasUsername || !hasPassword) {
            return goTo(false).build();
        }

        String secret = config.secretKey();
        String password = context.request.headers.get(config.passwordHeader()).get(0);
        String username = context.request.headers.get(config.usernameHeader()).get(0);
        AMIdentity userIdentity = coreWrapper.getIdentity(username, context.sharedState.get(REALM).asString());
        try {
            if (secret.equals(password) && userIdentity != null && userIdentity.isExists() && userIdentity.isActive()) {
                return goTo(true).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
            }
        } catch (IdRepoException e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
        } catch (SSOException e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
        }
        return goTo(false).build();
    }
}