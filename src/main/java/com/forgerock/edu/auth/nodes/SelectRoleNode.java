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
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.AuthContext;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.debug.Debug;
import java.security.AccessController;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and shared key for this request.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = SelectRoleNode.Config.class)
public class SelectRoleNode extends SingleOutcomeNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "SelectRoleNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100)
        default String defaultRole() {
            return "ContactReader";
        }

        @Attribute(order = 200)
        default List<String> allRealmRoles() {
            return SelectRoleNode.getAllRealmRoles();
        }
    }

    /**
     * Create the node.
     *
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
        String username = "demo";
        AMIdentity userIdentity = coreWrapper.getIdentity(username, context.sharedState.get(REALM).asString());

        try {
            if (userIdentity != null && userIdentity.isExists()
                    && userIdentity.isActive()) {
                return goToNext().replaceSharedState(
                        context.sharedState.copy().put(
                                USERNAME, username)).build();
            }
        } catch (IdRepoException e) {
            debug.error("[" + DEBUG_FILE + "]: "
                    + "Error locating user '{}' ", e);
        } catch (SSOException e) {
            debug.error("[" + DEBUG_FILE + "]: "
                    + "Error locating user '{}' ", e);
        }
        return goToNext().build();
    }

    private static List<String> getAllRealmRoles() {
        SSOToken adminToken = (SSOToken) AccessController.doPrivileged(AdminTokenAction.getInstance());
        Set<AMIdentity> groups = Collections.EMPTY_SET;
        try {
            String orgDN
                    = new AuthContext(adminToken).getOrganizationName();
            AMIdentityRepository amIdRepo
                    = new AMIdentityRepository(orgDN, adminToken);
            IdSearchControl search = new IdSearchControl();
            IdSearchResults result = amIdRepo.searchIdentities(
                    IdType.GROUP, "*", search);
            groups = result.getSearchResults();
        } catch (Exception ex) {
            System.err.println("[" + DEBUG_FILE
                    + "]: Exception querying groups..."
                    + ex.getMessage());
        // Due to this exception, answer will be empty;
        }
        List<String> realmRoles = new ArrayList();
        if ((groups != null) && !groups.isEmpty()) {
            for (AMIdentity group : groups) {
                try {
                    realmRoles.add(group.getName());
                } catch (Exception e) {
                    System.err.println("[" + DEBUG_FILE
                            + "]: Error in getAllRealmRoles: "
                            + e.getMessage());
                }
            }
        } else {
            realmRoles = new ArrayList(Arrays.asList(
                    "ContactReader", "ContactAdmin", "ProfileAdmin"));
        }
        return realmRoles;
    }
}
