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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.TextOutputCallback;
import java.util.Set;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and shared key for this request.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = SelectRoleNode.Config.class,
        configValidator = SelectRoleNodeConfigValidator.class)
public class SelectRoleNode extends SingleOutcomeNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final AmIdentityHelper identityHelper;
    private final static String DEBUG_FILE = "SelectRoleNode";
    private final static Debug DEBUG = Debug.getInstance(DEBUG_FILE);

    /**
     * Configuration for the node.
     */
    public interface Config {

        @Attribute(order = 100, requiredValue = true)
        default String defaultRole() {
            return "ContactReader";
        }

        @Attribute(order = 200, requiredValue = true)
        default Set<String> candidateRoles() {
            try {
                final AmIdentityHelper identityHelper = InjectorHolder.getInstance(AmIdentityHelper.class);
                return identityHelper.findAllGroupNamesInRealm("/");
            } catch (SSOException | IdRepoException ex) {
                DEBUG.error("Error during retrieving groups in root realm", ex);
                return ImmutableSet.of("ContactReader", "ContactAdmin", "ProfileAdmin");
            }
        }
    }

    /**
     * Create the node.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public SelectRoleNode(@Assisted Config config, CoreWrapper coreWrapper, AmIdentityHelper identityHelper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
        this.identityHelper = identityHelper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        String username = context.sharedState.get(USERNAME).asString();
        String realm = context.sharedState.get(REALM).asString();

        AMIdentity userIdentity = coreWrapper.getIdentity(username, realm);
        String[] selectableRoles = calculateSelectableRoles(userIdentity);


        if (context.hasCallbacks()) {
            return context.getCallback(ChoiceCallback.class)
                    .map(choiceCallback -> {
                        final int[] selectedIndexes = choiceCallback.getSelectedIndexes();
                        if (selectedIndexes.length != 1) {
                            return send(ImmutableList.of(
                                    createWarning("You should select one and only one role!"),
                                    createSelectRoleChoiceCallback(selectableRoles)))
                                    .build();
                        } else {
                            int selectedIndex = selectedIndexes[0];
                            String selectedRole = selectableRoles[selectedIndex];
                            return gotoNextWithSelectedRole(selectedRole);
                        }
                    }).orElseThrow(() -> new NodeProcessException("Required ChoiceCallback is missing"));

        } else {
            switch (selectableRoles.length) {
                case 0:
                    return gotoNextWithSelectedRole(config.defaultRole());
                case 1:
                    String selectedRole = selectableRoles[0];
                    return gotoNextWithSelectedRole(selectedRole);
                default:
                    return sendCallbacks(createSelectRoleChoiceCallback(selectableRoles));

            }
        }
    }

    private Action gotoNextWithSelectedRole(String selectedRole) {
        return goToNext()
                .putSessionProperty("selectedRole", selectedRole)
                .build();
    }

    private Action sendCallbacks(Callback... callbacks) {
        return send(ImmutableList.copyOf(callbacks))
                .build();
    }

    private ChoiceCallback createSelectRoleChoiceCallback(String[] selectableRoles) {
        return new ChoiceCallback("Select Role",
                selectableRoles, 0, false);
    }

    private TextOutputCallback createWarning(String message) {
        return new TextOutputCallback(TextOutputCallback.WARNING, message);
    }

    private String[] calculateSelectableRoles(AMIdentity userIdentity) throws NodeProcessException {
        try {
            return identityHelper.findAllAssignedGroupNamesOfUser(userIdentity)
                    .stream()
                    .filter(groupName -> config.candidateRoles().contains(groupName))  // filter out groups not in candidateRoles
                    .toArray(String[]::new);
        } catch (SSOException | IdRepoException ex) {
            throw new NodeProcessException("Error during querying user's group memberships", ex);
        }
    }

}
