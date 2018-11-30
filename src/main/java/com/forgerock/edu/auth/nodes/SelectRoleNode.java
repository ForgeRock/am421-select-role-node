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
import java.util.Optional;
import java.util.Set;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that checks to see if zero-page login headers have specified username
 * and shared key for this request.
 */
// TODO Ch2L2Ex2 Add configValidator = SelectRoleNodeConfigValidator.class to the metadata
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
                // InjectorHolder.getInstance is used to obtain a reference to a Guice managed object
                // This way the injector will instantiate AmIdentityHelper and if it has further dependencies, it will inject those.
                final AmIdentityHelper identityHelper = InjectorHolder.getInstance(AmIdentityHelper.class);
                // TODO Ch2L2Ex2 Query the group names within the top level realm ("/") by invoking the identityHelper's appropriate method
                // TODO Ch2L2Ex2 and return with this instead of static values.
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
    // TODO Ch2L2Ex2 Add an AMIdentityHelper reference to the constructor's parameter list
    // TODO Ch2L2Ex2   It will be instantiated and injected automatically by Guice
    @Inject
    public SelectRoleNode(@Assisted Config config, CoreWrapper coreWrapper, AmIdentityHelper identityHelper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
        // TODO Ch2L2Ex2 Save the identityHelper reference into the instance variable named identityHelper
        // TODO Ch2L2Ex2   Hint: this.identityHelper = identityHelper;
        this.identityHelper = identityHelper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        String realm = context.sharedState.get(REALM).asString();
        // TODO Ch2L2Ex2 Acquire the authenticated user's name from the sharedState.
        // TODO Ch2L2Ex2   Hint: Use SharedStateConstants.USERNAME as the key.
        String username = context.sharedState.get(USERNAME).asString();

        // TODO Ch2L2Ex2 Get the authenticated user's AMIdentity object by using the coreWrapper's getIdentity method.
        // TODO Ch2L2Ex2   Hint: Use CoreWrapper.getIdentity(String username, String realm) method
        AMIdentity userIdentity = coreWrapper.getIdentity(username, realm);

        // TODO Ch2L2Ex2 Calculate selectable roles by calling calculateSelectableRoles method and store it in the selectableRoles variable.
        String[] selectableRoles = calculateSelectableRoles(userIdentity);


        if (context.hasCallbacks()) {
            // The callbacks were filled out by the client and sent back
            // Let's process it

            // TODO Ch2L2Ex2 Find the ChoiceCallback in the context by invoking context.getCallback(ChoiceCallback.class)
            // TODO Ch2L2Ex2 Store it in a variable called optionalChoiceCallback
            Optional<ChoiceCallback> optionalChoiceCallback
                    = context.getCallback(ChoiceCallback.class);

            // TODO Ch2L2Ex2 Create two conditional branches: one for handling the situation
            // TODO Ch2L2Ex2   when the ChoiceCallback is present in optionalChoiceCallback
            // TODO Ch2L2Ex2   and one for the opposite case.

            // TODO Ch2L2Ex2 When the ChoiceCallback is present
            // TODO Ch2L2Ex2   Store the ChoiceCallback's selectedIndexes
            // TODO Ch2L2Ex2     in a variable named selectedIndexes.
            // TODO Ch2L2Ex2     Hint#1: use Optional.get() method to retrieve the ChoiceCallback reference
            // TODO Ch2L2Ex2     Hint#2: use ChoiceCallback.getSelectedIndexes() method to retrieve the selectedIndexes array
            // TODO Ch2L2Ex2   When the ChoiceCallback is present and the selectedIndexes.length != 1
            // TODO Ch2L2Ex2     send back two callbacks:
            // TODO Ch2L2Ex2       1. a TextOutputCallback with a warning message: "You should select one and only one role!"
            // TODO Ch2L2Ex2       2. a ChoiceCallback with the selectableRoles
            // TODO Ch2L2Ex2     Hint: use the provided createWarning() and createSelectRoleChoiceCallback() methods
            // TODO Ch2L2Ex2   When the ChoiceCallback is present and the selectedIndexes.length = 1
            // TODO Ch2L2Ex2     Calculate the selectedIndex. Hint: use the only element in the selectedIndexes array.
            // TODO Ch2L2Ex2     Calculate the selectedRole by selecting it from the selectableRoles array by the selectedIndex.
            // TODO Ch2L2Ex2       Hint: String selectedRole = selectableRoles[selectedIndex]
            // TODO Ch2L2Ex2     Set the selectedRole session property to the Action and go to the next node.
            // TODO Ch2L2Ex2       Hint: use the gotoNextWithSelectedRole(selectedRole) method
            // TODO Ch2L2Ex2     Hint: use the provided createWarning() and createSelectRoleChoiceCallback() methods
            // TODO Ch2L2Ex2 When the ChoiceCallback is not present
            // TODO Ch2L2Ex2   throw new NodeProcessException("Required ChoiceCallback is missing");

            if (optionalChoiceCallback.isPresent()) {
                final int[] selectedIndexes = optionalChoiceCallback.get().getSelectedIndexes();
                if (selectedIndexes.length != 1) {
                    return sendCallbacks(
                            createWarning("You should select one and only one role!"),
                            createSelectRoleChoiceCallback(selectableRoles));
                } else {
                    int selectedIndex = selectedIndexes[0];
                    String selectedRole = selectableRoles[selectedIndex];
                    return gotoNextWithSelectedRole(selectedRole);
                }
            } else {
                throw new NodeProcessException("Required ChoiceCallback is missing");
            }

        } else {
            // TODO Ch2L2Ex2 Create a switch branch based on the length of the selectableRoles array:
            // TODO Ch2L2Ex2   When selectableRoles.length = 0
            // TODO Ch2L2Ex2     return gotoNextWithSelectedRole(config.defaultRole())
            // TODO Ch2L2Ex2   When selectableRoles.length = 1
            // TODO Ch2L2Ex2     return gotoNextWithSelectedRole(selectedRole)
            // TODO Ch2L2Ex2   Otherwise
            // TODO Ch2L2Ex2     send back a ChoiceCallback instance with the selectable roles
            // TODO Ch2L2Ex2     Hint: use the sendCallbacks method and the createSelectRoleChoiceCallback method

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
        // TODO Ch2L2Ex2 put the selectedRole into a session property named selectedRole
        // TODO Ch2L2Ex2   Hint: Use the ActionBuilder's putSessionProperty method.
        // TODO Ch2L2Ex2         goToNext().putSessionProperty(...).build()
        return goToNext()
                .putSessionProperty("selectedRole", selectedRole)
                .build();
    }

    // TODO Ch2L2Ex2 Observe the usage of the send() method.
    // TODO Ch2L2Ex2   This is a convenient way of sending back callbacks to the client
    private Action sendCallbacks(Callback... callbacks) {
        return send(ImmutableList.copyOf(callbacks))
                .build();
    }

    private ChoiceCallback createSelectRoleChoiceCallback(String[] selectableRoles) {
        // TODO Ch2L2Ex2 Observe the creation of the ChoiceCallback instance
        // TODO Ch2L2Ex2   as this will be sent back to the authentication client
        // TODO Ch2L2Ex2   and has to be filled in.
        return new ChoiceCallback("Select Role",
                selectableRoles, 0, false);
    }

    private TextOutputCallback createWarning(String message) {
        // TODO Ch2L2Ex2 Observe the creation of the TextOutputCallback instance.
        // TODO Ch2L2Ex2   this way we can send back a warning message to the
        // TODO Ch2L2Ex2   authentication client.
        return new TextOutputCallback(TextOutputCallback.WARNING, message);
    }

    // TODO Ch2L2Ex2 Observe the next method, where the selectable roles of
    // TODO Ch2L2Ex2   the userIdentity are calculated by intersecting the
    // TODO Ch2L2Ex2   user's group memberships with the candidateRoles.
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
