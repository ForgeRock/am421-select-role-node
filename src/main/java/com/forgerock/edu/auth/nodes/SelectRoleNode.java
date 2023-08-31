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
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;

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
// DONE Ch2L2Ex2 Task3: Observe that the SelectRoleNode now extends SingleOutcomeNode
// DONE Ch2L2Ex2 Task3:   Which provides the goToNext() method without parameters
// DONE Ch2L2Ex2 Task3:     as it just has a single outcome.
// DONE Ch2L2Ex2 Task3:   Note that the outcomeProvider is also set to
// DONE Ch2L2Ex2 Task3:     SingleOutcomeNode.OutcomeProvider.class
// DONE Ch2L2Ex2 Task5: Add configValidator = SelectRoleNodeConfigValidator.class to the metadata
// DONE Ch2L2Ex2 Task5:   The SelectRoleNodeConfigValidator class has been provided as an example
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = SelectRoleNode.Config.class,
        configValidator = SelectRoleNodeConfigValidator.class)
public class SelectRoleNode extends SingleOutcomeNode {

    private final Config config;
    private final AmIdentityHelper identityHelper;
    private final static Debug DEBUG = Debug.getInstance("SelectRoleNode");

    /**
     * Configuration for the node.
     */
    public interface Config {

        // DONE Ch2L2Ex2 Task5: Observe the @Attribute annotation's properties
        // DONE Ch2L2Ex2 Task5:   Note that the attributes are now required
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
                // DONE Ch2L2Ex2 Task5: Query the group names within the top level realm ("/") by invoking the identityHelper's appropriate method
                // DONE Ch2L2Ex2 Task5: and return with this instead of static values.
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
    // DONE Ch2L2Ex2 Task4: Add an AMIdentityHelper reference to the constructor's parameter list
    // DONE Ch2L2Ex2 Task4:   It will be instantiated and injected automatically by Guice
    @Inject
    public SelectRoleNode(@Assisted Config config, AmIdentityHelper identityHelper) throws NodeProcessException {
        this.config = config;
        // DONE Ch2L2Ex2 Task4: Save the identityHelper reference into the instance variable named identityHelper
        // DONE Ch2L2Ex2 Task4:   Hint: this.identityHelper = identityHelper;
        this.identityHelper = identityHelper;
    }

    // DONE Ch2L2Ex2 Task4: Remove this constructor, as this is just here to let the unit test class compile

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        String realm = context.sharedState.get(REALM).asString();
        // DONE Ch2L2Ex2 Task7: Acquire the authenticated user's name from the sharedState.
        // DONE Ch2L2Ex2 Task7:   Hint: Use SharedStateConstants.USERNAME as the key.
        String username = context.sharedState.get(USERNAME).asString();

        // DONE Ch2L2Ex2 Task7: Get the authenticated user's AMIdentity object by using IdUtils' getIdentity method.
        // DONE Ch2L2Ex2 Task7:   Hint: Use IdUtils.getIdentity(String username, String realm) method
        AMIdentity userIdentity = IdUtils.getIdentity(username, realm);

        // DONE Ch2L2Ex2 Task7: Calculate selectable roles by calling calculateSelectableRoles method and store it in the selectableRoles variable.
        String[] selectableRoles = calculateSelectableRoles(userIdentity);


        if (!context.hasCallbacks()) {
            // No callbacks, which means this is the first invocation

            // DONE Ch2L2Ex2 Task7: Remove return goToNext().build() placeholder from the provided switch's
            // DONE Ch2L2Ex2 Task7:   default branch and implement the proper business logic:
            // DONE Ch2L2Ex2 Task7:   Based on the length of the selectableRoles array:

            switch (selectableRoles.length) {
                case 0:
                    // DONE Ch2L2Ex2 Task7:     When selectableRoles.length = 0
                    // DONE Ch2L2Ex2 Task7:       return gotoNextWithSelectedRole(config.defaultRole())
                    return gotoNextWithSelectedRole(config.defaultRole());
                case 1:
                    // DONE Ch2L2Ex2 Task7:     When selectableRoles.length = 1
                    // DONE Ch2L2Ex2 Task7:       return gotoNextWithSelectedRole(selectedRole)
                    String selectedRole = selectableRoles[0];
                    return gotoNextWithSelectedRole(selectedRole);
                default:
                    // DONE Ch2L2Ex2 Task7:     Otherwise
                    // DONE Ch2L2Ex2 Task7:       send back a ChoiceCallback instance with the selectable roles
                    // DONE Ch2L2Ex2 Task7:       Hint: use the sendCallbacks method and the createSelectRoleChoiceCallback method
                    return sendCallbacks(createSelectRoleChoiceCallback(selectableRoles));
            }

        } else {
            // The callbacks were filled out by the client and sent back
            // Let's process it

            // DONE Ch2L2Ex2 Task7: Find the ChoiceCallback in the context by invoking context.getCallback(ChoiceCallback.class)
            // DONE Ch2L2Ex2 Task7:   and store it in the optionalChoiceCallback variable
            Optional<ChoiceCallback> optionalChoiceCallback
                    = context.getCallback(ChoiceCallback.class);

            if (optionalChoiceCallback.isPresent()) {
                // When the ChoiceCallback is present in the incoming request
                //   (the authentication client submitted the user's choice)

                // DONE Ch2L2Ex2 Task7: Remove the original line: return goToNext().build();
                // DONE Ch2L2Ex2 Task7: Store the ChoiceCallback's selectedIndexes
                // DONE Ch2L2Ex2 Task7:   in a variable named selectedIndexes.
                // DONE Ch2L2Ex2 Task7:   Hint#1: use Optional.get() method to retrieve the ChoiceCallback reference
                // DONE Ch2L2Ex2 Task7:   Hint#2: use ChoiceCallback.getSelectedIndexes() method to retrieve the selectedIndexes array
                final int[] selectedIndexes = optionalChoiceCallback.get().getSelectedIndexes();

                // DONE Ch2L2Ex2 Task7: Create two conditional branches based on the selectedIndexes array's length
                if (selectedIndexes.length != 1) {
                    // DONE Ch2L2Ex2 Task7:   When the selectedIndexes.length != 1
                    // DONE Ch2L2Ex2 Task7:     send back two callbacks:
                    // DONE Ch2L2Ex2 Task7:       1. a TextOutputCallback with a warning message: "You should select one and only one role!"
                    // DONE Ch2L2Ex2 Task7:       2. a ChoiceCallback with the selectableRoles
                    // DONE Ch2L2Ex2 Task7:     Hint#1: use the provided createWarning() and createSelectRoleChoiceCallback() methods
                    // DONE Ch2L2Ex2 Task7:     Hint#2: return sendCallbacks(createWarning("...",createSelectRoleChoiceCallback(selectableRoles))
                    return sendCallbacks(
                            createWarning("You should select one and only one role!"),
                            createSelectRoleChoiceCallback(selectableRoles));
                } else {
                    // DONE Ch2L2Ex2 Task7: When the selectedIndexes.length = 1
                    // DONE Ch2L2Ex2 Task7:   Calculate the selectedIndex. Hint: use the only element in the selectedIndexes array.
                    int selectedIndex = selectedIndexes[0];

                    // DONE Ch2L2Ex2 Task7:   Check whether the selected index is negative or selectedIndex >= selectableRoles.length
                    // DONE Ch2L2Ex2 Task7:     In these cases send back a warning and the callbacks as before
                    // DONE Ch2L2Ex2 Task7:     The warning message should be something like this:
                    // DONE Ch2L2Ex2 Task7:       "Non-existing index is received, choose an existing one"
                    // DONE Ch2L2Ex2 Task7:     Hint: return sendCallbacks(createWarning("...",createSelectRoleChoiceCallback(selectableRoles))
                    if (selectedIndex < 0 || selectedIndex >= selectableRoles.length) {
                        return sendCallbacks(
                                createWarning("Non-existing index is received, choose an existing one"),
                                createSelectRoleChoiceCallback(selectableRoles));
                    }
                    // DONE Ch2L2Ex2 Task7:   Calculate the selectedRole by selecting it from the selectableRoles array by the selectedIndex.
                    // DONE Ch2L2Ex2 Task7:     Hint: String selectedRole = selectableRoles[selectedIndex]
                    String selectedRole = selectableRoles[selectedIndex];
                    // DONE Ch2L2Ex2 Task7:   Set the selectedRole session property to the Action and go to the next node.
                    // DONE Ch2L2Ex2 Task7:     Hint#1: use the gotoNextWithSelectedRole(selectedRole) method
                    // DONE Ch2L2Ex2 Task7:     Hint#2: use the provided createWarning() and createSelectRoleChoiceCallback() methods
                    return gotoNextWithSelectedRole(selectedRole);
                }
            } else {
                // DONE Ch2L2Ex2 Task7: Instead of returning goToNext().build()
                // DONE Ch2L2Ex2 Task7:   throw new NodeProcessException("Required ChoiceCallback is missing");
                throw new NodeProcessException("Required ChoiceCallback is missing");
            }
        }
    }

    private Action gotoNextWithSelectedRole(String selectedRole) {
        // DONE Ch2L2Ex2 Task7: put the selectedRole into a session property named selectedRole
        // DONE Ch2L2Ex2 Task7:   Hint: Use the ActionBuilder's putSessionProperty method.
        // DONE Ch2L2Ex2 Task7:         goToNext().putSessionProperty(...).build()
        return goToNext()
                .putSessionProperty("selectedRole", selectedRole)
                .build();
    }

    // DONE Ch2L2Ex2 Task7: Observe the usage of the send() method.
    // DONE Ch2L2Ex2 Task7:   This is a convenient way of sending back callbacks to the client
    private Action sendCallbacks(Callback... callbacks) {
        return send(ImmutableList.copyOf(callbacks))
                .build();
    }

    private ChoiceCallback createSelectRoleChoiceCallback(String[] selectableRoles) {
        // DONE Ch2L2Ex2 Task7: Observe the creation of the ChoiceCallback instance
        // DONE Ch2L2Ex2 Task7:   as this will be sent back to the authentication client
        // DONE Ch2L2Ex2 Task7:   and has to be filled in.
        return new ChoiceCallback("Select Role",
                selectableRoles, 0, false);
    }

    private TextOutputCallback createWarning(String message) {
        // DONE Ch2L2Ex2 Task7: Observe the creation of the TextOutputCallback instance.
        // DONE Ch2L2Ex2 Task7:   this way we can send back a warning message to the
        // DONE Ch2L2Ex2 Task7:   authentication client.
        return new TextOutputCallback(TextOutputCallback.WARNING, message);
    }

    // DONE Ch2L2Ex2 Task7: Observe the next method, where the selectable roles of
    // DONE Ch2L2Ex2 Task7:   the userIdentity are calculated by intersecting the
    // DONE Ch2L2Ex2 Task7:   user's group memberships with the candidateRoles.
    private String[] calculateSelectableRoles(AMIdentity userIdentity) throws NodeProcessException {
        try {
            final Set<String> assignedGroupNames =
                    identityHelper.findAllAssignedGroupNamesOfUser(userIdentity);

            final Set<String> candidateRoles = config.candidateRoles();

            return assignedGroupNames
                    .stream()
                    .filter(candidateRoles::contains)  // filter out groups not in candidateRoles
                    .toArray(String[]::new);
        } catch (SSOException | IdRepoException ex) {
            throw new NodeProcessException("Error during querying user's group memberships", ex);
        }
    }

}
