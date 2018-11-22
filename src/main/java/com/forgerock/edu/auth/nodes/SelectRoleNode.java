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
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;

import static org.forgerock.openam.auth.node.api.Action.send;

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
        String username = context.sharedState.get(USERNAME).asString();
        String realm = context.sharedState.get(REALM).asString();
        
        AMIdentity userIdentity = coreWrapper.getIdentity(username, realm);
        
        // Determine the common roles to create the final selectable list of roles.
        List<String> selectableRoles = getUserAssignedRoles(userIdentity);
        selectableRoles.retainAll(config.allRealmRoles());
        
        if (context.hasCallbacks()) {
            Action.ActionBuilder actionB = goToNext();
            //JsonValue copyState = context.sharedState.copy();
            Iterator<? extends Callback> iterator = context.getAllCallbacks().iterator();
            while (iterator.hasNext()) {
                ChoiceCallback choiceCb = (ChoiceCallback) iterator.next();
                int countSelected = choiceCb.getSelectedIndexes().length;
                if (countSelected > 1) {
                    debug.error(this.getClass().getSimpleName() + " Too many choices selected, cannot determine role to use.");
                    throw new NodeProcessException("Multiple roles choices is not supported, please choose one role");
                }
                else {
                    int selectedIdx = choiceCb.getSelectedIndexes()[0];
                    //debug.message("Selected Index: " + selectedIdx);
                    String selectedRole = choiceCb.getChoices()[selectedIdx];
                    debug.error("Choice from callack set as session selectedRole: " + selectedRole);
                    // Add selectedRole to session properties
                    // and to the shared state
                    actionB.putSessionProperty("selectedRole", selectedRole);     
                    //copyState.put("selectedRole", selectedRole);
                }
            }
            return actionB.build(); //  .replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
        }
        else {
            int numberOfRoles = selectableRoles.size();
            // Set the default role as the selectedRole if the number of selectable roles is zero.
            String selectedRole = config.defaultRole();
            
            //debug.message("Number of selectableRoles: " + numberOfRoles + ", selectedRole " + (numberOfRoles == 0 ? "(default): " : "(initial): ") + selectedRole);            
            if (numberOfRoles < 2) {
                // If numberOfRoles is one then set selectedRole to the first and only choice
                if (numberOfRoles == 1) selectedRole = selectableRoles.get(0);
                Action.ActionBuilder actionB = goToNext();
                //JsonValue copyState = context.sharedState.copy();
                actionB.putSessionProperty("selectedRole", selectedRole);  
                // Optionally, add the selectedRole into sharedState to use in a Scripted Deciscion node
                // copyState.put("selectedRole", selectedRole); 
                debug.error("Set session selectedRole: " + (numberOfRoles == 0 ? "(default) " : "(single) ")  + selectedRole);
                return actionB.build(); //replaceSharedState(copyState).build();
            }
            else { // more than one choice, build the callback
                //List<Callback> callbacks = new ArrayList<Callback>(1);
                String[] choices = new String[numberOfRoles];
                selectableRoles.toArray(choices);
                ChoiceCallback choiceCallback = new ChoiceCallback("Select Role", choices, 0, false);
                choiceCallback.setSelectedIndex(0);
                //debug.message("Get ChoiceCallback name: " + choiceCallback.getPrompt() + " default choice: " + choiceCallback.getDefaultChoice());
                //callbacks.add(choiceCallback);
                //return send(ImmutableList.copyOf(callbacks)).build();
                return send(ImmutableList.of(choiceCallback)).build();
            }             
        }
    }
    
    private List<String> getUserAssignedRoles(AMIdentity userIdentity) throws NodeProcessException {
        List<String> allUserRoles = new ArrayList<>(); 
        try {
            if (userIdentity != null && userIdentity.isExists() && userIdentity.isActive()) {
                try {
                    Set<AMIdentity> memberships = userIdentity.getMemberships(IdType.GROUP);
                    for (AMIdentity role : memberships) {
                        allUserRoles.add(role.getName());   
                    }
                }
                catch (IdRepoException ex) {
                    debug.error("Exception during querying groups...", ex);
                    // Due to this exception, answer will be empty;
                    throw new NodeProcessException(ex.getMessage());
                }
            }
            else {
                throw new NodeProcessException("User " + userIdentity.getName() + " either does not exist or is not active.");
            }
        }
        catch (IdRepoException | SSOException ex) {
            throw new NodeProcessException(ex.getMessage());
        }
        return allUserRoles;  // returns either an empty list, or a list with one or more roles.
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
