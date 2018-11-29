package com.forgerock.edu.auth.nodes;

import com.google.common.collect.ImmutableSet;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdType;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

class SelectRoleNodeTest {
    SelectRoleNode.Config defaultConfig;
    CoreWrapper coreWrapper;
    AMIdentity userIdentity;
    AmIdentityHelper identityHelper;
    JsonValue sharedState;
    SelectRoleNode selectRoleNode;

    @BeforeEach
    void beforeEach() throws Exception {
        defaultConfig = mock(SelectRoleNode.Config.class);
        coreWrapper = mock(CoreWrapper.class);
        userIdentity = mock(AMIdentity.class);
        identityHelper = mock(AmIdentityHelper.class);
        sharedState = mock(JsonValue.class);

        given(defaultConfig.defaultRole())
                .willReturn("def");
        given(defaultConfig.candidateRoles())
                .willReturn(ImmutableSet.of("def", "first", "second"));

        given(sharedState.get(SharedStateConstants.REALM))
                .willReturn(new JsonValue("/"));
        given(sharedState.get(SharedStateConstants.USERNAME))
                .willReturn(new JsonValue("john"));

        given(userIdentity.isActive())
                .willReturn(true);
        given(userIdentity.isExists())
                .willReturn(true);
        given(userIdentity.getType())
                .willReturn(IdType.USER);
        given(userIdentity.getName())
                .willReturn("john");

        given(coreWrapper.getIdentity(eq("john"), anyString()))
                .willReturn(userIdentity);

        given(identityHelper.findAllGroupNamesInRealm("/"))
                .willReturn(ImmutableSet.of("def","first","second","third","fourth"));

        selectRoleNode = new SelectRoleNode(defaultConfig, coreWrapper, identityHelper);
    }

    @Test
    @DisplayName("shouldReturnChoiceCallbackWhenSelectableRolesSizeIsGreaterThanOne")
    void shouldReturnChoiceCallbackWhenSelectableRolesSizeIsGreaterThanOne() throws Exception {

        given(identityHelper.findAllAssignedGroupNamesOfUser(userIdentity))
                .willReturn(ImmutableSet.of("def","second","fourth"));

        final ExternalRequestContext externalRequestContext = new ExternalRequestContext.Builder().build();
        final TreeContext treeContext = new TreeContext(sharedState, externalRequestContext, Collections.emptyList());

        //WHEN
        final Action action = selectRoleNode.process(treeContext);

        assertEquals(action.callbacks.size(), 1);
        assertTrue(action.callbacks.get(0) instanceof ChoiceCallback);
        final ChoiceCallback callback = (ChoiceCallback) action.callbacks.get(0);
        assertArrayEquals(new String[] {"def", "second"}, callback.getChoices());
    }

    @Test
    @DisplayName("shouldReturnChoiceCallbackWhenSelectableRolesSizeIsGreaterThanOne")
    void shouldReturnSelectedRoleImmediatelyWhenSelectableIsOnlyOne() throws Exception {

        given(identityHelper.findAllAssignedGroupNamesOfUser(userIdentity))
                .willReturn(ImmutableSet.of("second","fourth"));

        final ExternalRequestContext externalRequestContext = new ExternalRequestContext.Builder().build();
        final TreeContext treeContext = new TreeContext(sharedState, externalRequestContext, Collections.emptyList());

        //WHEN
        final Action action = selectRoleNode.process(treeContext);

        assertEquals(action.callbacks.size(), 0);
        assertEquals(action.sessionProperties.get("selectedRole"), "second");
    }

    @Test
    @DisplayName("shouldReturnChoiceCallbackWhenSelectableRolesSizeIsGreaterThanOne")
    void shouldReturnDefaultRoleImmediatelyWhenSelectableIsEmpty() throws Exception {

        given(identityHelper.findAllAssignedGroupNamesOfUser(userIdentity))
                .willReturn(ImmutableSet.of("fourth"));

        final ExternalRequestContext externalRequestContext = new ExternalRequestContext.Builder().build();
        final TreeContext treeContext = new TreeContext(sharedState, externalRequestContext, Collections.emptyList());

        //WHEN
        final Action action = selectRoleNode.process(treeContext);

        assertEquals(action.callbacks.size(), 0);
        assertEquals(action.sessionProperties.get("selectedRole"), "def");
    }
}