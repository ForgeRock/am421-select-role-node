package com.forgerock.edu.auth.nodes;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdType;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.junit.jupiter.api.*;
import org.opentest4j.AssertionFailedError;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.TextOutputCallback;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

// DONE Ch2L2Ex2 Task6: Observe the unit tests and run them
class SelectRoleNodeTest {
    SelectRoleNode.Config config;
    AMIdentity userIdentity;
    AmIdentityHelper identityHelper;
    JsonValue sharedState;
    SelectRoleNode selectRoleNode;
    Set<String> candidateRoles;
    String defaultRole;
    TreeContext createTreeContextWithoutCallbacks() {
        final ExternalRequestContext externalRequestContext = new ExternalRequestContext.Builder().build();
        return new TreeContext(sharedState, externalRequestContext, Collections.emptyList(), Optional.empty());
    }

    TreeContext createTreeContextWithCallbacks(Callback... callbacks) {
        final List<Callback> callbackList = ImmutableList.copyOf(callbacks);
        final ExternalRequestContext externalRequestContext = new ExternalRequestContext.Builder().build();
        return new TreeContext(sharedState, externalRequestContext, callbackList, Optional.empty());
    }

    void givenUserIsMemberOf(String... groupNames) throws Exception {
        given(identityHelper.findAllAssignedGroupNamesOfUser(userIdentity))
                .willReturn(ImmutableSet.copyOf(groupNames));
    }


    @BeforeEach
    void beforeEach() throws Exception {
        config = mock(SelectRoleNode.Config.class);
        userIdentity = mock(AMIdentity.class);
        identityHelper = mock(AmIdentityHelper.class);
        sharedState = mock(JsonValue.class);
        defaultRole = "Default";
        candidateRoles = ImmutableSet.of(defaultRole, "first", "second");

        // Config
        given(config.defaultRole())
                .willReturn(defaultRole);
        given(config.candidateRoles())
                .willReturn(candidateRoles);

        // Shared State
        given(sharedState.get(SharedStateConstants.REALM))
                .willReturn(new JsonValue("/"));
        given(sharedState.get(SharedStateConstants.USERNAME))
                .willReturn(new JsonValue("john"));

        // User's identity
        given(userIdentity.isActive())
                .willReturn(true);
        given(userIdentity.isExists())
                .willReturn(true);
        given(userIdentity.getType())
                .willReturn(IdType.USER);
        given(userIdentity.getName())
                .willReturn("john");

        given(identityHelper.getIdentity(eq("john"), anyString()))
                .willReturn(userIdentity);

        // The tested class instance
        selectRoleNode = new SelectRoleNode(config, identityHelper);
    }

    @AfterEach
    void afterEach() {
        //idUtils.close();
    }

    @Nested
    @DisplayName("When no callbacks received")
    class NoCallbacks {

        TreeContext treeContext;

        @BeforeEach
        void beforeEach() {
            treeContext = createTreeContextWithoutCallbacks();
        }

        @Nested
        @DisplayName("When the number of selectable roles > 1")
        class SelectableRoleSizeIsGreaterThanOne {
            @BeforeEach
            void beforeEach() throws Exception {
                givenUserIsMemberOf(defaultRole, "second", "fourth");
                // the intersection is defaultRole and "second"
            }

            @Test
            @DisplayName("Should return a ChoiceCallback instance with the selectable roles")
            void shouldReturnChoiceCallbackWhenSelectableRolesSizeIsGreaterThanOne() throws Exception {
                //WHEN
                final Action action = selectRoleNode.process(treeContext);
                //ASSERTIONS
                assertEquals(1, action.callbacks.size());
                assertTrue(action.callbacks.get(0) instanceof ChoiceCallback);
                final ChoiceCallback callback = (ChoiceCallback) action.callbacks.get(0);
                assertArrayEquals(new String[]{defaultRole, "second"},
                        callback.getChoices(),
                        "The ChoiceCallbacks object does not contain the expected choices");
            }
        }

        @Nested
        @DisplayName("When the number of selectable roles = 1")
        class SelectableRoleSizeIsOne {
            @BeforeEach
            void beforeEach() throws Exception {
                givenUserIsMemberOf("second", "fourth");
                // So the intersection will "second"
            }

            @Test
            @DisplayName("Should go to next node with selectedRole session property set to the only selectable role")
            void shouldReturnSelectedRoleImmediatelyWhenSelectableIsOnlyOne() throws Exception {

                //WHEN
                final Action action = selectRoleNode.process(treeContext);

                assertEquals(0, action.callbacks.size());
                assertEquals("second", action.sessionProperties.get("selectedRole"),
                        "The selectedRole is not set to 'second'");
            }

        }

        @Nested
        @DisplayName("When the number of selectable roles = 0")
        class SelectableRoleSizeIsZero {
            @BeforeEach
            void beforeEach() throws Exception {
                givenUserIsMemberOf("fourth");
                // So the intersection will be an empty set
            }

            @Test
            @DisplayName("Should go to next node with selectedRole session property set config.defaultRole")
            void shouldReturnDefaultRoleImmediatelyWhenSelectableIsEmpty() throws Exception {

                //WHEN
                final Action action = selectRoleNode.process(treeContext);

                assertEquals(0, action.callbacks.size(),
                        "The callbacks size is not zero");
                assertEquals(defaultRole, action.sessionProperties.get("selectedRole"),
                        "The selectedRole is not config.defaultRole");
            }

        }

    }

    @Nested
    @DisplayName("When callbacks received")
    class Callbacks {

        TreeContext treeContext;
        TextOutputCallback otherCallback;
        String[] offeredChoices;

        @BeforeEach
        void beforeEach() throws Exception {
            givenUserIsMemberOf(defaultRole, "second", "fourth");
            offeredChoices = new String[]{defaultRole, "second"};
            // the intersection is defaultRole and "second"
            otherCallback = new TextOutputCallback(TextOutputCallback.WARNING, "msg");
        }

        ChoiceCallback choiceCallbackWithSelectedIndexes(int... selectedIndexes) {
            final ChoiceCallback choiceCallback = new ChoiceCallback("Select Role", offeredChoices, 0, true);
            choiceCallback.setSelectedIndexes(selectedIndexes);
            return choiceCallback;
        }

        ChoiceCallback choiceCallbackWithNoSelectedIndexes() {
            return choiceCallbackWithSelectedIndexes(new int[0]);
        }

        ChoiceCallback choiceCallbackWithSelectedIndex(int selectedIndex) {
            return choiceCallbackWithSelectedIndexes(selectedIndex);
        }

        @Nested
        @DisplayName("When the ChoiceCallback is missing")
        class NoChoiceCallback {
            @BeforeEach
            void beforeEach() throws Exception {
                treeContext = createTreeContextWithCallbacks(otherCallback);
            }

            @Test
            @DisplayName("Should throw a NodeProcessException")
            void shouldThrowNodeProcessExceptionWhenHasCallbacksButChoiceCallbackIsMissing() throws Exception {
                //WHEN
                assertThrows(NodeProcessException.class, () -> selectRoleNode.process(treeContext));
            }
        }

        @Nested
        @DisplayName("When ChoiceCallback is sent")
        class WithChoiceCallback {

            TextOutputCallback assertContainsWarningCallback(List<Callback> callbackList) {
                final TextOutputCallback textOutputCallback = callbackList.stream()
                        .filter(callback -> callback instanceof TextOutputCallback)
                        .map(callback -> (TextOutputCallback) callback)
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("No TextOutputCallback found in response"));
                assertEquals(TextOutputCallback.WARNING, textOutputCallback.getMessageType(), "TextOutputCallback.messageType is not WARNING");
                return textOutputCallback;
            }

            ChoiceCallback assertContainsChoiceCallback(List<Callback> callbackList) {
                return callbackList.stream()
                        .filter(callback -> callback instanceof ChoiceCallback)
                        .map(callback -> (ChoiceCallback) callback)
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("No ChoiceCallback found in response"));
            }

            void assertResponseContainsWarningAndProperChoiceCallback(Action action) throws Exception {
                assertEquals(2, action.callbacks.size());
                assertContainsWarningCallback(action.callbacks);
                final ChoiceCallback choiceCallback = assertContainsChoiceCallback(action.callbacks);
                assertArrayEquals(offeredChoices,
                        choiceCallback.getChoices(),
                        "The ChoiceCallbacks object does not contain the expected choices");
            }


            @Nested
            @DisplayName("When selectedItems size is zero")
            class NoSelectedItems {
                @BeforeEach
                void beforeEach() throws Exception {
                    treeContext = createTreeContextWithCallbacks(
                            choiceCallbackWithNoSelectedIndexes());
                }

                @Test
                @DisplayName("Should return a TextOutputCallback with a warning message and the proper ChoiceCallback")
                void shouldReturnWarningAndTheProperChoiceCallbackWhenChoiceCallbackIsSentWithoutSelectedIndexes() throws Exception {
                    //WHEN
                    final Action action = selectRoleNode.process(treeContext);
                    //ASSERTIONS
                    assertResponseContainsWarningAndProperChoiceCallback(action);
                }
            }

            @Nested
            @DisplayName("When selectedItems size > 1")
            class SelectedItemsSizeIsMoreThanOne {
                @BeforeEach
                void beforeEach() throws Exception {
                    treeContext = createTreeContextWithCallbacks(
                            choiceCallbackWithSelectedIndexes(0, 1));
                }

                @Test
                @DisplayName("Should return a TextOutputCallback with a warning message and the proper ChoiceCallback")
                void shouldReturnWarningAndTheProperChoiceCallbackWhenChoiceCallbackIsSentWithoutSelectedIndexes() throws Exception {
                    //WHEN
                    final Action action = selectRoleNode.process(treeContext);
                    //ASSERTIONS
                    assertResponseContainsWarningAndProperChoiceCallback(action);
                }
            }

            @Nested
            @DisplayName("When selectedItems size = 1 and the selectedItem index is valid")
            class SelectedItemsSizeIsOne {
                @BeforeEach
                void beforeEach() throws Exception {
                    treeContext = createTreeContextWithCallbacks(
                            choiceCallbackWithSelectedIndex(1));
                }

                @Test
                @DisplayName("Should go to next state and set selectedRole property")
                void shouldGoToNextStateAndSetSelectedRoleProperlyWhenChoiceCallbackIsSentWithoutSelectedIndexes() throws Exception {
                    //WHEN
                    final Action action = selectRoleNode.process(treeContext);
                    //ASSERTIONS
                    assertEquals("outcome", action.outcome);
                    assertEquals("second", action.sessionProperties.get("selectedRole"));
                }
            }
            @Nested
            @DisplayName("When selectedItem < 0")
            class SelectedItemIsNegative {
                @BeforeEach
                void beforeEach() throws Exception {
                    treeContext = createTreeContextWithCallbacks(
                            choiceCallbackWithSelectedIndex(-1));
                }

                @Test
                @DisplayName("Should return a TextOutputCallback with a warning message and the proper ChoiceCallback")
                void shouldReturnWarningAndTheProperChoiceCallbackWhenChoiceCallbackIsSentWithNegativeSelectedIndex() throws Exception {
                    //WHEN
                    final Action action = selectRoleNode.process(treeContext);
                    //ASSERTIONS
                    assertResponseContainsWarningAndProperChoiceCallback(action);
                }
            }
            @Nested
            @DisplayName("When selectedItem >= offeredChoices.length")
            class SelectedItemIsTwoBig {
                @BeforeEach
                void beforeEach() throws Exception {
                    treeContext = createTreeContextWithCallbacks(
                            choiceCallbackWithSelectedIndex(2));
                }

                @Test
                @DisplayName("Should return a TextOutputCallback with a warning message and the proper ChoiceCallback")
                void shouldReturnWarningAndTheProperChoiceCallbackWhenChoiceCallbackIsSentWithNegativeSelectedIndex() throws Exception {
                    //WHEN
                    final Action action = selectRoleNode.process(treeContext);
                    //ASSERTIONS
                    assertResponseContainsWarningAndProperChoiceCallback(action);
                }
            }
        }
    }
}

