package com.forgerock.edu.auth.nodes;

import com.google.inject.Inject;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.IdRepoException;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.ServiceConfigException;
import org.forgerock.openam.sm.ServiceConfigValidator;
import org.forgerock.openam.sm.ServiceErrorException;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validator class for the SelectRoleNode configuration.
 * <p>The {@link SelectRoleNode.Config} interface has two properties:
 *  {@link SelectRoleNode.Config#defaultRole()} and
 * {@link SelectRoleNode.Config#candidateRoles()}. The goal of this
 * class is to reject invalid configurations by throwing
 * a {@link ServiceConfigException}.
 * </p>
 * <p>The applied validation rules are:</p>
 * <ul>
 *     <li>
 *         {@code candidateRoles}:
 *         <p>All candidate roles should be existing group names in the given realm.</p>
 *     </li>
 *     <li>
 *         {@code defaultRole}:
 *         <p>Should be one of the candidateRoles.</p>
 *     </li>
 * </ul>
 */
public class SelectRoleNodeConfigValidator implements ServiceConfigValidator {

    private AmIdentityHelper identityHelper;

    @Inject
    public SelectRoleNodeConfigValidator(AmIdentityHelper identityHelper) {
        this.identityHelper = identityHelper;
    }

    @Override
    public void validate(Realm realm, List<String> list, Map<String, Set<String>> config) throws ServiceConfigException, ServiceErrorException {
        final Set<String> allGroupNamesInRealm;
        try {
            allGroupNamesInRealm = identityHelper.findAllGroupNamesInRealm(realm.asPath());
        } catch (SSOException | IdRepoException ex) {
            throw new ServiceErrorException("Error during finding all groups in realm", ex);
        }
        final Set<String> candidateRoles = config.get("candidateRoles");
        validateCandidateRoles(realm, candidateRoles, allGroupNamesInRealm);

        final String defaultRole = config.get("defaultRole").iterator().next();
        validateDefaultRole(defaultRole, candidateRoles);

    }

    private void validateDefaultRole(String defaultRole, Set<String> candidateRoles) throws ServiceConfigException {
        if (!candidateRoles.contains(defaultRole)) {
            throw new ServiceConfigException("defaultRole is not one of the candidateRoles");
        }
    }

    private void validateCandidateRoles(Realm realm, Set<String> candidateRoles, Set<String> allGroupNamesInRealm) throws ServiceConfigException {
        final String invalidRoleNames = candidateRoles.stream()
                .filter(candidateRole -> !allGroupNamesInRealm.contains(candidateRole))
                .collect(Collectors.joining());

        if (!invalidRoleNames.isEmpty()) {
            throw new ServiceConfigException("candidateRoles contains non-existing group name(s) " +
                    "in realm " + realm + " : " + invalidRoleNames);
        }
    }
}
