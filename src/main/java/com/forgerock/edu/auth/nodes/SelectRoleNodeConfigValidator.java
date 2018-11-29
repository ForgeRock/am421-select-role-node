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

public class SelectRoleNodeConfigValidator implements ServiceConfigValidator {

    private AmIdentityHelper identityHelper;

    @Inject
    public SelectRoleNodeConfigValidator(AmIdentityHelper identityHelper) {
        this.identityHelper = identityHelper;
    }

    @Override
    public void validate(Realm realm, List<String> list, Map<String, Set<String>> map) throws ServiceConfigException, ServiceErrorException {
        final Set<String> allGroupNamesInRealm;
        try {
            allGroupNamesInRealm = identityHelper.findAllGroupNamesInRealm(realm.asPath());
        } catch (SSOException | IdRepoException ex) {
            throw new ServiceErrorException("Error during finding all groups in realm", ex);
        }
        validateDefaultRole(realm, map, allGroupNamesInRealm);
        validateCandidateRoles(realm, map, allGroupNamesInRealm);


    }

    private void validateDefaultRole(Realm realm, Map<String, Set<String>> map, Set<String> allGroupNamesInRealm) throws ServiceConfigException {
        final Set<String> defaultRole = map.get("defaultRole");

        final Optional<String> invalidRoleName = defaultRole.stream()
                .filter(candidateRole -> !allGroupNamesInRealm.contains(candidateRole))
                .findAny();

        if (invalidRoleName.isPresent()) {
            throw new ServiceConfigException("defaultRole contains non-existing group name" +
                    "in the current realm (" + realm + "): " + invalidRoleName.get());
        }
    }

    private void validateCandidateRoles(Realm realm, Map<String, Set<String>> map, Set<String> allGroupNamesInRealm) throws ServiceConfigException {
        final Set<String> candidateRoles = map.get("candidateRoles");
        final List<String> invalidRoleNames = candidateRoles.stream()
                .filter(candidateRole -> !allGroupNamesInRealm.contains(candidateRole))
                .collect(Collectors.toList());
        if (!invalidRoleNames.isEmpty()) {
            final String invalidRoleNamesString = invalidRoleNames.stream().collect(Collectors.joining());
            throw new ServiceConfigException("candidateRoles contains non-existing group name(s) " +
                    "in the current realm (" + realm + "): " + invalidRoleNamesString);
        }
    }
}
