package com.forgerock.edu.auth.nodes;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.*;
import com.sun.identity.security.AdminTokenAction;

import java.security.AccessController;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AmIdentityHelper {

    /**
     * Retrieves all the assigned groups of the given userIdentity object.
     *
     * @param userIdentity AMIdentity instance representing the user, whose memberships should be returned.
     * @return Set of AMIdentity instances representing the groups that the given user is member of.
     * @throws IllegalArgumentException if the passed AMIdentity instance is {@code null}, it is not a USER identity, it does not exist or it is inactive.
     * @throws IdRepoException If an error occurs in the IdRepo during querying the memberships of the given identity
     * @throws SSOException If the user's SSO token is invalid.
     */
    // TODO Ch2L2Ex2 Task2: Observe the usage the AMIdentity class
    public Set<AMIdentity> findAllAssignedGroupsOfUser(AMIdentity userIdentity) throws IllegalArgumentException, IdRepoException, SSOException {
        if (userIdentity == null
                || userIdentity.getType() != IdType.USER
                || !userIdentity.isExists()
                || !userIdentity.isActive()) {
            throw new IllegalArgumentException("User either does not exist or is not active.");
        } else {
            return userIdentity.getMemberships(IdType.GROUP);
        }
    }


    public Set<String> findAllAssignedGroupNamesOfUser(AMIdentity userIdentity) throws IllegalArgumentException, IdRepoException, SSOException {
        return findAllAssignedGroupsOfUser(userIdentity)
                .stream()
                .map(AMIdentity::getName)
                .collect(Collectors.toSet());
    }


    /**
     * Retrieves all groups in the given realm.
     *
     * @throws IdRepoException If there are repository related error conditions
     * @throws SSOException If the admin's single sign on token is invalid.
     */
    public Set<AMIdentity> findAllGroupsInRealm(String realm) throws IdRepoException, SSOException {
        // TODO Ch2L2Ex2 Task2: Observe the way to obtain an admin SSO Token for privileged operations
        SSOToken adminToken = (SSOToken) AccessController.doPrivileged(AdminTokenAction.getInstance());

        // TODO Ch2L2Ex2 Task2: Observe the creation of AMIdentityRepository instance
        // TODO Ch2L2Ex2 Task2:   the first parameter specifies the ream
        // TODO Ch2L2Ex2 Task2:   the second parameter determines the performer's identity
        AMIdentityRepository identityRepository
                = new AMIdentityRepository(realm, adminToken);

        IdSearchControl searchControl = new IdSearchControl();
        // TODO Ch2L2Ex2 Task2: Observe the way to query for all the groups within a specified realm
        IdSearchResults searchResult = identityRepository.searchIdentities(
                IdType.GROUP, "*", searchControl);
        return searchResult.getSearchResults();
    }

    /**
     * Retrieves all group names of the given realm
     * @param realm
     * @return
     * @throws IdRepoException
     * @throws SSOException
     */
    public Set<String> findAllGroupNamesInRealm(String realm) throws IdRepoException, SSOException {
        return findAllGroupsInRealm(realm)
                .stream()
                .map(group -> group.getName())
                .collect(Collectors.toSet());
    }

    /**
     * Gets the AMIdentity of a user with username equal to uName that exists in realm
     *
     * @param username username of the user to get.
     * @param realm realm the user belongs to.
     * @return The AMIdentity of user with username equal to uName.
     */
    public AMIdentity getIdentity(String username, String realm) {
        return IdUtils.getIdentity(username, realm);
    }


}
