package org.keycloaks.user.service.impl;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.*;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.*;
import org.keycloaks.exceptions.KeycloakSampleException;
import org.keycloaks.user.config.KeycloakConfigProperties;
import org.keycloaks.user.data.dtos.requests.CreateSubGroupRequest;
import org.keycloaks.user.data.dtos.requests.KeycloakTokenResponse;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.models.User;
import org.keycloaks.user.service.KeycloakService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakServiceImpl implements KeycloakService {

    private final Keycloak keycloak;

    private final WebClient.Builder webClient;

    private final KeycloakConfigProperties keycloakConfigProperties;

    @Value("${KEYCLOAK_REALM}")
    private String KEYCLOAK_REALM;

    @Value("${KEYCLOAK_SERVER_URL}")
    private String KEYCLOAK_SERVER_URL;

    @Value("${KEYCLOAK_CLIENT_SECRET}")
    private String KEYCLOAK_CLIENT_SECRET;

    @Value("${CLIENT_ID}")
    private String KEYCLOAK_CLIENT_ID;

    private final ModelMapper modelMapper;


    @Override
    public UserRepresentation createUser(String realm, SignUpRequest userRequestDto) {
        UsersResource usersResource = keycloak.realm(realm).users();

        List<UserRepresentation> existingUsers = usersResource.list();
        for (UserRepresentation user : existingUsers) {
            if (user.getEmail().equals(userRequestDto.getEmail().toLowerCase())) {
                throw new IllegalArgumentException("User with the same email/username already exists in realm '" + realm + "'.");
            }
        }

        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setEmail(userRequestDto.getEmail());
        userRepresentation.setUsername(userRequestDto.getEmail());
        userRepresentation.setEnabled(true);
        userRepresentation.setEmailVerified(true);
        userRepresentation.setFirstName(userRequestDto.getFirstName());
        userRepresentation.setLastName(userRequestDto.getLastName());

        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
        credentialRepresentation.setValue(userRequestDto.getPassword());
        credentialRepresentation.setTemporary(false);

        userRepresentation.setCredentials(List.of(credentialRepresentation));

        try {
            Response response = keycloak.realm(realm).users().create(userRepresentation);

            if (response.getStatusInfo().equals(Response.Status.CONFLICT)) {
                throw new RuntimeException("User with the same email or username already exists.");
            }

            List<UserRepresentation> foundUsers = keycloak.realm(realm).users().search(userRequestDto.getEmail());
            if (foundUsers.isEmpty()) {
                throw new RuntimeException("User creation failed.");
            }
            return foundUsers.get(0);

        } catch (Exception e) {
            throw new RuntimeException("An error occurred while creating the user.", e);
        }
    }

//    @Override
//    public void addUserToRealm(String realmName, SignUpRequest userRequestDto) throws KeycloakSampleException {
//
//        if (!doesRealmExist(realmName)) {
//            throw new KeycloakSampleException("Realm '" + realmName + "' does not exist.");
//        }
//
//        UsersResource usersResource = keycloak.realm(realmName).users();
//
//        List<UserRepresentation> existingUsers = usersResource.list();
//        for (UserRepresentation user : existingUsers) {
//            if (user.getEmail().equals(userRequestDto.getEmail().toLowerCase())) {
//                throw new IllegalArgumentException("User with the same email/username already exists in realm '" + realmName + "'.");
//            }
//        }
//
//        UserRepresentation representation = new UserRepresentation();
//        representation.setEmail(userRequestDto.getEmail());
//        representation.setUsername(userRequestDto.getEmail());
//        representation.setEnabled(true);
//        representation.setEmailVerified(true);
//        representation.setFirstName(userRequestDto.getFirstName());
//        representation.setLastName(userRequestDto.getLastName());
//
//
//        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
//        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
//        credentialRepresentation.setValue(userRequestDto.getPassword());
//        credentialRepresentation.setTemporary(false);
//
//        representation.setCredentials(List.of(credentialRepresentation));
//
//        Response response = keycloak.realm(realmName).users().create(representation);
//        if (response.getStatusInfo().equals(Response.Status.CONFLICT)) {
//            throw new IllegalArgumentException("User with the same email/username already exists in realm '" + realmName + "'.");
//        }
//
//        List<UserRepresentation> foundUsers = keycloak.realm(realmName).users().search(userRequestDto.getEmail());
//        if (foundUsers.isEmpty()) {
//            throw new RuntimeException("User creation failed.");
//        }
//    }


    @Override
    public UserResource getUser(String keycloakId) {
        try {
            return keycloak.realm(KEYCLOAK_REALM).users().get(keycloakId);
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    @Override
    public String getUserIdByEmail(String email) {
        try {
            UsersResource usersResource = keycloak.realm(KEYCLOAK_REALM).users();
            List<UserRepresentation> users = usersResource.search(email);
            if (users != null && !users.isEmpty()) {
                return users.get(0).getId();
            } else {
                throw new RuntimeException("User with email " + email + " not found in Keycloak");
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to get user ID from Keycloak", e);
        }
    }

    @Override
    public RoleRepresentation getRole(String roleName) {
        try {
            return keycloak.realm(KEYCLOAK_REALM).roles().get(roleName).toRepresentation();
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    @Override
    public void createPassword(String keycloakId, String password) {
        UserResource userResource = this.getUser(keycloakId);
        UserRepresentation userRepresentation = userResource.toRepresentation();

        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
        credentialRepresentation.setValue(password);
        credentialRepresentation.setTemporary(Boolean.FALSE);

        userResource.resetPassword(credentialRepresentation);
        userRepresentation.setEmailVerified(Boolean.TRUE);
        userRepresentation.setEnabled(Boolean.TRUE);
        userResource.update(userRepresentation);
    }

    @Override
    public void updateUser(User user) {
        UserResource userResource = this.getUser(user.getId());
        UserRepresentation userRepresentation = userResource.toRepresentation();

        userRepresentation.setFirstName(user.getFirstName());
        userRepresentation.setLastName(user.getLastName());
        userRepresentation.setEmail(user.getEmail());
        userResource.update(userRepresentation);
    }

    @Override
    public AccessTokenResponse login(LoginRequestDto loginRequestDto) {
        try {
            Keycloak cloak = KeycloakBuilder.builder()
                    .grantType(OAuth2Constants.PASSWORD)
                    .realm(KEYCLOAK_REALM)
                    .clientId(KEYCLOAK_CLIENT_ID)
                    .clientSecret(KEYCLOAK_CLIENT_SECRET)
                    .username(loginRequestDto.getEmail())
                    .password(loginRequestDto.getPassword())
                    .serverUrl(KEYCLOAK_SERVER_URL)
                    .build();
            TokenManager tokenManager = cloak.tokenManager();
            return tokenManager.getAccessToken();
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new RuntimeException();
        }
    }

    @Override
    public AccessTokenResponse refreshToken(String refreshToken) {
        try {
            KeycloakTokenResponse response = webClient
                    .baseUrl(String.format("%s/realms/%s/protocol/openid-connect/token", KEYCLOAK_SERVER_URL,
                            KEYCLOAK_REALM))
                    .build()
                    .post()
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData("grant_type", "refresh_token")
                            .with("refresh_token", refreshToken)
                            .with("client_id", KEYCLOAK_CLIENT_ID))
                    .retrieve()
                    .bodyToMono(KeycloakTokenResponse.class)
                    .block();

            AccessTokenResponse accessTokenResponse = new AccessTokenResponse();
            assert response != null;
            accessTokenResponse.setToken(response.getAccessToken());
            accessTokenResponse.setRefreshToken(response.getRefreshToken());

            return accessTokenResponse;
        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

    @Override
    public String addRoleToRealm(String roleName, String description) {
        RolesResource rolesResource = keycloak.realm(KEYCLOAK_REALM).roles();
        List<RoleRepresentation> existingRoles = rolesResource.list();

        if (existingRoles.stream().noneMatch(role -> role.getName().equals(roleName))) {
            RoleRepresentation roleRepresentation = new RoleRepresentation();
            roleRepresentation.setName(roleName);
            roleRepresentation.setDescription(description);

            rolesResource.create(roleRepresentation);
            return roleName;
        }
        throw new RuntimeException("Role name exists already");
    }


    @Override
    public void createClient(String clientName) {
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        clientRepresentation.setClientId(clientName);
        clientRepresentation.setDirectAccessGrantsEnabled(Boolean.TRUE);
        clientRepresentation.setPublicClient(Boolean.TRUE);

        try (Response response = keycloak.realm(KEYCLOAK_REALM).clients().create(clientRepresentation)) {
            if (response.getStatusInfo().equals(Response.Status.CONFLICT)) {
                log.info("Keycloak client already exists: {}", clientName);
            }
        } catch (Exception ignored) {
            ignored.printStackTrace();
        }
    }

    @Override
    public void createRealm(String realmName) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be null or empty.");
        }
        if (doesRealmExist(realmName)) {
            throw new KeycloakSampleException("Realm '" + realmName + "' already exists.");
        }
        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setRealm(realmName);
        realmRepresentation.setEnabled(true);

        keycloak.realms().create(realmRepresentation);
        log.info("Created Realm: " + realmName);
    }

    protected boolean doesRealmExist(String realmName) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        try {
            RealmResource realmResource = getRealmResource(realmName);
            realmResource.toRepresentation();
            return true;
        } catch (NotFoundException exception) {
            return false;
        }
    }


    @Override
    public void deleteUser(String keycloakId) {
        try {
            UserResource userResource = getUser(keycloakId);
            userResource.remove();
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete user from Keycloak", e);
        }
    }

    @Override
    public GroupRepresentation createGroup(String groupName) {
        String roleName = groupName + "_Membership_Role";
        String description = String.format("Default Role for members of %s group", groupName);
        try {
            GroupRepresentation groupRepresentation = new GroupRepresentation();
            groupRepresentation.setName(groupName);
            String createdRoleName = addRoleToRealm(roleName, description);
            groupRepresentation.setRealmRoles(Collections.singletonList(createdRoleName)); // Assign a default role if needed
            Response response = keycloak.realm(KEYCLOAK_REALM).groups().add(groupRepresentation);
            if (response.getStatusInfo().equals(Response.Status.CONFLICT)) {
                throw new RuntimeException();
            }
            assignRoleToGroup(groupName, roleName);
            return getGroupByName(groupName);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create group", e);
        }
    }

    public Response addSubgroup(CreateSubGroupRequest request) {
        try {
            GroupRepresentation parentGroup = getGroupByName(request.getParentGroupName());
            GroupRepresentation subGroup = new GroupRepresentation();
            subGroup.setName(request.getChildGroupName());
            return keycloak.realm(KEYCLOAK_REALM).groups().group(parentGroup.getId()).subGroup(subGroup);
        } catch (Exception e) {

            throw new RuntimeException("Failed to create subgroup", e);
        }
    }

    private GroupRepresentation getGroupByName(String groupName) {
        try {
            List<GroupRepresentation> groups = keycloak.realm(KEYCLOAK_REALM).groups().groups();
            for (GroupRepresentation group : groups) {
                if (group.getName().equals(groupName)) {
                    return group;
                }
            }
            throw new RuntimeException("Group not found: " + groupName);
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch group", e);
        }
    }

    @Override
    public List<RoleRepresentation> getAllRoles() {

        RealmResource realmResource = keycloak.realm(KEYCLOAK_REALM);
        RolesResource realmRolesResource = realmResource.roles();
        List<RoleRepresentation> realmRoles = realmRolesResource.list();
        List<RoleRepresentation> allRoles = new ArrayList<>(realmRoles);

        List<RoleRepresentation> clientRoles = getAllClientRoles(realmResource);
        allRoles.addAll(clientRoles);

        return allRoles;
    }

    private List<RoleRepresentation> getAllClientRoles(RealmResource realmResource) {
        List<RoleRepresentation> clientRoles = new ArrayList<>();
        List<ClientRepresentation> clients = realmResource.clients().findAll();

        for (ClientRepresentation client : clients) {
            String clientId = client.getId();
            RolesResource clientRolesResource = realmResource.clients().get(clientId).roles();

            List<RoleRepresentation> roles = clientRolesResource.list();
            clientRoles.addAll(roles);
        }

        return clientRoles;
    }

    @Override
    public void addRoleToUser(String userId, String roleName) {
        try {
            RoleRepresentation roleRepresentation = getRoleByName(roleName);
            keycloak.realm(KEYCLOAK_REALM).users().get(userId)
                    .roles().realmLevel().add(Collections.singletonList(roleRepresentation));
        } catch (Exception e) {
            throw new RuntimeException("Failed to add role to user", e);
        }
    }

    @Override
    public void addUserToGroup(String userId, String groupName) {


        try {
            UserResource userResource = keycloak.realm(KEYCLOAK_REALM).users().get(userId);
            if (userResource == null) {
                throw new RuntimeException("User not found: " + userId);
            }

            GroupRepresentation group = findGroupByName(groupName);
            if (group == null) {
                throw new RuntimeException("Group not found: " + groupName);
            }

            keycloak.realm(KEYCLOAK_REALM).users().get(userId).joinGroup(group.getId());
            if (group.getParentId() != null) {
                GroupRepresentation parentGroup = keycloak.realm(KEYCLOAK_REALM).groups().group(group.getParentId()).toRepresentation();

                List<String> parentRoles = parentGroup.getRealmRoles();
                if (parentRoles != null) {
                    for (String role : parentRoles) {
                        keycloak.realm(KEYCLOAK_REALM).users().get(userId).roles().realmLevel().remove(Collections.singletonList(getRoleByName(role)));
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to add user to group", e);
        }
    }


    private GroupRepresentation findGroupByName(String groupName) {
        try {
            List<GroupRepresentation> allGroups = getAllGroups();
            for (GroupRepresentation group : allGroups) {
                if (group.getName().equals(groupName)) {
                    return group;
                }
            }
            return null;
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch group", e);
        }
    }


    @Override
    public void assignRoleToGroup(String groupName, String roleName) {
        try {
            GroupRepresentation groupRepresentation = findGroupByName(groupName);
            RoleRepresentation roleRepresentation = getRoleByName(roleName);

            assignRoleToGroup(groupRepresentation, roleRepresentation);
        } catch (Exception e) {
            throw new RuntimeException("Failed to assign role to group", e);
        }
    }

    private void assignRoleToGroup(GroupRepresentation groupRepresentation, RoleRepresentation roleRepresentation) {
        try {
            keycloak.realm(KEYCLOAK_REALM).groups().group(groupRepresentation.getId()).roles().realmLevel().add(Collections.singletonList(roleRepresentation));
        } catch (Exception e) {
            throw new RuntimeException("Failed to assign role to group", e);
        }
    }

    private RoleRepresentation getRoleByName(String roleName) {
        try {
            List<RoleRepresentation> roles = getAllRoles();
            for (RoleRepresentation role : roles) {
                if (role.getName().equals(roleName)) {
                    return role;
                }
            }
            throw new RuntimeException("Role not found: " + roleName);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get role by name", e);
        }
    }

    @Override
    public List<GroupRepresentation> getAllGroups() {
        try {
            RealmResource realmResource = keycloak.realm(KEYCLOAK_REALM);
            List<GroupRepresentation> allGroups = realmResource.groups().groups();

            List<GroupRepresentation> allGroupsIncludingSubgroups = new ArrayList<>(allGroups);
            for (GroupRepresentation group : allGroups) {
                fetchSubgroups(realmResource, group, allGroupsIncludingSubgroups);
            }

            return allGroupsIncludingSubgroups;
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch groups", e);
        }
    }

    private void fetchSubgroups(RealmResource realmResource, GroupRepresentation group, List<GroupRepresentation> allGroupsIncludingSubgroups) {
        try {
            List<GroupRepresentation> subgroups = realmResource.groups().group(group.getId()).getSubGroups(0, allGroupsIncludingSubgroups.size(), true);

            allGroupsIncludingSubgroups.addAll(subgroups);
            for (GroupRepresentation subgroup : subgroups) {
                fetchSubgroups(realmResource, subgroup, allGroupsIncludingSubgroups);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch subgroups for group: " + group.getId(), e);
        }
    }


    @Override
    public UserRepresentation getUserDetails(String userId) {
        try {
            RealmResource realmResource = keycloak.realm(KEYCLOAK_REALM);
            UsersResource usersResource = realmResource.users();

            return usersResource.get(userId).toRepresentation();
        } catch (Exception e) {
            throw new RuntimeException("Failed to get user details", e);
        }
    }

    @Override
    public void removeRoleFromUser(String userId, String roleName) {
        try {
            UserResource userResource = keycloak.realm(KEYCLOAK_REALM).users().get(userId);
            if (userResource == null) {
                throw new RuntimeException("User not found: " + userId);
            }

            RoleRepresentation roleRepresentation = getRoleByName(roleName);
            userResource.roles().realmLevel().remove(Collections.singletonList(roleRepresentation));
        } catch (Exception e) {
            throw new RuntimeException("Failed to remove role from user", e);
        }

    }


    @Override
    public GroupRepresentation getGroup(String groupId) {
        return null;
    }

    @Override
    public void createRole(String s) {

    }

    @Override
    public RealmRepresentation getRealm(String realmName) throws KeycloakSampleException, NotFoundException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        return keycloak.realm(realmName).toRepresentation();
    }

    @Override
    public ClientRepresentation getClientInRealm(String realmName, String clientName) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        if (StringUtils.isEmpty(clientName)) {
            throw new KeycloakSampleException("Client name cannot be empty");
        }
        RealmResource realmResource = getRealmResource(realmName);
//        return realmResource.clients().get(clientName).toRepresentation();
        ClientsResource clientsResource = realmResource.clients();
        List<ClientRepresentation> resources = clientsResource.findAll();
        for (ClientRepresentation foundClient : resources) {
            if (foundClient.getClientId().equals(clientName)) {
                return foundClient;
            }
        }
        throw new KeycloakSampleException("Client not found");
    }

    private RealmResource getRealmResource(String realmName) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        return keycloak.realm(realmName);
    }

    private ClientResource getClientResource(String realmName, String clientName) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        if (StringUtils.isEmpty(clientName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        String clientId = getClientInRealm(realmName, clientName).getId();
        return keycloak.realm(realmName).clients().get(clientId);
//        return null;
    }

    @Override
    public void createClientInRealm(String realmName, String clientName) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        if (StringUtils.isEmpty(clientName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        getRealm(realmName);
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        clientRepresentation.setClientId(clientName);
        clientRepresentation.setDirectAccessGrantsEnabled(Boolean.TRUE);
        clientRepresentation.setPublicClient(Boolean.TRUE);
        Response response = keycloak.realm(realmName).clients().create(clientRepresentation);
        if (response.getStatusInfo().equals(Response.Status.CONFLICT)) {
            throw new KeycloakSampleException("Client with that name exists already");
        }
    }

    @Override
    public void deleteClientInRealm(String realmName, String clientName) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        if (StringUtils.isEmpty(clientName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        ClientResource clientResource = getClientResource(realmName, clientName);
        clientResource.remove();
    }

    @Override
    public void createRoleInRealm(String realmName, String roleName, String roleDescription) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realmName)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        if (StringUtils.isEmpty(roleName)) {
            throw new KeycloakSampleException("Role name cannot be empty");
        }
        RealmResource realmResource = getRealmResource(realmName);
        RolesResource rolesResource = realmResource.roles();
        List<RoleRepresentation> existingRoles = rolesResource.list();

        if (existingRoles.stream().noneMatch(role -> role.getName().equals(roleName))) {
            RoleRepresentation roleRepresentation = new RoleRepresentation();
            roleRepresentation.setName(roleName);
            roleRepresentation.setDescription(roleDescription);
            rolesResource.create(roleRepresentation);
        }
        throw new KeycloakSampleException("Role name exists already");
    }

    public RoleRepresentation getRoleInRealm(String realm, String roleName) throws KeycloakSampleException {
        if (StringUtils.isEmpty(realm)) {
            throw new KeycloakSampleException("Realm name cannot be empty");
        }
        if (StringUtils.isEmpty(roleName)) {
            throw new KeycloakSampleException("Role name cannot be empty");
        }
        getRealm(realm);
        return keycloak.realm(realm).roles().get(roleName).toRepresentation();
    }

    @Override
    public void deleteRealm(String realmName) throws KeycloakSampleException {

        try {
            RealmResource realmResource = getRealmResource(realmName);
            realmResource.remove();
        } catch (NotFoundException ex) {
            throw new KeycloakSampleException("Realm not found: " + realmName);
        } catch (Exception message) {
            throw new KeycloakSampleException("Error occurred while deleting realm: " + message.getMessage());
        }

//        RealmResource realmResource = getRealmResource(realmName);
//        realmResource.toRepresentation();
//        realmResource.remove();
//        RealmsResource realmsResource = keycloak.realms();
//        if (realmsResource.findAll().stream().noneMatch(r -> r.getRealm().equals(realmName))) {
//            throw new NotFoundException("Realm not found: " + realmName);
//        }
//        realmsResource.realm(realmName).remove();
    }
}
