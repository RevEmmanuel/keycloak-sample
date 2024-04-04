package org.keycloaks.user.service.impl;

import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.*;
import org.keycloaks.user.data.dtos.requests.CreateSubGroupRequest;
import org.keycloaks.user.data.dtos.requests.KeycloakTokenResponse;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.models.User;
import org.keycloaks.user.service.KeycloakService;
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

    @Value("${example.keycloak.realm}")
    private String KEYCLOAK_REALM;

    @Value("${example.keycloak.server-url}")
    private String KEYCLOAK_SERVER_URL;

    @Value("${example.keycloak.master-client-id}")
    private String KEYCLOAK_CLIENT_ID;

    @Override
    public UserRepresentation createUser(SignUpRequest userRequestDto) {
        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setEmail(userRequestDto.getEmail());
        userRepresentation.setUsername(userRequestDto.getEmail());
        userRepresentation.setEnabled(Boolean.TRUE);
        userRepresentation.setEmailVerified(Boolean.TRUE);
        userRepresentation.setFirstName(userRequestDto.getFirstName());
        userRepresentation.setLastName(userRequestDto.getLastName());

        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
        credentialRepresentation.setValue(userRequestDto.getPassword());
        credentialRepresentation.setTemporary(Boolean.FALSE);

        userRepresentation.setCredentials(List.of(credentialRepresentation));

        try {
            Response response = keycloak.realm(KEYCLOAK_REALM).users().create(userRepresentation);

            if (response.getStatusInfo().equals(Response.Status.CONFLICT)) {
                throw new RuntimeException();
            }
            return keycloak.realm(KEYCLOAK_REALM).users().search(userRequestDto.getEmail()).get(0);

        } catch (Exception e) {
            throw new RuntimeException();
        }
    }

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
            TokenManager tokenManager = keycloak.tokenManager();
            return tokenManager.getAccessToken();
        } catch (Exception e) {
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
            // not sure
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
        }
    }

    @Override
    public void createRealm() {
        if (keycloak.realms().findAll().stream().noneMatch(realm -> realm.getRealm().equals(KEYCLOAK_REALM))) {
            RealmRepresentation realmRepresentation = new RealmRepresentation();
            realmRepresentation.setRealm(KEYCLOAK_REALM);

            keycloak.realms().create(realmRepresentation);
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
    public Response createGroup(String groupName) {
        String roleName = groupName + "_Membership_Role";
        String description = String.format("Default Role for members of %s group", groupName);
        try {
            GroupRepresentation groupRepresentation = new GroupRepresentation();
            groupRepresentation.setName(groupName);
            String createdRoleName = addRoleToRealm(roleName, description);
            groupRepresentation.setRealmRoles(Collections.singletonList(createdRoleName)); // Assign a default role if needed
            Response response = keycloak.realm(KEYCLOAK_REALM).groups().add(groupRepresentation);
            assignRoleToGroup(groupName, roleName);
            return response;
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
    public GroupRepresentation getGroup(String groupId) {
        return null;
    }
}
