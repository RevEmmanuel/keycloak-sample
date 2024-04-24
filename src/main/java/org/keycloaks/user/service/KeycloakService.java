package org.keycloaks.user.service;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.*;
import org.keycloaks.exceptions.KeycloakSampleException;
import org.keycloaks.user.data.dtos.requests.CreateSubGroupRequest;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.models.User;

import java.util.List;


public interface KeycloakService {

    UserRepresentation createUser(String realm, SignUpRequest userRequestDto);

    AccessTokenResponse login(LoginRequestDto loginRequestDto);

//    void addUserToRealm(String realmName, SignUpRequest userRequestDto) throws KeycloakSampleException;

    UserResource getUser(String keycloakId);

    String getUserIdByEmail(String email);

    RoleRepresentation getRole(String roleName);

    String addRoleToRealm(String roleName, String description);

    void updateUser(User user);

    void deleteUser(String keycloakId);

    GroupRepresentation createGroup(String groupName);

    Response addSubgroup(CreateSubGroupRequest request);

    List<RoleRepresentation> getAllRoles();

    void addRoleToUser(String userId, String roleName);

    void addUserToGroup(String userId, String groupName);

    void assignRoleToGroup(String groupName, String roleName);

    List<GroupRepresentation> getAllGroups();

    UserRepresentation getUserDetails(String userId);

    void removeRoleFromUser(String userId, String roleName);

    void createPassword(String keycloakId, String password);

    AccessTokenResponse refreshToken(String refreshToken);


    void createClient(String clientName);

    void createRealm(String realmName) throws KeycloakSampleException;

    GroupRepresentation getGroup(String groupId);

    void createRole(String s);

    void createClientInRealm(String realmName, String clientName) throws KeycloakSampleException;

    RealmRepresentation getRealm(String realmName) throws KeycloakSampleException, NotFoundException;

    ClientRepresentation getClientInRealm(String realmName, String clientName) throws KeycloakSampleException;

    void deleteClientInRealm(String realmName, String clientName) throws KeycloakSampleException;

    void deleteRealm(String realmName) throws KeycloakSampleException;

    void createRoleInRealm(String realmName, String roleName, String roleDescription) throws KeycloakSampleException;

    RoleRepresentation getRoleInRealm(String realm, String roleName) throws KeycloakSampleException;
}
