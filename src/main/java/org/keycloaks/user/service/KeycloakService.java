package org.keycloaks.user.service;

import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloaks.user.data.dtos.requests.CreateSubGroupRequest;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.models.User;

import java.util.List;


public interface KeycloakService {

    UserRepresentation createUser(SignUpRequest userRequestDto);

    AccessTokenResponse login(LoginRequestDto loginRequestDto);

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

    void createPassword(String keycloakId, String password);

    AccessTokenResponse refreshToken(String refreshToken);


    void createClient(String clientName);

    void createRealm();

    GroupRepresentation getGroup(String groupId);

    void createRole(String s);
}
