package org.keycloaks.user.service;

import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.models.User;

public interface KeycloakService {

    UserRepresentation createUser(SignUpRequest userRequestDto);

    UserResource getUser(String keycloakId);

    RoleRepresentation getRole(String roleName);

    void assignRole(String keycloakId, String role);

    void createPassword(String keycloakId, String password);

    void updateUser(User user);

    AccessTokenResponse login(LoginRequestDto loginRequestDto);

    AccessTokenResponse refreshToken(String refreshToken);

    void addRolesToRealm();

    void createClient(String clientName);

    void createRealm();

}
