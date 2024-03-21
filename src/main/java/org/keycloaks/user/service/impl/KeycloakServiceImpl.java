package org.keycloaks.user.service.impl;

import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.*;
import org.keycloaks.user.data.dtos.requests.CreateUserRepresentationRequestDto;
import org.keycloaks.user.data.dtos.requests.KeycloakTokenResponse;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.enums.ExampleRoles;
import org.keycloaks.user.data.models.User;
import org.keycloaks.user.service.KeycloakService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakServiceImpl implements KeycloakService {

    private final Keycloak keycloak;

    private final WebClient.Builder webClient;

    @Value("${centric.keycloak.realm}")
    private String KEYCLOAK_REALM;

    @Value("${centric.keycloak.server-url}")
    private String KEYCLOAK_SERVER_URL;

    @Value("${centric.keycloak.master-client-id}")
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
                // user already exists
                throw new RuntimeException();
            }

            return keycloak.realm(KEYCLOAK_REALM).users().search(userRequestDto.getEmail()).get(0);
        } catch (Exception e) {
            // user already exists??
            throw new RuntimeException();
        }
    }

    @Override
    public UserResource getUser(String keycloakId) {
        try {
            return keycloak.realm(KEYCLOAK_REALM).users().get(keycloakId);
        } catch (Exception e) {
            // user not found
            throw new RuntimeException();
        }
    }

    @Override
    public RoleRepresentation getRole(String roleName) {
        try {
            return keycloak.realm(KEYCLOAK_REALM).roles().get(roleName).toRepresentation();
        } catch (Exception e) {
            // cannot find role?
            throw new RuntimeException();
        }
    }

    @Override
    public void assignRole(String keycloakId, String role) {
        UserResource userResource = this.getUser(keycloakId);
        RoleRepresentation roleRepresentation = this.getRole(role);

        userResource.roles().realmLevel().add(List.of(roleRepresentation));
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

        userRepresentation.setFirstName(user.getName());
        userRepresentation.setEmail(user.getEmail());
        userResource.update(userRepresentation);
    }

    @Override
    public AccessTokenResponse login(LoginRequestDto loginRequestDto) {
        try {
            Keycloak keycloak = KeycloakBuilder.builder()
                    .realm(KEYCLOAK_REALM)
                    .serverUrl(KEYCLOAK_SERVER_URL)
                    .username(loginRequestDto.getEmail())
                    .password(loginRequestDto.getPassword())
                    .clientId(KEYCLOAK_CLIENT_ID)
                    .build();

            TokenManager tokenManager = keycloak.tokenManager();
            return tokenManager.getAccessToken();
        } catch (Exception e) {
            // invalid login details
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
    public void addRolesToRealm() {
        RolesResource rolesResource = keycloak.realm(KEYCLOAK_REALM).roles();
        List<RoleRepresentation> existingRoles = rolesResource.list();
        List<String> allRoles = Arrays.stream(ExampleRoles.values()).map(Enum::name).toList();
        List<String> roles = allRoles.stream()
                .filter(role -> !existingRoles
                        .stream()
                        .map(RoleRepresentation::getName)
                        .toList()
                        .contains(role))
                .toList();

        if (!roles.isEmpty()) {
            for (String role : roles) {
                RoleRepresentation roleRepresentation = new RoleRepresentation();
                roleRepresentation.setName(role);
                rolesResource.create(roleRepresentation);
            }
        }
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
}
