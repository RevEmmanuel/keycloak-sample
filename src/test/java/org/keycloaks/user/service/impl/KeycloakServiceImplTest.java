package org.keycloaks.user.service.impl;

import jakarta.ws.rs.NotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloaks.exceptions.KeycloakSampleException;
import org.keycloaks.user.service.KeycloakService;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import static org.junit.jupiter.api.Assertions.*;


@SpringBootTest
@ActiveProfiles("local")
@Slf4j
class KeycloakServiceImplTest {

    @Autowired
    private KeycloakService keycloakService;

    @Value("${KEYCLOAK_REALM}")
    private String KEYCLOAK_REALM;

    @Value("${EXTRA_REALM}")
    private String EXTRA_REALM;

    private String clientName;

    private String realmName;

    private String email;

    private String roleName;

    @BeforeEach
    void createDifferentNames() {
        clientName = "testClient" + System.currentTimeMillis();
        realmName = "testRealm" + System.currentTimeMillis();
        email = String.format("%s@gmail.com", "testUser" + System.currentTimeMillis()).toLowerCase();
        roleName = "testRole " + System.currentTimeMillis();
    }

    @Test
    void getRealmWithNullRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getRealm(null));
    }


    @Test
    void getRealmWithEmptyRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getRealm(""));
    }

    @Test
    void getRealmWithValidRealmName() {
        try {
            RealmRepresentation resource = keycloakService.getRealm(KEYCLOAK_REALM);
            assertNotNull(resource);
            assertEquals(KEYCLOAK_REALM, resource.getRealm());
        } catch (KeycloakSampleException exception) {
            log.error("Error occurred", exception);
        }
    }

    @Test
    void getRealmWithInvalidRealmName() {
        assertThrows(NotFoundException.class, () -> keycloakService.getRealm("invalidRealm"));
    }

    @Test
    void createClientWithNullRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createClientInRealm(null, null));
    }

    @Test
    void createClientWithEmptyRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createClientInRealm("", null));
    }

    @Test
    void createClientWithNullClientName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createClientInRealm("realm", null));
    }

    @Test
    void createClientWithEmptyClientName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createClientInRealm("realm", ""));
    }

    @Test
    void getClientWithNullRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getClientInRealm(null, null));
    }

    @Test
    void getClientWithEmptyRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getClientInRealm("", null));
    }

    @Test
    void getClientWithNullClientName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getClientInRealm("realm", null));
    }

    @Test
    void getClientWithEmptyClientName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getClientInRealm("realm", ""));
    }

    @Test
    void getClientThatDoesNotExist() {
        assertThrows(KeycloakSampleException.class,
                () -> keycloakService.getClientInRealm(KEYCLOAK_REALM, "invalidClient"),
                "Client not found");
    }

    @Test
    void createClientInRealm() {
        try {
            keycloakService.createClientInRealm(KEYCLOAK_REALM, clientName);
            ClientRepresentation foundClient = keycloakService.getClientInRealm(KEYCLOAK_REALM, clientName);
            assertNotNull(foundClient);
            assertEquals(clientName, foundClient.getClientId());
        } catch (KeycloakSampleException exception) {
            log.error("Error occurred", exception);
        }
    }

    @Test
    void cannotCreateClientWithSameNameInRealm() {
        try {
            keycloakService.createClientInRealm(KEYCLOAK_REALM, clientName);
        } catch (KeycloakSampleException exception) {
            log.error("Error occurred", exception);
        }
        assertThrows(KeycloakSampleException.class,
                () -> keycloakService.createClientInRealm(KEYCLOAK_REALM, clientName),
                "Client with that name exists already");
    }

    @Test
    void cannotCreateClientAndFindItInAnotherInRealm() {
        try {
            keycloakService.createClientInRealm(KEYCLOAK_REALM, clientName);
        } catch (KeycloakSampleException exception) {
            log.error("Error occurred", exception);
        }
        assertThrows(KeycloakSampleException.class,
                () -> keycloakService.getClientInRealm(EXTRA_REALM, clientName),
                "Client not found");
    }

    @Test
    void deleteClientInRealm() {
        try {
            keycloakService.createClientInRealm(KEYCLOAK_REALM, clientName);
            ClientRepresentation foundClient = keycloakService.getClientInRealm(KEYCLOAK_REALM, clientName);
            assertNotNull(foundClient);
            assertEquals(clientName, foundClient.getClientId());
        } catch (KeycloakSampleException exception) {
            log.error("Error occurred", exception);
        }
        assertDoesNotThrow(() -> keycloakService.deleteClientInRealm(KEYCLOAK_REALM, clientName));
        assertThrows(KeycloakSampleException.class,
                () -> keycloakService.getClientInRealm(KEYCLOAK_REALM, clientName),
                "Client not found");
    }

    @Test
    void createRealmWhenRealmNameDoesNotExist() throws KeycloakSampleException {
        keycloakService.createRealm(realmName);
        RealmRepresentation createdRealm = keycloakService.getRealm(realmName);
        assertNotNull(createdRealm);
        assertEquals(realmName, createdRealm.getRealm());
    }


    @Test
    void createRealmWhenRealmAlreadyExist() throws KeycloakSampleException {
        keycloakService.createRealm(realmName);
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createRealm(realmName));
    }

    @Test
    void createUserSuccessfully() {
        SignUpRequest userRequest = new SignUpRequest("Joel", "Mack", email, "password123");
        UserRepresentation createdUser = keycloakService.createUser(KEYCLOAK_REALM, userRequest);
        assertNotNull(createdUser);
        assertEquals(email, createdUser.getEmail());
        assertEquals("Joel", createdUser.getFirstName());
        assertEquals("Mack", createdUser.getLastName());
    }

    @Test
    void cannotCreateRoleWithNullRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createRoleInRealm(null, null, null));
    }


    @Test
    void cannotCreateRoleWithEmptyRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createRoleInRealm("", null, null));
    }

    @Test
    void cannotCreateRoleWithNullRoleName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createRoleInRealm("realm", null, null));
    }


    @Test
    void cannotCreateRoleWithEmptyRoleName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.createRoleInRealm("realm", "", "any description"));
    }

    @Test
    void cannotGetRoleWithNullRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getRoleInRealm(null, null));
    }


    @Test
    void cannotGetRoleWithEmptyRealmName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getRoleInRealm("", null));
    }

    @Test
    void cannotGetRoleWithNullRoleName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getRoleInRealm("realm", null));
    }


    @Test
    void cannotGetRoleWithEmptyRoleName() {
        assertThrows(KeycloakSampleException.class, () -> keycloakService.getRoleInRealm("realm", ""));
    }

    @Test
    void cannotGetRoleWithInvalidRoleName() {
        assertThrows(NotFoundException.class, () -> keycloakService.getRoleInRealm("realm", "invalidRole"));
    }

    @Test
    void createRoleInRealm() {
        try {
            keycloakService.createRoleInRealm(KEYCLOAK_REALM, roleName, "any description");
            RoleRepresentation foundRole = keycloakService.getRoleInRealm(KEYCLOAK_REALM, roleName);
            assertNotNull(foundRole);
            assertEquals(roleName, foundRole.getName());
            assertEquals("any description", foundRole.getDescription());
        } catch (KeycloakSampleException e) {
            log.error("Error occurred", e);
        }
    }

    @Test
    void cannotCreateRoleWithSameNameInRealm() {
        try {
            keycloakService.createRoleInRealm(KEYCLOAK_REALM, roleName, "any description");
        } catch (KeycloakSampleException exception) {
            log.error("Error occurred", exception);
        }
        assertThrows(KeycloakSampleException.class,
                () -> keycloakService.createRoleInRealm(KEYCLOAK_REALM, roleName, "any description"),
                "Role name exists already");
    }



    /*
    @Test
    void deleteRealmWithValidRealmName() throws KeycloakSampleException {
        keycloakService.createRealm(realmName);
        keycloakService.deleteRealm(realmName);
        assertThrows(NotFoundException.class, () -> keycloakService.getRealm(realmName));
    }

    @Test
    void addAUserToRealm() throws KeycloakSampleException {
        SignUpRequest userRequest = new SignUpRequest("Jane", "Doe", email, "password123");
        keycloakService.createRealm(realmName);
        RealmRepresentation createdRealm = keycloakService.getRealm(realmName);
        assertNotNull(createdRealm);
        assertEquals(realmName, createdRealm.getRealm());

        assertDoesNotThrow(() -> keycloakService.addUserToRealm(createdRealm.getRealm(), userRequest));
        List<UserRepresentation> users = keycloak.realm(createdRealm.getRealm()).users().search(email);
        assertFalse(users.isEmpty(), "User should be created in the realm");
        assertEquals("Jane", users.get(0).getFirstName());
    }
     */

}

