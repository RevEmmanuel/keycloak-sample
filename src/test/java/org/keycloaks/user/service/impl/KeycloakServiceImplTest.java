package org.keycloaks.user.service.impl;

import jakarta.ws.rs.NotFoundException;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloaks.exceptions.KeycloakSampleException;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.keycloak.models.utils.ModelToRepresentation.toRepresentation;

@SpringBootTest
@ActiveProfiles("local")
class KeycloakServiceImplTest {

    private static final Logger log = LoggerFactory.getLogger(KeycloakServiceImplTest.class);

    @Autowired
    private Keycloak keycloak;

    @Autowired
    private KeycloakServiceImpl keycloakServiceImpl;

    @Test
    void getRealmWithNullRealmName() {
        assertThrows(KeycloakSampleException.class, () -> KeycloakServiceImpl.getRealm(keycloak, null, null, null));
    }

    @Test
    void getRealmWithEmptyRealmName() {
        assertThrows(KeycloakSampleException.class, () -> KeycloakServiceImpl.getRealm(keycloak, "", null, null));
    }

    @Test
    void getRealmWithNullUsername() {
        assertThrows(KeycloakSampleException.class,
                () -> KeycloakServiceImpl.getRealm(keycloak, "serviceTest", null, null));
    }

    @Test
    void getRealmWithEmptyUsername() {
        assertThrows(KeycloakSampleException.class,
                () -> KeycloakServiceImpl.getRealm(keycloak, "serviceTest", "", null));
    }

    @Test
    void getRealmWithValidRealmName() {
        try {
            RealmRepresentation resource =
                    KeycloakServiceImpl.getRealm(keycloak, "myrealm", "", "");
            assertNotNull(resource);
            log.info(resource.getDisplayName());
            log.info(resource.getId());
            log.info(resource.getClass().toString());
            log.info(resource.toString());
            assertEquals("myrealm", resource.getRealm());
        } catch (KeycloakSampleException exception) {
            exception.printStackTrace();
        }
    }

    @Test
    void getRealmWithInvalidRealmName() {
        assertThrows(NotFoundException.class, () -> KeycloakServiceImpl.getRealm(keycloak, "invalidRealm", "deolaaxo@gmail.com", "#Ijebuode1"));
    }

    @Test
    void createRealmWhenRealmNameDoesNotExist() throws KeycloakSampleException {
        String realmName = "MerchantRealmTwo";
        keycloakServiceImpl.createRealm(realmName);
        RealmRepresentation createdRealm = keycloak.realms().realm(realmName).toRepresentation();
        assertNotNull(createdRealm);
        assertEquals(realmName, createdRealm.getRealm());
    }

    @Test
    void createRealmWhenRealmAlreadyExist() {
        String realmName = "MerchantRealmTwo";
        assertThrows(KeycloakSampleException.class, () -> {
            keycloakServiceImpl.createRealm(realmName);
        });
    }


    @Test
    void deleteRealmWithValidRealmName() throws KeycloakSampleException {
        String realmName = "MerchantRealm";
        keycloakServiceImpl.createRealm(realmName);
//        RealmRepresentation createdRealm = keycloak.realms().realm(realmName).toRepresentation();
//        assertNotNull(createdRealm);
//        assertEquals(realmName, createdRealm.getRealm());
        keycloakServiceImpl.deleteRealm(realmName);
        assertThrows(NotFoundException.class, () -> KeycloakServiceImpl.getRealm(keycloak, realmName, "Okanga", ""));
    }

    @Test
    void createUserSuccessfully() {
        String realmName = "KarraboBackofficeRealm";
        SignUpRequest userRequest = new SignUpRequest("okanga.doe@example.com", "Joel", "Mack", "password123");

        UserRepresentation createdUser = keycloakServiceImpl.createUser(userRequest);

        assertNotNull(createdUser);
        assertEquals("okanga.doe@example.com", createdUser.getEmail());
        assertEquals("Jane", createdUser.getFirstName());
        assertEquals("Doe", createdUser.getLastName());
    }

    @Test
    void addUserToExistingRealm() {
        String realmName = "KarraboBackofficeRealm";
        SignUpRequest userRequest = new SignUpRequest("jane.doe@example.com", "Jane", "Doe", "password123");

        assertDoesNotThrow(() -> {
            keycloakServiceImpl.addUserToRealm(realmName, userRequest);
        });
        List<UserRepresentation> users = keycloak.realm(realmName).users().search("jane.doe@example.com");
        assertFalse(users.isEmpty(), "User should be created in the realm");
        assertEquals("Jane", users.get(0).getFirstName());
    }
}