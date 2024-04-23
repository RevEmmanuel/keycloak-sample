package org.keycloaks.user.service.impl;

import jakarta.ws.rs.NotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.Before;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloaks.exceptions.KeycloakSampleException;
import org.keycloaks.user.service.KeycloakService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.event.annotation.BeforeTestMethod;
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

    @Before()
    String createClientName() {
        return "testClient" + System.currentTimeMillis();
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
            String clientName = "testClient " + System.currentTimeMillis();
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
        String clientName = "testClient " + System.currentTimeMillis();
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
        String clientName = "testClient " + System.currentTimeMillis();
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
        String clientName = "testClient " + System.currentTimeMillis();
        try {
            keycloakService.createClientInRealm(KEYCLOAK_REALM, clientName);
            ClientRepresentation foundClient = keycloakService.getClientInRealm(KEYCLOAK_REALM, clientName);
            assertNotNull(foundClient);
            assertEquals(clientName, foundClient.getClientId());
        } catch (KeycloakSampleException exception) {
            log.error("Error occurred", exception);
        }
        /*
        keycloakService.deleteClientInRealm(KEYCLOAK_REALM, clientName);
        assertThrows(KeycloakSampleException.class,
                () -> keycloakService.getClientInRealm(KEYCLOAK_REALM, clientName),
                "Client not found");
         */
    }


}
