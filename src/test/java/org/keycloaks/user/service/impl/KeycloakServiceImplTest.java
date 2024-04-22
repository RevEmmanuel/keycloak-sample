package org.keycloaks.user.service.impl;

import jakarta.ws.rs.NotFoundException;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloaks.exceptions.KeycloakSampleException;
import org.keycloaks.user.service.KeycloakService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

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
                    KeycloakServiceImpl.getRealm(keycloak, "serviceTest", "deolaaxo@gmail.com", "#Ijebuode1");
            assertNotNull(resource);
            log.info(resource.getDisplayName());
            log.info(resource.getId());
            log.info(resource.getClass().toString());
            log.info(resource.toString());
            assertEquals("serviceTest", resource.getRealm());
        } catch (KeycloakSampleException exception) {
            exception.printStackTrace();
        }
    }

    @Test
    void getRealmWithInvalidRealmName() {
        assertThrows(NotFoundException.class, () -> KeycloakServiceImpl.getRealm(keycloak, "invalidRealm", "deolaaxo@gmail.com", "#Ijebuode1"));
    }


}