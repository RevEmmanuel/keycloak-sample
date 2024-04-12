package org.keycloaks.user.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import java.io.IOException;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakInitializer {

    private final ObjectMapper objectMapper;
    private final Keycloak keycloak;
    private final String INIT_KEYCLOAK_PATH = "keycloak/keycloak-realm.json";

    private final KeycloakConfigProperties keycloakConfigProperties;

    @PostConstruct
    public void init() throws IOException {
        if (keycloak.realms().findAll().stream()
                .noneMatch(realm -> realm.getRealm().equals(keycloakConfigProperties.getRealm()))) {

            Resource resource = new ClassPathResource(INIT_KEYCLOAK_PATH);

            RealmRepresentation realmRepresentationToImport = objectMapper.readValue(resource.getInputStream(),
                    RealmRepresentation.class);

            keycloak.realms().create(realmRepresentationToImport);
        }
    }

}
