package org.keycloaks.user.controller;

import jakarta.ws.rs.core.Response;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloaks.user.data.dtos.requests.CreateSubGroupRequest;
import org.keycloaks.user.service.KeycloakService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
public class KeycloakController {

    private final KeycloakService keycloakService;

    public KeycloakController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }


    @PostMapping("/add-role")
    public ResponseEntity<?> addRoleToRealm(@RequestParam String roleName, @RequestParam String description) {
        try {
            keycloakService.addRoleToRealm(roleName, description);
            return ResponseEntity.ok("Role added successfully to the realm.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to add role to the realm: " + e.getMessage());
        }
    }

    @PostMapping("/groups")
    public ResponseEntity<Object> createGroup(@RequestParam String groupName) {
        Response response = keycloakService.createGroup(groupName);
        if (response.getStatusInfo().equals(Response.Status.CREATED)) {
            return ResponseEntity.status(HttpStatus.CREATED).body("Group created successfully");
        } else {
            return ResponseEntity.status(response.getStatus()).body("Failed to create group");
        }
    }

    @PostMapping("/subgroup")
    public ResponseEntity<String> createSubGroup(@RequestBody CreateSubGroupRequest request) {
        Response response = keycloakService.addSubgroup(request);
        if (response.getStatus() == 201) {
            return ResponseEntity.ok("Subgroup created successfully");
        } else {
            return ResponseEntity.status(response.getStatus()).body("Failed to create subgroup");
        }
    }


    @GetMapping("/all-roles")
    public ResponseEntity<?> getAllRoles() {
        try {
            List<RoleRepresentation> allRoles = keycloakService.getAllRoles();
            return ResponseEntity.ok(allRoles);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred while retrieving roles: " + e.getMessage());
        }
    }


    @PostMapping("/assign/{groupName}")
    public ResponseEntity<String> assignRoleToGroup(@PathVariable String groupName, @RequestParam String roleName) {
        try {
            keycloakService.assignRoleToGroup(groupName, roleName);
            return ResponseEntity.ok("Role assigned successfully to group: " + groupName);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to assign role to group: " + groupName);
        }
    }
}
