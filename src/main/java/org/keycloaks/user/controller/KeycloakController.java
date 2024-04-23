package org.keycloaks.user.controller;

import jakarta.ws.rs.core.Response;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
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
    public ResponseEntity<String> createGroup(@RequestParam String groupName) {
        try {
            keycloakService.createGroup(groupName);
            return ResponseEntity.status(HttpStatus.CREATED).body("Group created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to create group");
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


    @PostMapping("/assign-role-to-user")
    public ResponseEntity<?> assignRoleToUser(@RequestParam String userId, @RequestParam String roleName) {
        try {
            keycloakService.addRoleToUser(userId, roleName);
            return ResponseEntity.ok("Role assigned successfully to user: " + roleName);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to assign role to user");
        }
    }

    @PostMapping("/{userId}/assign-user-to-groups/{groupName}")
    public ResponseEntity<String> addUserToGroup(@PathVariable String userId, @PathVariable String groupName) {
        try {
            keycloakService.addUserToGroup(userId, groupName);
            return ResponseEntity.ok("User successfully added to group: " + groupName);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to add user to group");
        }
    }


    @PostMapping("/assign-role-to-group/{groupName}")
    public ResponseEntity<String> assignRoleToGroup(@PathVariable String groupName, @RequestParam String roleName) {
        try {
            keycloakService.assignRoleToGroup(groupName, roleName);
            return ResponseEntity.ok("Role assigned successfully to group: " + groupName);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to assign role to group: " + groupName);
        }
    }

    @GetMapping("/allGroups")
    public ResponseEntity<List<GroupRepresentation>> getAllGroups() {
        try {
            List<GroupRepresentation> allGroups = keycloakService.getAllGroups();
            return ResponseEntity.ok(allGroups);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(List.of());
        }
    }


    @GetMapping("/user-details/{userId}")
    public ResponseEntity<UserRepresentation> getUserDetails(@PathVariable String userId) {
        UserRepresentation userDetails = keycloakService.getUserDetails(userId);
        return ResponseEntity.ok(userDetails);
    }


    @DeleteMapping("/remove-role-from-users/{userId}/roles/{roleName}")
    public ResponseEntity<String> removeRoleFromUser(@PathVariable String userId, @PathVariable String roleName) {
        try {
            keycloakService.removeRoleFromUser(userId, roleName);
            return ResponseEntity.ok("Role removed successfully from user.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to remove role from user: " + e.getMessage());
        }
    }
}
