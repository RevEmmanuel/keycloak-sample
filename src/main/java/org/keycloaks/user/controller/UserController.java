package org.keycloaks.user.controller;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.dtos.requests.UpdateUserRequestDto;
import org.keycloaks.user.data.dtos.responses.TokenResponseDto;
import org.keycloaks.user.data.dtos.responses.UserDto;
import org.keycloaks.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@Slf4j
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    @Operation(summary = "Signup")
    public ResponseEntity<TokenResponseDto> signUp(
            @RequestBody @Valid SignUpRequest requestDto) {
        return ResponseEntity.ok(userService.signUp(requestDto));
    }

    @PostMapping("/login")
    @Operation(summary = "Login")
    public ResponseEntity<TokenResponseDto> login(@RequestBody @Valid LoginRequestDto requestDto) {
        return ResponseEntity.ok(userService.login(requestDto));
    }

    @GetMapping("/details")
    @Operation(summary = "Get current user details")
    public ResponseEntity<UserDto> getCurrentUser() {
        return ResponseEntity.ok(userService.getCurrentUserDetails());
    }

    @PutMapping("/update")
    @Operation(summary = "Update current user details")
    public ResponseEntity<UserDto> updateCurrentUser(@RequestBody @Valid UpdateUserRequestDto requestDto) {
        return ResponseEntity.ok(userService.updateCurrentUserDetails(requestDto));
    }

    @DeleteMapping("/delete/{userId}")
    @Operation(summary = "Delete user by ID")
    public ResponseEntity<Void> deleteUser(@PathVariable String userId) {
        userService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

}
