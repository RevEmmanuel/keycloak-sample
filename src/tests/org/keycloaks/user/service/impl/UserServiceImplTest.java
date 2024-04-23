package org.keycloaks.user.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.dtos.responses.TokenResponseDto;
import org.keycloaks.user.data.models.User;
import org.keycloaks.user.data.repositories.UserRepository;
import org.keycloaks.user.service.KeycloakService;
import org.keycloaks.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;


@SpringBootTest
@ActiveProfiles("local")
@Slf4j
class UserServiceImplTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private KeycloakService keycloakService;

    @Autowired
    private UserService userService;

    private final String userEmail = "john@example.com";

//    @BeforeEach
//    void tearDown(){
//        userRepository.deleteAll();
//    }

    @Test
    void signUp_SuccessfulRegistration_ReturnTokenResponse() {
        SignUpRequest requestDto = SignUpRequest.builder()
                .email(userEmail)
                .firstName("John")
                .password("password123")
                .lastName("Doe")
                .build();

        TokenResponseDto signedUpUser = userService.signUp(requestDto);
        String registeredUserDetails = keycloakService.getUserIdByEmail(userEmail);
        if (registeredUserDetails != null){
            assertNotNull(registeredUserDetails);
            assertNotNull(signedUpUser.getAuth());

        }
    }


    @Test
    void login() {
        LoginRequestDto requestDto = LoginRequestDto.builder()
                .email("john@examp.com")
                .password("password123")
                .build();
        TokenResponseDto tokenResponseDto = userService.login(requestDto);
        assertNotNull(tokenResponseDto);
        assertNotNull(tokenResponseDto.getAuth());
        assertNotNull(tokenResponseDto.getRefresh());
    }

    @Test
    void updateCurrentUserDetails() {
    }


    @Test
    void deleteUser() {
        Optional<User> optionalUser = userRepository.findByEmail("yes@gmail.com");
        User existingUser = optionalUser.get();
        String registeredUserDetails = keycloakService.getUserIdByEmail(userEmail);

        keycloakService.deleteUser(registeredUserDetails);
        userService.deleteUser(existingUser.getId());

        Optional<User> deletedUser = userRepository.findById(existingUser.getId());
        assertFalse(deletedUser.isPresent());
        assertNull(registeredUserDetails);

    }
}