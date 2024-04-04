package org.keycloaks.user.service.impl;


import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.dtos.requests.UpdateUserRequestDto;
import org.keycloaks.user.data.dtos.responses.TokenResponseDto;
import org.keycloaks.user.data.dtos.responses.UserDto;
import org.keycloaks.user.data.models.User;
import org.keycloaks.user.data.repositories.UserRepository;
import org.keycloaks.user.service.KeycloakService;
import org.keycloaks.user.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final KeycloakService keycloakService;
    private final ModelMapper modelMapper;

    @Override
    public User getCurrentUser() {
        try {
            Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String subject = jwt.getSubject();
            log.info("Principal: {}", subject);
            return userRepository.findById(subject).orElseThrow(() -> new RuntimeException("Cannot find user"));
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    @Transactional
    public TokenResponseDto login(LoginRequestDto requestDto) {
        AccessTokenResponse accessTokenResponse = keycloakService.login(LoginRequestDto.builder()
                .email(requestDto.getEmail())
                .password(requestDto.getPassword())
                .build());

        return TokenResponseDto.builder()
                .auth(accessTokenResponse.getToken())
                .refresh(accessTokenResponse.getRefreshToken())
                .build();
    }

    @Override
    public UserDto getCurrentUserDetails() {
        return modelMapper.map(this.getCurrentUser(), UserDto.class);
    }

    @Override
    public UserDto updateCurrentUserDetails(UpdateUserRequestDto requestDto) {
        User user = this.getCurrentUser();
        if (user == null) {
            throw new RuntimeException("Current user not found");
        }

        user.setFirstName(requestDto.getFirstName());
        user.setLastName(requestDto.getLastName());
        user.setPhoneNumber(requestDto.getPhoneNumber());

        keycloakService.updateUser(user);
        return modelMapper.map(userRepository.save(user), UserDto.class);
    }

    @Override
    public TokenResponseDto signUp(SignUpRequest requestDto) {
        if (userRepository.existsByEmail(requestDto.getEmail())) {
            throw new RuntimeException("Email already exists");
        }
        UserRepresentation userRepresentation = keycloakService.createUser(requestDto);
        userRepository.save(User.builder()
                .email(userRepresentation.getEmail())
                .id(userRepresentation.getId())
                .firstName(userRepresentation.getFirstName())
                .lastName(userRepresentation.getLastName())
                .build());

        AccessTokenResponse accessTokenResponse = keycloakService.login(LoginRequestDto.builder()
                .email(userRepresentation.getEmail())
                .password(requestDto.getPassword())
                .build());

        return TokenResponseDto.builder()
                .auth(accessTokenResponse.getToken())
                .refresh(accessTokenResponse.getRefreshToken())
                .build();
    }

    @Override
    public void deleteUser(String userId) {
        keycloakService.deleteUser(userId);
        userRepository.deleteById(userId);
    }
}
