package org.keycloaks.user.service;

import org.keycloaks.user.data.dtos.requests.LoginRequestDto;
import org.keycloaks.user.data.dtos.requests.SignUpRequest;
import org.keycloaks.user.data.dtos.requests.UpdateUserRequestDto;
import org.keycloaks.user.data.dtos.responses.TokenResponseDto;
import org.keycloaks.user.data.dtos.responses.UserDto;
import org.keycloaks.user.data.models.User;

public interface UserService {

    User getCurrentUser();

    TokenResponseDto login(LoginRequestDto requestDto);

    UserDto getCurrentUserDetails();

    UserDto updateCurrentUserDetails(UpdateUserRequestDto requestDto);

    TokenResponseDto signUp(SignUpRequest requestDto);

    void deleteUser(String userId);
}
