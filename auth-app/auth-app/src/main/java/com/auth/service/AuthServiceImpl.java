package com.auth.service;

import com.auth.dto.UserDto;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserService userService;
    @Override
    public UserDto registerUser(UserDto userDto) {
        UserDto udto = userService.createUser(userDto);
        return udto;
    }
}
