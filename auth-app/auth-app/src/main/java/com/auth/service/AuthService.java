package com.auth.service;

import com.auth.dto.UserDto;

public interface AuthService {
    UserDto registerUser(UserDto userDto);
}
