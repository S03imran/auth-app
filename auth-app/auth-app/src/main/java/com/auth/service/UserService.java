package com.auth.service;

import com.auth.dto.UserDto;

public interface UserService {

    //create user
    UserDto createUser(UserDto userDto);

    public Iterable<UserDto> getAllUsers();

    public UserDto getUserByEmail(String email);

    public UserDto updateUser(UserDto userDto, String userId);

    public void deleteUser(String userId);

    public UserDto getUserById(String userId);
}
