package com.auth.service;

import com.auth.dto.UserDto;
import com.auth.entities.Provider;
import com.auth.entities.User;
import com.auth.exception.ResourceNotFoundException;
import com.auth.helper.UserHelper;
import com.auth.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserRepository userRepository;

    @Autowired
    ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        if(userDto.getEmail() == null || userDto.getEmail().isEmpty()){
            throw new IllegalArgumentException("Email is required");
        }
        if(userRepository.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("User with this email already exists");
        }
        User user = modelMapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider()!=null?userDto.getProvider(): Provider.LOCAL);
        //assign role to new user fir authorization

        User savedUser = userRepository.save(user);
        UserDto savedUserDto = modelMapper.map(savedUser, UserDto.class);
        return savedUserDto;
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new ResourceNotFoundException("User not found with given email " ));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        //find the user
        User existingUser = userRepository.findById(uuid).orElseThrow(() -> new ResourceNotFoundException("User not found with given id "));
        //update the user details
        if(userDto.getName()!=null){
            existingUser.setName(userDto.getName());
        }
        if(userDto.getImage()!=null){
            existingUser.setImage(userDto.getImage());
        }
        if(userDto.getProvider()!=null){
            existingUser.setProvider(userDto.getProvider());
        }
        if(userDto.getPassword()!=null){
            existingUser.setPassword(userDto.getPassword());
        }
        existingUser.setEnable(userDto.isEnable());
        existingUser.setUpdatedAt(Instant.now());
        User updatedUser = userRepository.save(existingUser);
        return modelMapper.map(updatedUser, UserDto.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID uid = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uid).orElseThrow(() -> new ResourceNotFoundException("User not found with given id "));
        userRepository.delete(user);
    }

    @Override
    public UserDto getUserById(String userId) {
        UUID uid = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uid).orElseThrow(() -> new ResourceNotFoundException("User not found with given id "));
        return modelMapper.map(user, UserDto.class);
    }
}
