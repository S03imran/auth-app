package com.auth.dto;

public record LoginRequest(
        String email,
        String password
) {

}
