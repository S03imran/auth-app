package com.auth.dto;

public record Tokenresponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        String tokenType,
        UserDto user
) {
    public static Tokenresponse of(String accessToken, String refreshToken, long expiresIn, UserDto user) {
        return new Tokenresponse(accessToken, refreshToken, expiresIn, "Bearer", user);
    }
}
