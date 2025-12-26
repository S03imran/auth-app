package com.auth.controller;

import com.auth.dto.LoginRequest;
import com.auth.dto.RefreshTokenRequest;
import com.auth.dto.Tokenresponse;
import com.auth.dto.UserDto;
import com.auth.entities.RefreshToken;
import com.auth.entities.User;
import com.auth.repository.RefreshTokenRepository;
import com.auth.repository.UserRepository;
import com.auth.security.JwtService;
import com.auth.service.AuthService;
import com.auth.service.CookieService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final ModelMapper mapper;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    @PostMapping("/login")
    public ResponseEntity<Tokenresponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response){
        //authenticate
        Authentication authenticate = authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(()->new BadCredentialsException("Invalid email or password"));
        if(!user.isEnable()){
            throw new DisabledException("User is diabled");
        }

        String jti = UUID.randomUUID().toString();
        var refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        //save the information related to refresh token to db
        refreshTokenRepository.save(refreshTokenOb);

        //generate access token
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user,refreshTokenOb.getJti());

        // use cookie service to attach refresh token in cookie
        cookieService.attachRefreshCookie(response,refreshToken,(int)jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

        Tokenresponse tokenresponse = Tokenresponse.of(accessToken,refreshToken,jwtService.getAccessTtlSeconds(),mapper.map(user,UserDto.class));
        return ResponseEntity.ok(tokenresponse);
    }

    private Authentication authenticate(LoginRequest loginRequest) {
        try{
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(),loginRequest.password()));
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    //to renew access and refresh token creating a new endpoint
    @PostMapping("refresh")
    public ResponseEntity<Tokenresponse> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletResponse response,
            HttpServletRequest request
    ){
        //ready refresh token from cookie or body
        String refreshToken = readRefreshTokenFromRequest(body, request).orElseThrow(()->new BadCredentialsException("Refresh Token is missing"));
        if(!jwtService.isRefreshToken(refreshToken)){
            throw new BadCredentialsException("Invalid refresh token");
        }

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);
        RefreshToken storedRefreshToken =   refreshTokenRepository.findByJti(jti).orElseThrow(()->new BadCredentialsException("Invalid refresh token"));
        if(storedRefreshToken.isRevoked()){
            throw new BadCredentialsException("Refresh token is expired or revoked");
        }

        if(storedRefreshToken.getExpiresAt().isBefore(Instant.now())){
            throw new  BadCredentialsException("Refresh token expired");
        }

        if(!storedRefreshToken.getUser().getId().equals(userId)){
            throw new BadCredentialsException("Refresh token does not belongs to the user");
        }

        //rotate refresh token
        storedRefreshToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setReplacedBy(newJti);
        refreshTokenRepository.save(storedRefreshToken);
        User user = storedRefreshToken.getUser();

        var newRefreshTokenOb = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        refreshTokenRepository.save(newRefreshTokenOb);
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user,newRefreshTokenOb.getJti());

        cookieService.attachRefreshCookie(response,newRefreshToken,(int)jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);
        return ResponseEntity.ok(Tokenresponse.of(newAccessToken,newRefreshToken,jwtService.getAccessTtlSeconds(),mapper.map(user,UserDto.class)));
    }

    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest body, HttpServletRequest request) {
        //prefer reading refresh token from cookie
        if(request.getCookies()!=null){
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(c->cookieService.getRefreshTokenCookieName().equals(c.getName()))
                    .map(c->c.getValue())
                    .filter(v->!v.isBlank())
                    .findFirst();
            if(fromCookie.isPresent()){
                return fromCookie;
            }
        }
        // if not found in cookie read from body
        if(body!=null && body.refreshToken()!=null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }

        // header
        String refreshHeader = request.getHeader("X-Refresh-Token");
        if(refreshHeader!=null && !refreshHeader.isBlank()) {
            return Optional.of(refreshHeader.trim());
        }

        //Authorization = Bearer <token>
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeader!=null && authHeader.regionMatches(true,0,"Bearer ",0,"Bearer".length())) {
            String candidate = authHeader.substring(7).trim();
            if(!candidate.isEmpty()){
                try{
                    if(jwtService.isRefreshToken(candidate)){
                        return Optional.of(candidate);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return Optional.empty();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response){
        readRefreshTokenFromRequest(null, request).ifPresent(token->{
            try{
                if(jwtService.isRefreshToken(token)){
                    String jti = jwtService.getJti(token);
                    refreshTokenRepository.findByJti(jti).ifPresent(rt->{
                        rt.setRevoked(true);
                        refreshTokenRepository.save(rt);
                    });
                }
            }catch (JwtException ignored){

            }
        });
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeaders(response);
        SecurityContextHolder.clearContext();
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }
}
