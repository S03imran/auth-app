package com.auth.security;

import com.auth.entities.Provider;
import com.auth.entities.RefreshToken;
import com.auth.entities.User;
import com.auth.repository.RefreshTokenRepository;
import com.auth.repository.UserRepository;
import com.auth.service.CookieService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.auth.frontend.success-redirect}")
    private String frontEndSuccessUrl;
    @Value("${app.auth.frontend.failure-redirect}")
    private String frontEndFailureUrl;

    private final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Authentication Success");
        logger.info(authentication.toString());

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        //identify user
        String registrationId = "unknown";
        if(authentication instanceof OAuth2AuthenticationToken token){
            registrationId = token.getAuthorizedClientRegistrationId();
        }
        logger.info("Registration Id: " + registrationId);
        logger.info("User: "+oAuth2User.getAttributes().toString());

        User user;
        switch (registrationId) {
            case "google"-> {
                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("picture", "").toString();
                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(picture)
                        .enable(true)
                        .providerId(googleId)
                        .provider(Provider.GOOGLE)
                        .build();
                user = userRepository.findByEmail(email).orElseGet(()->userRepository.save(newUser));

            }
            case "github"->{
                String name = oAuth2User.getAttributes().getOrDefault("login", "").toString();
                //String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String githubId = oAuth2User.getAttributes().getOrDefault("id", "").toString();
                String image = oAuth2User.getAttributes().getOrDefault("avatar_url", "").toString();
                String email = (String) oAuth2User.getAttributes().get("email");
                if (email == null) {
                    email = name + "@github.com";
                }
                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(image)
                        .enable(true)
                        .providerId(githubId)
                        .provider(Provider.GITHUB)
                        .build();
                user = userRepository.findByEmail(email).orElseGet(()->userRepository.save(newUser));

            }
            default -> throw new RuntimeException("Invalid Registration id");
        }
        // we are getting username, email
        //create a new user
        //create jwt token

        String jti = UUID.randomUUID().toString();
        RefreshToken refreshTokenOn = RefreshToken.builder().jti(jti).user(user).revoked(false).createdAt(Instant.now()).expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds())).build();
        refreshTokenRepository.save(refreshTokenOn);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOn.getJti());
        cookieService.attachRefreshCookie(response,refreshToken,(int) jwtService.getRefreshTtlSeconds());

        //response.getWriter().write("Login Successful via OAuth2");
        response.sendRedirect(frontEndSuccessUrl);
    }
}
