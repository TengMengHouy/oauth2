package com.example.init;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;
import java.time.Duration;

@Component
public class DataInitializer implements CommandLineRunner {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(RegisteredClientRepository registeredClientRepository,
                           PasswordEncoder passwordEncoder) {
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        String pkceClientId = "spa-client";
        if (registeredClientRepository.findByClientId(pkceClientId) == null) {
            RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(pkceClientId)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:3000/oauth2/callback")
                    .scope("openid")
                    .scope("profile")
                    .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(30))
                            .refreshTokenTimeToLive(Duration.ofDays(3))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();
            registeredClientRepository.save(publicClient);
            System.out.println("Created PKCE client: " + pkceClientId);
        }

        String machineClientId = "machine-client";
        if (registeredClientRepository.findByClientId(machineClientId) == null) {
            String rawSecret = "machine-secret-please-change";
            RegisteredClient machine = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(machineClientId)
                    .clientSecret(passwordEncoder.encode(rawSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("api.read")
                    .scope("api.write")
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofHours(1))
                            .build())
                    .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                    .build();
            registeredClientRepository.save(machine);
            System.out.println("Created machine client: " + machineClientId + " secret: " + rawSecret);
        }
    }
}
