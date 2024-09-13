package org.example.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.oauth.handler.CustomizerAuthenticationFailureHandler;
import org.example.oauth.handler.CustomizerAuthenticationSuccessHandler;
import org.example.oauth.sms.MobilePhoneAuthenticationConverter;
import org.example.oauth.sms.MobilePhoneAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {


    @Autowired
    private MobilePhoneAuthenticationProvider mobilePhoneAuthenticationProvider;


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                    // 自定义授权模式转换器
                    .accessTokenRequestConverter(new MobilePhoneAuthenticationConverter())
                    // 自定义授权响应
                    .accessTokenResponseHandler(new CustomizerAuthenticationSuccessHandler())
                    .errorResponseHandler(new CustomizerAuthenticationFailureHandler())
            )
            .oidc(Customizer.withDefaults());

        http.exceptionHandling((exceptions) -> exceptions
            .authenticationEntryPoint((request, response, authException) -> {
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                OAuth2Error error = new OAuth2Error(
                    "unauthorized",
                    authException.getMessage(),
                    "https://tools.ietf.org/html/rfc6750#section-3.1"
                );

                new ObjectMapper().writeValue(response.getOutputStream(), error);
            })
        );

         // 添加自定义的认证提供者
        http.authenticationProvider(mobilePhoneAuthenticationProvider);

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("mobile-client")
            .clientSecret(passwordEncoder.encode("secret"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(new AuthorizationGrantType("mobile_phone")) // 自定义授权类型
            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/mobile-client")
            .scope("message.read")
            .scope("message.write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE) // 设置访问令牌格式为 REFERENCE
                        .build())
            .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


}