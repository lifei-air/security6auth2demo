package org.example.oauth.sms;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
public class MobilePhoneAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MobilePhoneAuthenticationToken mobilePhoneAuthentication = (MobilePhoneAuthenticationToken) authentication;

        // 验证手机号和验证码的逻辑...
        String phoneNumber = (String) mobilePhoneAuthentication.getPrincipal();
        String smsCode = (String) mobilePhoneAuthentication.getCredentials();

        // 这里应该添加实际的验证逻辑
        if (!"123456".equals(smsCode)) {  // 示例验证，实际应该查询数据库或缓存
            throw new BadCredentialsException("Invalid SMS code");
        }

        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient();
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(mobilePhoneAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(registeredClient.getScopes())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType("mobile_phone"))
                .build();


        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (!(generatedAccessToken instanceof OAuth2AccessToken)) {
            throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "The token generator failed to generate the access token.", null));
        }

        OAuth2AccessToken accessToken = (OAuth2AccessToken) generatedAccessToken;

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(mobilePhoneAuthentication)
                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .authorizedScopes(registeredClient.getScopes())
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .authorizationGrantType(new AuthorizationGrantType("mobile_phone"))
                    .build();

            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "The token generator failed to generate the refresh token.", null));
            }
            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
        }

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(phoneNumber)
                .authorizationGrantType(new AuthorizationGrantType("mobile_phone"))
                .token(accessToken)
                .refreshToken(refreshToken)
                .build();

        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, refreshToken,  Collections.emptyMap());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MobilePhoneAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient() {
        // 这里需要实现获取当前认证的客户端逻辑
        // 例如，从 SecurityContextHolder 中获取
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2ClientAuthenticationToken) {
            return (OAuth2ClientAuthenticationToken) authentication;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}