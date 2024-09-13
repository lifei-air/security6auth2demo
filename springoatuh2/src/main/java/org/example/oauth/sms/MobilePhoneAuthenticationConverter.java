package org.example.oauth.sms;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class MobilePhoneAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!"mobile_phone".equals(grantType)) {
            return null;
        }

        String phoneNumber = request.getParameter("phone_number");
        String smsCode = request.getParameter("sms_code");
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);

        if (phoneNumber == null || smsCode == null || clientId == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"));
        }

        return new MobilePhoneAuthenticationToken(phoneNumber, smsCode, clientId);
    }
}