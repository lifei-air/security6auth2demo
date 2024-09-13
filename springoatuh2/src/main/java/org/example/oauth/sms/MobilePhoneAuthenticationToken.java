package org.example.oauth.sms;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class MobilePhoneAuthenticationToken extends AbstractAuthenticationToken {
    private final String phoneNumber;
    private final String smsCode;
    private final String clientId;

    public MobilePhoneAuthenticationToken(String phoneNumber, String smsCode, String clientId) {
        super(null);
        this.phoneNumber = phoneNumber;
        this.smsCode = smsCode;
        this.clientId = clientId;
        setAuthenticated(false);
    }

    public MobilePhoneAuthenticationToken(String phoneNumber, String smsCode, String clientId, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.phoneNumber = phoneNumber;
        this.smsCode = smsCode;
        this.clientId = clientId;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.smsCode;
    }

    @Override
    public Object getPrincipal() {
        return this.phoneNumber;
    }

    public String getClientId() {
        return this.clientId;
    }
}