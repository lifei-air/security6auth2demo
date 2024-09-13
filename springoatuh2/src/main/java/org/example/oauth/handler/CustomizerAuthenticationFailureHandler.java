package org.example.oauth.handler;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.res.CommonResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

@Slf4j
public class CustomizerAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final MappingJackson2HttpMessageConverter httpMessageConverter = new MappingJackson2HttpMessageConverter();
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        log.info("Customizer Authentication failed....");
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
        String errMsg;

        if (exception instanceof OAuth2AuthenticationException) {

            OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
            errMsg = error.getErrorCode();
        } else {
            errMsg = exception.getLocalizedMessage();
        }

        CommonResult result = CommonResult.failed(errMsg);
        httpMessageConverter.write(result, MediaType.APPLICATION_JSON, httpResponse);

    }
}
