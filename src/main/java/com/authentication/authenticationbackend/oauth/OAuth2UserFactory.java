package com.authentication.authenticationbackend.oauth;

import com.authentication.authenticationbackend.exception.OAuth2AuthenticationProcessingException;
import com.authentication.authenticationbackend.model.Provider;

import java.util.Map;

public class OAuth2UserFactory {
    public static GoogleOAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(Provider.GOOGLE.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
