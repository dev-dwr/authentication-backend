package com.authentication.authenticationbackend.oauth;

import com.authentication.authenticationbackend.exception.OAuth2AuthenticationProcessingException;
import com.authentication.authenticationbackend.model.AppUserRoles;
import com.authentication.authenticationbackend.model.Provider;
import com.authentication.authenticationbackend.model.User;
import com.authentication.authenticationbackend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User user = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, user);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User user) {
        GoogleOAuth2UserInfo oAuth2UserInfo = OAuth2UserFactory.getOAuth2UserInfo(userRequest.getClientRegistration().getRegistrationId(), user.getAttributes());
        if(oAuth2UserInfo.getEmail().isEmpty()) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findUserByEmail(oAuth2UserInfo.getEmail());
        User userToSave;
        if(userOptional.isPresent()) {
            userToSave = userOptional.get();
            if(!userToSave.getProvider().equals(Provider.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase()))) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                        userToSave.getProvider() + " account. Please use your " + userToSave.getProvider() +
                        " account to login.");
            }
            userToSave = updateExistingUser(userToSave, oAuth2UserInfo);
        } else {
            userToSave = registerNewUser(userRequest, oAuth2UserInfo);
        }
        return UserPrincipal.create(userToSave, user.getAttributes());

    }
    private User updateExistingUser(User existingUser, GoogleOAuth2UserInfo oAuth2UserInfo) {
        existingUser.setFirstname(oAuth2UserInfo.getName());
        return userRepository.save(existingUser);
    }
    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, GoogleOAuth2UserInfo oAuth2UserInfo) {
        User newUser = new User();

        newUser.setProvider(Provider.GOOGLE);
        newUser.setEmail(oAuth2UserInfo.getEmail());
        newUser.setFirstname(oAuth2UserInfo.getFirstName());
        newUser.setLastname(oAuth2UserInfo.getLastname());
        newUser.setEnabled(true);
        newUser.setAppUserRoles(List.of(AppUserRoles.ROLE_USER));
        newUser.setPassword("Blocked by Google SSO");
        return userRepository.save(newUser);
    }
}