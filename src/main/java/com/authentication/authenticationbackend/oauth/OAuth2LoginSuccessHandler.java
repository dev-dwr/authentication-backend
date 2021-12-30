package com.authentication.authenticationbackend.oauth;

import com.authentication.authenticationbackend.model.AppUserRoles;
import com.authentication.authenticationbackend.model.Provider;
import com.authentication.authenticationbackend.model.User;
import com.authentication.authenticationbackend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository repository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        CustomOAuth2User auth2User = (CustomOAuth2User) authentication.getPrincipal();
        boolean existsUser = repository.existsByEmail(auth2User.getEmail());
        if(!existsUser){
            User newUser = new User();
            newUser.setProvider(Provider.GOOGLE);
            newUser.setEmail(auth2User.getEmail());
            newUser.setFirstname(auth2User.getFirstName());
            newUser.setLastname(auth2User.getLastname());
            newUser.setEnabled(true);

            List<AppUserRoles> list = auth2User.getAuthorities().stream().findFirst().map(s -> AppUserRoles.valueOf(s.getAuthority())).stream().collect(Collectors.toList());

            newUser.setAppUserRoles(list);
            newUser.setPassword("Blocked by Google SSO");
            repository.save(newUser);
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
