package com.authentication.authenticationbackend.service;

import com.authentication.authenticationbackend.payload.RegistrationCredentials;
//import com.authentication.authenticationbackend.repository.RoleRepository;
import com.authentication.authenticationbackend.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    PasswordEncoder encoder;
    @Mock
    UserRepository userRepository;
//    @Mock
//    RoleRepository roleRepository;

    @InjectMocks
    UserService userService;

    RegistrationCredentials registrationCredentials = new RegistrationCredentials();
//    Role role = new Role();

    @BeforeEach
    void setUp() {
        registrationCredentials.setEmail("daa@@");
        registrationCredentials.setFirstname("da");
        registrationCredentials.setLastname("pa");
        registrationCredentials.setPassword("dada");


//        role.setName(RoleName.ROLE_STUDENT);
//        role.setId(1L);
    }

    @Test
    void existsByEmail() {
        //given
        String email = "dupa@gmail.com";

        //when
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        Boolean exists = userRepository.existsByEmail(email);

        Mockito.verify(userRepository, times(1)).existsByEmail(anyString());

        assertThat(exists).isTrue();
    }

    @Test
    void createUserAccount() {

//        User user = User.builder()
//                .id(1L)
//                .firstname(registrationCredentials.getFirstname())
//                .email(registrationCredentials.getEmail())
//                .lastname(registrationCredentials.getLastname())
//                .password(registrationCredentials.getPassword())
//                .roles(Collections.singleton(role))
//                .build();
//
//
//
//        when(roleRepository.findByName(role.getName())).thenReturn(Optional.of(role));
//        when(userRepository.save(any())).thenReturn(user);
//
//        User userUnderTest = userService.createUserAccount(registrationCredentials);
//
//        assertThat(userUnderTest.getId()).isEqualTo(user.getId());
//        assertThat(userUnderTest.getEmail()).isEqualTo(user.getEmail());
//        assertThat(userUnderTest.getRoles()).isEqualTo(user.getRoles());
//
//        verify(userRepository, times(1)).save(any());
//
   }

//    @Test
//    void createGivenAccountWithWrongRole(){
//        AppException thrown = Assertions.assertThrows(AppException.class, () -> {
//            when(roleRepository.findByName(RoleName.ROLE_STUDENT))
//                    .thenThrow(new AppException("Student role not set"));
//            User userUnderTest = userService.createUserAccount(registrationCredentials);
//        });
//        Assertions.assertEquals("Student role not set", thrown.getMessage());
//
//    }
}