package com.authentication.authenticationbackend.repository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import com.authentication.authenticationbackend.model.User;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@ExtendWith(MockitoExtension.class)
@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void initUseCase() {
        User user1 = new User();
        user1.setEmail("dada@gmail.com");
        user1.setFirstname("dada");
        user1.setLastname("papa");
        user1.setPassword("lalala");
        userRepository.save(user1);
    }

    @Test
    void existsByEmailShouldReturnTrue() {
        String email = "dada@gmail.com";

        Boolean exists = userRepository.existsByEmail(email);

        assertThat(exists).isTrue();
    }
    @Test
    void existsByEmailShouldReturnFalse() {
        String email = "test@gmail.com";

        Boolean exists = userRepository.existsByEmail(email);

        assertThat(exists).isFalse();
    }

}