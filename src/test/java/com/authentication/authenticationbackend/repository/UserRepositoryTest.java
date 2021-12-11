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
        User user1 = User.builder()
                .firstname("Name")
                .lastname("lastnem")
                .password("passw")
                .email("dada@gmail.com").build();
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