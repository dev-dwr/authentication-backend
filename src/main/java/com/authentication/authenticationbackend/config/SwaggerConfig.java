package com.authentication.authenticationbackend.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.service.SecurityScheme;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.List;

import static java.util.Collections.singletonList;


@Configuration
@EnableSwagger2
@RequiredArgsConstructor
public class SwaggerConfig {
    private final ObjectMapper objectMapper;

    //serialize non null fields
    void customizeObjectMapper(){
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Bean
    public Docket swaggerApi(){
        return new Docket(DocumentationType.SWAGGER_2)
                //.ignoredParameterTypes(UsernamePasswordAuthenticationToken.class)
                .select()
                .paths(PathSelectors.regex("^(?!/(error).*$).*$"))
                .build()
                .securitySchemes(singletonList(createSchema())).securityContexts(singletonList(createContext()));
    }

    private SecurityContext createContext() {
        return SecurityContext.builder()
                .securityReferences(createRef())
                .forPaths(PathSelectors.any())
                .build();
    }
    private List<SecurityReference> createRef() {
        AuthorizationScope authorizationScope = new AuthorizationScope(
                "global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return singletonList(new SecurityReference("apiKey", authorizationScopes));
    }

    private SecurityScheme createSchema() {
        return new ApiKey("apiKey", "Authorization", "header");
    }
}
