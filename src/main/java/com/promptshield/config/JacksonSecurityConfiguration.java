package com.promptshield.config;

import com.fasterxml.jackson.core.StreamReadConstraints;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;

/** Bounds JSON parser work before request DTO validation is reached. */
@Configuration(proxyBeanMethods = false)
public class JacksonSecurityConfiguration {

    @Bean
    Jackson2ObjectMapperBuilderCustomizer untrustedJsonReadConstraints(
            @Value("${app.request.max-json-string-chars:2000000}") int maxStringChars,
            @Value("${app.request.max-json-nesting-depth:100}") int maxNestingDepth) {
        if (maxStringChars <= 0 || maxNestingDepth <= 0) {
            throw new IllegalArgumentException("JSON read constraints must be positive");
        }
        return builder -> builder.postConfigurer(objectMapper -> objectMapper.getFactory().setStreamReadConstraints(
                StreamReadConstraints.builder()
                        .maxStringLength(maxStringChars)
                        .maxNestingDepth(maxNestingDepth)
                        .build()));
    }
}
