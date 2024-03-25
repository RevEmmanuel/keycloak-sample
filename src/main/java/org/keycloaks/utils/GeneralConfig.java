package org.keycloaks.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.format.DateTimeFormatter;

@Configuration
public class GeneralConfig {

    @Bean
    public ModelMapper modelMapper() {
        ModelMapper mapper = new ModelMapper();
        mapper.getConfiguration()
                .setFieldMatchingEnabled(true)
                .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE)
                .setMatchingStrategy(MatchingStrategies.STANDARD);
        return mapper;
    }


    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        var LOCAL_DATETIME_SERIALIZER = new LocalDateTimeSerializer(
                DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'")
        );
        JavaTimeModule module = new JavaTimeModule();
        module.addSerializer(LOCAL_DATETIME_SERIALIZER);
        return new ObjectMapper().registerModule(module);
    }

    @Bean
    public WebClient.Builder getWebClientBuilder() {
        return WebClient.builder();
    }
}
