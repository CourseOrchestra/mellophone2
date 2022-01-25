package ru.curs.mellophone.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import ru.curs.mellophone.config.properties.MellophoneProperties;


@Configuration
@EnableConfigurationProperties({MellophoneProperties.class})
public class MellophoneConfiguration {
}
