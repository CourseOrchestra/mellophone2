package ru.curs.mellophone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class MellophoneApplication {
    public static void main(String[] args) {
        SpringApplication.run(MellophoneApplication.class, args);
    }
}