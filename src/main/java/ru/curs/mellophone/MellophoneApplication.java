package ru.curs.mellophone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import ru.curs.mellophone.logic.AuthManager;

import javax.annotation.PostConstruct;

@SpringBootApplication
public class MellophoneApplication {

    public static void main(String[] args) {
        SpringApplication.run(MellophoneApplication.class, args);
    }

    @PostConstruct
    public void postConstruct() {
        AuthManager.getTheManager().productionModeInitialize();
    }


}