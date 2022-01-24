package ru.curs.mellophone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.curs.mellophone.logic.AuthManager;

import javax.annotation.PostConstruct;

@RestController
@EnableAutoConfiguration
public class MellophoneApplication {

    @RequestMapping("/mellophone")
    String home() {
        return "Hello World2345!";
    }

    public static void main(String[] args) {
        SpringApplication.run(MellophoneApplication.class, args);
    }

    @PostConstruct
    public void postConstruct() {
        AuthManager.getTheManager().productionModeInitialize();
    }


}