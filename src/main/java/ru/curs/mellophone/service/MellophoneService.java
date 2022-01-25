package ru.curs.mellophone.service;

import org.springframework.stereotype.Service;
import ru.curs.mellophone.config.properties.MellophoneProperties;
import ru.curs.mellophone.logic.AuthManager;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

@Service
public record MellophoneService(MellophoneProperties properties) {

    @PostConstruct
    private void postConstruct() {
        AuthManager.getTheManager().productionModeInitialize(properties.getMellophoneConfigPath(), properties.getLog4jConfigPath());
    }

    @PreDestroy
    private void preDestroy() {
        AuthManager.getTheManager().productionModeDestroy();
    }

    public String login() {


        //AuthManager.login(sesid, gp, login, pwd, ip);
        AuthManager.getTheManager().login("123", "all", "user1", "2222__", null);

        return "Hello login44!";

    }

}
