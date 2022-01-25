package ru.curs.mellophone.service;

import org.springframework.stereotype.Service;
import ru.curs.mellophone.config.properties.MellophoneProperties;
import ru.curs.mellophone.logic.AuthManager;

@Service
public class MellophoneService {

    private final MellophoneProperties properties;

    public MellophoneService(MellophoneProperties properties) {
        this.properties = properties;
    }

    public String login() {

        System.out.println(properties.getMellophoneConfigPath());
        System.out.println(properties.getLog4jConfigPath());

        //AuthManager.login(sesid, gp, login, pwd, ip);
        AuthManager.getTheManager().login("123", "all", "user1", "2222", null);

        return "Hello login44!";

    }

}
