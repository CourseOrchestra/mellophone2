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

    public void login(String sesid, String gp, String login, String pwd, String ip) {
        if (gp == null) {
            gp = AuthManager.GROUP_PROVIDERS_ALL;
        }
        if (AuthManager.GROUP_PROVIDERS_NOT_DEFINE.equalsIgnoreCase(gp)) {
            gp = "";
        }

        if ((ip != null) && ip.isEmpty()) {
            ip = null;
        }

        AuthManager.getTheManager().login(sesid, gp, login, pwd, ip);
    }


}
