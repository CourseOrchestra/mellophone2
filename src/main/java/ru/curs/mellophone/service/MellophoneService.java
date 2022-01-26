package ru.curs.mellophone.service;

import org.springframework.stereotype.Service;
import ru.curs.mellophone.config.properties.MellophoneProperties;
import ru.curs.mellophone.logic.AuthManager;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

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

    public void logout(String sesid) {
        AuthManager.getTheManager().logout(sesid);
    }

    public String isauthenticated(String sesid, String ip) {
        if ((ip != null) && ip.isEmpty()) {
            ip = null;
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().isAuthenticated(sesid, ip, pw);
        pw.flush();
        return os.toString();
    }

    public String checkname(String sesid, String name) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().checkName(sesid, name, pw);
        pw.flush();
        return os.toString();
    }

    public String getproviderlist(String gp, String login, String pwd, String ip) {
        if (gp == null) {
            gp = AuthManager.GROUP_PROVIDERS_ALL;
        }
        if (AuthManager.GROUP_PROVIDERS_NOT_DEFINE.equalsIgnoreCase(gp)) {
            gp = "";
        }

        if ((ip != null) && ip.isEmpty()) {
            ip = null;
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().getProviderList(gp, login, pwd, ip, pw);
        pw.flush();
        return os.toString();
    }

    public String importgroupsproviders() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().importGroupsProviders(pw);
        pw.flush();
        return os.toString();
    }

    public String checkcredentials(String gp, String login, String pwd, String ip) {
        if (gp == null) {
            gp = AuthManager.GROUP_PROVIDERS_ALL;
        }
        if (AuthManager.GROUP_PROVIDERS_NOT_DEFINE.equalsIgnoreCase(gp)) {
            gp = "";
        }

        if ((ip != null) && ip.isEmpty()) {
            ip = null;
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().checkCredentials(gp, login, pwd, ip, pw);

        pw.flush();
        return os.toString();
    }


}
