package ru.curs.mellophone.service;

import org.springframework.stereotype.Service;
import ru.curs.mellophone.config.properties.MellophoneProperties;
import ru.curs.mellophone.logic.AuthManager;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Service
public record MellophoneService(MellophoneProperties properties) {

    @PostConstruct
    private void postConstruct() {
        AuthManager.getTheManager().productionModeInitialize(properties.getConfigFile());
    }

    @PreDestroy
    private void preDestroy() {
        AuthManager.getTheManager().productionModeDestroy();
    }

    public void login(String sesid, String gp, String login, String pwd, String ip) {
        if (isNull(gp)) {
            gp = AuthManager.GROUP_PROVIDERS_ALL;
        }
        if (AuthManager.GROUP_PROVIDERS_NOT_DEFINE.equalsIgnoreCase(gp)) {
            gp = "";
        }

        if (nonNull(ip) && ip.isEmpty()) {
            ip = null;
        }

        AuthManager.getTheManager().login(sesid, gp, login, pwd, ip);
    }

    public String login2(String sesid, String login, String pwd) {
        return AuthManager.getTheManager().login(sesid, AuthManager.GROUP_PROVIDERS_ALL, login, pwd, null);
    }

    public void logout(String sesid) {
        AuthManager.getTheManager().logout(sesid);
    }

    public String isauthenticated(String sesid, String ip) {
        if (nonNull(ip) && ip.isEmpty()) {
            ip = null;
        }

        return AuthManager.getTheManager().isAuthenticated(sesid, ip);
    }

    public String checkname(String sesid, String name) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().checkName(sesid, name, pw);
        pw.flush();
        return os.toString();
    }

    public String getproviderlist(String gp, String login, String pwd, String ip) {
        if (isNull(gp)) {
            gp = AuthManager.GROUP_PROVIDERS_ALL;
        }
        if (AuthManager.GROUP_PROVIDERS_NOT_DEFINE.equalsIgnoreCase(gp)) {
            gp = "";
        }

        if (nonNull(ip) && ip.isEmpty()) {
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
        if (isNull(gp)) {
            gp = AuthManager.GROUP_PROVIDERS_ALL;
        }
        if (AuthManager.GROUP_PROVIDERS_NOT_DEFINE.equalsIgnoreCase(gp)) {
            gp = "";
        }

        if (nonNull(ip) && ip.isEmpty()) {
            ip = null;
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().checkCredentials(gp, login, pwd, ip, pw);
        pw.flush();
        return os.toString();
    }

    public String getuserlist(String pid, String gp, String token) {
        if (isNull(gp)) {
            gp = AuthManager.GROUP_PROVIDERS_ALL;
        }
        if (AuthManager.GROUP_PROVIDERS_NOT_DEFINE.equalsIgnoreCase(gp)) {
            gp = "";
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().getUserList(pid, gp, token, pw);
        pw.flush();
        return os.toString();
    }

    public void userCreate(String token, String user) {
        InputStream isUser;
        isUser = new ByteArrayInputStream(user.getBytes(StandardCharsets.UTF_8));
        AuthManager.getTheManager().userCreate(token, isUser);
    }

    public void userUpdate(String token, String sid, String user) {
        InputStream isUser;
        isUser = new ByteArrayInputStream(user.getBytes(StandardCharsets.UTF_8));
        AuthManager.getTheManager().userUpdate(token, sid, isUser);
    }

    public void userDelete(String token, String sid) {
        AuthManager.getTheManager().userDelete(token, sid);
    }

    public String changepwd(String sesid, String oldpwd, String newpwd) {
        return AuthManager.getTheManager().changeOwnPwd(sesid, oldpwd, newpwd);
    }

    public String changeuserpwd(String sesid, String username, String newpwd) {
        return AuthManager.getTheManager().changeUserPwd(sesid, username, newpwd);
    }

    public void changeappsesid(String oldsesid, String newsesid) {
        AuthManager.getTheManager().changeAppSessionId(oldsesid, newsesid);
    }

    public void loginesiauser(String sesid, String login, String userinfo) {
        AuthManager.getTheManager().loginESIAUser(sesid, login, userinfo);
    }

    public String setdjangoauthid(String djangosesid, String djangoauthid, String login, String name, String sid) {
        return AuthManager.getTheManager().setDjangoAuthId(djangosesid, djangoauthid, login, name, sid);
    }

    public String getdjangoauthid(String djangosesid, String authsesid, String djangoCallback) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(os);
        AuthManager.getTheManager().getDjangoAuthId(djangosesid, authsesid, djangoCallback, pw);
        pw.flush();
        return os.toString();
    }

    public void setsettings(String token, String lockouttime, String loginattemptsallowed) {
        AuthManager.getTheManager().setSettings(token, lockouttime, loginattemptsallowed);
    }

    public String authenticationgif(String sesid, String authsesid) {
        return AuthManager.getTheManager().authenticationGif(sesid, authsesid);
    }

    public void setstate(String sesid, String state) {
        AuthManager.getTheManager().setState(sesid, state);
    }

    public String getstate(String sesid) {
        return AuthManager.getTheManager().getState(sesid);
    }

}




