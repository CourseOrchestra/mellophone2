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


    public void login2(String sesid, String login, String pwd) {



        String authsesid = AuthManager.getTheManager().login(sesid, AuthManager.GROUP_PROVIDERS_ALL, login, pwd, null);


//        response.addCookie(new Cookie("authsesid", authsesid));



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

    public String getuserlist(String pid, String gp, String token, String ip) {
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
        AuthManager.getTheManager().getUserList(pid, gp, token, ip, pw);
        pw.flush();
        return os.toString();
    }

    public void userCreate(String token, String user) {
        InputStream isUser = new ByteArrayInputStream(user.getBytes());
        AuthManager.getTheManager().userCreate(token, isUser);
    }

    public void userUpdate(String token, String sid, String user) {
        InputStream isUser = new ByteArrayInputStream(user.getBytes());
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
        AuthManager.getTheManager().loginESIAUser(sesid, login, userinfo, null);
    }


}
