package ru.curs.mellophone.controller;

import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import ru.curs.mellophone.logic.EAuthServerLogic;
import ru.curs.mellophone.service.MellophoneService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import java.io.InputStream;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;


@Validated
@RestController
@CrossOrigin
@RequestMapping("/mellophone")
public class MellophoneController {

    private static final String DIR_IMAGES = "/images/";
    private static final String COLOR_BANNER = "color.gif";
    private static final String BW_BANNER = "bw.gif";

    private final MellophoneService mellophoneService;

    public MellophoneController(MellophoneService mellophoneService) {
        this.mellophoneService = mellophoneService;
    }

    @RequestMapping("/login")
    public void login(@NotNull String sesid, String gp, @NotNull String login, @NotNull String pwd, String ip) {
        mellophoneService.login(sesid, gp, login, pwd, ip);
    }

    @RequestMapping("/login2")
    public void login2(@NotNull String sesid, @NotNull String login, @NotNull String pwd, HttpServletResponse response) {
        String authsesid = mellophoneService.login2(sesid, login, pwd);
        Cookie cookie = new Cookie("authsesid", authsesid);
        response.addCookie(cookie);
    }

    @RequestMapping("/logout")
    public void logout(@NotNull String sesid) {
        mellophoneService.logout(sesid);
    }

    @RequestMapping({"/isauthenticated", "/checkid"})
    public String isauthenticated(@NotNull String sesid, String ip) {
        return mellophoneService.isauthenticated(sesid, ip);
    }

    @RequestMapping("/checkname")
    public String checkname(@NotNull String sesid, @NotNull String name) {
        return mellophoneService.checkname(sesid, name);
    }

    @RequestMapping("/getproviderlist")
    public String getproviderlist(String gp, @NotNull String login, @NotNull String pwd, String ip) {
        return mellophoneService.getproviderlist(gp, login, pwd, ip);
    }

    @RequestMapping("/importgroupsproviders")
    public String importgroupsproviders() {
        return mellophoneService.importgroupsproviders();
    }

    @RequestMapping("/checkcredentials")
    public String checkcredentials(String gp, @NotNull String login, @NotNull String pwd, String ip) {
        return mellophoneService.checkcredentials(gp, login, pwd, ip);
    }

    @RequestMapping("/getuserlist")
    public String getuserlist(String pid, String gp, @NotNull String token) {
        return mellophoneService.getuserlist(pid, gp, token);
    }

    @PostMapping("/user/create")
    public void userCreate(@NotNull String token, @RequestBody @NotNull String user) {
        mellophoneService.userCreate(token, user);
    }

    @PostMapping("/user/{sid}")
    public void userUpdate(@NotNull String token, @PathVariable @NotNull String sid, @RequestBody @NotNull String user) {
        mellophoneService.userUpdate(token, sid, user);
    }

    @DeleteMapping("/user/{sid}")
    public void userDelete(@NotNull String token, @PathVariable @NotNull String sid) {
        mellophoneService.userDelete(token, sid);
    }

    @RequestMapping("/changepwd")
    public String changepwd(@NotNull String sesid, @NotNull String oldpwd, @NotNull String newpwd) {
        return mellophoneService.changepwd(sesid, oldpwd, newpwd);
    }

    @RequestMapping("/changeuserpwd")
    public String changeuserpwd(@NotNull String sesid, @NotNull String username, @NotNull String newpwd) {
        return mellophoneService.changeuserpwd(sesid, username, newpwd);
    }

    @RequestMapping("/changeappsesid")
    public void changeappsesid(@NotNull String oldsesid, @NotNull String newsesid) {
        mellophoneService.changeappsesid(oldsesid, newsesid);
    }

    @RequestMapping("/loginesiauser")
    public void loginesiauser(@NotNull String sesid, @NotNull String login, String userinfo) {
        mellophoneService.loginesiauser(sesid, login, userinfo);
    }

    @RequestMapping("/setdjangoauthid")
    public String setdjangoauthid(@NotNull String sesid, @NotNull String djangoauthid, @NotNull String login, @NotNull String name, @NotNull String sid, String callback, HttpServletResponse response) {
        String authsesid = mellophoneService.setdjangoauthid(sesid, djangoauthid, login, name, sid);
        Cookie cookie = new Cookie("authsesid", authsesid);
        response.addCookie(cookie);
        return callback + "();";
    }

    @RequestMapping("/getdjangoauthid")
    public String getdjangoauthid(@NotNull String sesid, String callback, @CookieValue(required = false) String authsesid) {
        return mellophoneService.getdjangoauthid(sesid, authsesid, callback);
    }

    @RequestMapping("/setsettings")
    public void setsettings(@NotNull String token, String lockouttime, String loginattemptsallowed) {
        mellophoneService.setsettings(token, lockouttime, loginattemptsallowed);
    }

    @RequestMapping(value = "/authentication.gif", produces = MediaType.IMAGE_GIF_VALUE)
    public @ResponseBody
    byte[] authenticationgif(@NotNull String sesid, @CookieValue(required = false) String authsesid, HttpServletResponse response) {

        String authsesidNew = mellophoneService.authenticationgif(sesid, authsesid);
        String banner;
        if (isNull(authsesidNew)) {
            if (nonNull(authsesid)) {
                Cookie cookie = new Cookie("authsesid", null);
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
            banner = BW_BANNER;
        } else {
            if (!"AUTH_OK".equals(authsesidNew)) {
                Cookie cookie = new Cookie("authsesid", authsesidNew);
                response.addCookie(cookie);
            }
            banner = COLOR_BANNER;
        }

        InputStream in = getClass().getResourceAsStream(DIR_IMAGES + banner);
        byte[] array;
        try {
            assert nonNull(in);
            array = in.readAllBytes();
        } catch (Exception e) {
            e.printStackTrace();
            throw EAuthServerLogic.create(e);
        }

        return array;
    }

    @PostMapping("/setstate")
    public void setstate(@NotNull String sesid, @RequestBody @NotNull String state) {
        mellophoneService.setstate(sesid, state);
    }

    @RequestMapping("/getstate")
    public String getstate(@NotNull String sesid) {
        return mellophoneService.getstate(sesid);
    }

}












