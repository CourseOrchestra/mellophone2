package ru.curs.mellophone.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.curs.mellophone.service.MellophoneService;

import javax.validation.constraints.NotNull;


@Validated
@RestController
@CrossOrigin
@RequestMapping("/mellophone")
public class MellophoneController {

    private final MellophoneService mellophoneService;

    public MellophoneController(MellophoneService mellophoneService) {
        this.mellophoneService = mellophoneService;
    }

    @RequestMapping("/login")
    public void login(@NotNull String sesid, String gp, @NotNull String login, @NotNull String pwd, String ip) {
        mellophoneService.login(sesid, gp, login, pwd, ip);
    }

    @RequestMapping("/logout")
    public void logout(@NotNull String sesid) {
        mellophoneService.logout(sesid);
    }

    @RequestMapping({"/isauthenticated", "/checkid"})
    public String login(@NotNull String sesid, String ip) {
        return mellophoneService.isauthenticated(sesid, ip);
    }


}
