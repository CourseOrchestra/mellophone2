package ru.curs.mellophone.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.curs.mellophone.logic.AuthManager;


@RestController
@CrossOrigin
@RequestMapping("/mellophone")
public class MellophoneController {


    @GetMapping("/login")
    public String login() {

        //AuthManager.login(sesid, gp, login, pwd, ip);
        AuthManager.getTheManager().login("123", "all", "user1", "2222", null);


        return "Hello login222222222222!";

    }

}
