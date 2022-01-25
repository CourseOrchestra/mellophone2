package ru.curs.mellophone.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.curs.mellophone.service.MellophoneService;


@RestController
@CrossOrigin
@RequestMapping("/mellophone")
public record MellophoneController(MellophoneService mellophoneService) {

    @GetMapping("/login")
    public String login() {
        return mellophoneService.login();
    }

}
