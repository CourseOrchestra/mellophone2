package ru.curs.mellophone.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
@RequestMapping("/mellophone")
public class MellophoneController {

	@GetMapping("/login")
	public String login() {

		return "Hello login222222222222!";

	}

}
