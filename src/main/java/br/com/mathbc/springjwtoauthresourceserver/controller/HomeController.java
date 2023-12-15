package br.com.mathbc.springjwtoauthresourceserver.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/home")
public class HomeController {

    @GetMapping
    public String index() {
        var authUser = SecurityContextHolder.getContext().getAuthentication();

        System.out.println(authUser.getAuthorities());

        return "Hello World";
    }
}
