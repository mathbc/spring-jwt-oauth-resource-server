package br.com.mathbc.springjwtoauthresourceserver.controller;

import br.com.mathbc.springjwtoauthresourceserver.config.security.AuthService;
import br.com.mathbc.springjwtoauthresourceserver.config.security.CredentialsDto;
import br.com.mathbc.springjwtoauthresourceserver.domain.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/token")
    public String token(@RequestBody CredentialsDto credentialsDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(credentialsDto.email(), credentialsDto.password()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User authUser = (User) authentication.getPrincipal();

        System.out.println(authUser.getAuthorities());

        String token = authService.generateToken(authentication);

        return token;
    }
}
