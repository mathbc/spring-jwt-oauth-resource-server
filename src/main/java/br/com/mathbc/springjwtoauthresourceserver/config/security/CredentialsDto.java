package br.com.mathbc.springjwtoauthresourceserver.config.security;

public record CredentialsDto (
        String email,
        String password
) {
}
