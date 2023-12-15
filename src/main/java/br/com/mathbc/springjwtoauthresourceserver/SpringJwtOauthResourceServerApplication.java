package br.com.mathbc.springjwtoauthresourceserver;

import br.com.mathbc.springjwtoauthresourceserver.config.RsaKeysConfigProperties;
import br.com.mathbc.springjwtoauthresourceserver.domain.user.User;
import br.com.mathbc.springjwtoauthresourceserver.domain.user.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableConfigurationProperties(RsaKeysConfigProperties.class)
@SpringBootApplication
public class SpringJwtOauthResourceServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtOauthResourceServerApplication.class, args);
	}

//	@Bean
//	public CommandLineRunner initializeUser(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
//		return args -> {
//
//			User user = new User();
//			user.setName("Matheus");
//			user.setEmail("matheus@teste.com");
//			user.setPassword(passwordEncoder.encode("123456"));
//
//			// Save the user to the database
//			userRepository.save(user);
//
//		};
//	}
}
