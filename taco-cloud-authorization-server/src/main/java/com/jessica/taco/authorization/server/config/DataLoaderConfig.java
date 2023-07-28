package com.jessica.taco.authorization.server.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.jessica.taco.authorization.server.dao.UserRepository;
import com.jessica.taco.authorization.server.entity.User;

@Configuration
public class DataLoaderConfig {
  @Bean
  ApplicationRunner dataLoader(UserRepository repo, PasswordEncoder encoder) {
    return args -> {
      repo.save(new User("taco", encoder.encode("password"), "ROLE_ADMIN"));
    };
  }
}
