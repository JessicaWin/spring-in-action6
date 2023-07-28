package com.example.tacos.config;

import java.util.HashSet;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import com.example.tacos.dao.UserRepository;
import com.example.tacos.model.User;

@Configuration
public class SecurityConfig {
  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  // @Bean
  // public UserDetailsService userDetailsService(PasswordEncoder encoder) {
  // List<UserDetails> usersList = new ArrayList<>();
  // usersList.add(
  // new User("buzz", encoder.encode("password"), Arrays.asList(new
  // SimpleGrantedAuthority("ROLE_USER"))));
  // usersList.add(
  // new User("woody", encoder.encode("password"), Arrays.asList(new
  // SimpleGrantedAuthority("ROLE_USER"))));
  // return new InMemoryUserDetailsManager(usersList);
  // }

  @Bean
  UserDetailsService userDetailsService(UserRepository userRepo) {
    return username -> {
      User user = userRepo.findByUsername(username);
      if (user != null)
        return user;
      throw new UsernameNotFoundException("User '" + username + "' not found");
    };
  }

  private GrantedAuthoritiesMapper userAuthoritiesMapper() {
    return (authorities) -> {
      Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
      authorities.forEach(authority -> {
        mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
      });
      return mappedAuthorities;
    };
  }

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(
            auth -> auth.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**"))
                .permitAll().requestMatchers("/design", "/orders", "/current").hasRole("USER")
                .requestMatchers(HttpMethod.POST, "/api/ingredients")
                .hasAuthority("SCOPE_writeIngredients")
                .requestMatchers(HttpMethod.DELETE, "/api/ingredients")
                .hasAuthority("SCOPE_deleteIngredients").requestMatchers("/", "/**").permitAll())
        .oauth2ResourceServer(oauth2 -> oauth2.jwt())
        .headers(headers -> headers.frameOptions().sameOrigin()).csrf().disable().formLogin()
        .loginPage("/login").loginProcessingUrl("/authenticate").usernameParameter("username")
        .passwordParameter("password").defaultSuccessUrl("/design").and().logout()
        .logoutSuccessUrl("/login").and().oauth2Login().loginPage("/login")
        .userInfoEndpoint(userInfo -> userInfo.userAuthoritiesMapper(this.userAuthoritiesMapper()))
        .and().build();
  }

}
