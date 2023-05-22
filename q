[1mdiff --git a/taco-cloud/src/main/java/com/example/tacos/config/SecurityConfig.java b/taco-cloud/src/main/java/com/example/tacos/config/SecurityConfig.java[m
[1mindex 0969a7d..afc18ee 100644[m
[1m--- a/taco-cloud/src/main/java/com/example/tacos/config/SecurityConfig.java[m
[1m+++ b/taco-cloud/src/main/java/com/example/tacos/config/SecurityConfig.java[m
[36m@@ -1,33 +1,54 @@[m
 package com.example.tacos.config;[m
 [m
[31m-import java.util.ArrayList;[m
[31m-import java.util.Arrays;[m
[31m-import java.util.List;[m
[31m-[m
 import org.springframework.context.annotation.Bean;[m
 import org.springframework.context.annotation.Configuration;[m
[31m-import org.springframework.security.core.authority.SimpleGrantedAuthority;[m
[31m-import org.springframework.security.core.userdetails.User;[m
[31m-import org.springframework.security.core.userdetails.UserDetails;[m
[32m+[m[32mimport org.springframework.security.config.annotation.web.builders.HttpSecurity;[m
 import org.springframework.security.core.userdetails.UserDetailsService;[m
[32m+[m[32mimport org.springframework.security.core.userdetails.UsernameNotFoundException;[m
 import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;[m
 import org.springframework.security.crypto.password.PasswordEncoder;[m
[31m-import org.springframework.security.provisioning.InMemoryUserDetailsManager;[m
[32m+[m[32mimport org.springframework.security.web.SecurityFilterChain;[m
[32m+[m[32mimport org.springframework.security.web.util.matcher.AntPathRequestMatcher;[m
[32m+[m
[32m+[m[32mimport com.example.tacos.dao.UserRepository;[m
[32m+[m[32mimport com.example.tacos.model.User;[m
 [m
 @Configuration[m
 public class SecurityConfig {[m
 	@Bean[m
[31m-	public PasswordEncoder passwordEncoder() {[m
[32m+[m	[32mPasswordEncoder passwordEncoder() {[m
 		return new BCryptPasswordEncoder();[m
 	}[m
 [m
[32m+[m[32m//	@Bean[m
[32m+[m[32m//	public UserDetailsService userDetailsService(PasswordEncoder encoder) {[m
[32m+[m[32m//		List<UserDetails> usersList = new ArrayList<>();[m
[32m+[m[32m//		usersList.add([m
[32m+[m[32m//				new User("buzz", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))));[m
[32m+[m[32m//		usersList.add([m
[32m+[m[32m//				new User("woody", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))));[m
[32m+[m[32m//		return new InMemoryUserDetailsManager(usersList);[m
[32m+[m[32m//	}[m
[32m+[m
 	@Bean[m
[31m-	public UserDetailsService userDetailsService(PasswordEncoder encoder) {[m
[31m-		List<UserDetails> usersList = new ArrayList<>();[m
[31m-		usersList.add([m
[31m-				new User("buzz", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))));[m
[31m-		usersList.add([m
[31m-				new User("woody", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))));[m
[31m-		return new InMemoryUserDetailsManager(usersList);[m
[32m+[m	[32mUserDetailsService userDetailsService(UserRepository userRepo) {[m
[32m+[m		[32mreturn username -> {[m
[32m+[m			[32mUser user = userRepo.findByUsername(username);[m
[32m+[m			[32mif (user != null)[m
[32m+[m				[32mreturn user;[m
[32m+[m			[32mthrow new UsernameNotFoundException("User '" + username + "' not found");[m
[32m+[m		[32m};[m
 	}[m
[32m+[m
[32m+[m	[32m@Bean[m
[32m+[m	[32mSecurityFilterChain filterChain(HttpSecurity http) throws Exception {[m
[32m+[m		[32mreturn http[m
[32m+[m				[32m.authorizeHttpRequests(auth -> auth.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**"))[m
[32m+[m						[32m.permitAll().requestMatchers("/design", "/orders").hasRole("USER").requestMatchers("/", "/**")[m
[32m+[m						[32m.permitAll())[m
[32m+[m				[32m.headers(headers -> headers.frameOptions().sameOrigin())[m
[32m+[m				[32m.csrf(csrf -> csrf.ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")))[m
[32m+[m				[32m.formLogin().and().build();[m
[32m+[m	[32m}[m
[32m+[m
 }[m
warning: CRLF will be replaced by LF in taco-cloud/src/main/java/com/example/tacos/config/SecurityConfig.java.
The file will have its original line endings in your working directory.
