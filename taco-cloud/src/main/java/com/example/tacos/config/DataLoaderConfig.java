package com.example.tacos.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.example.tacos.dao.IngredientRepository;
import com.example.tacos.dao.UserRepository;
import com.example.tacos.model.Ingredient;
import com.example.tacos.model.Ingredient.Type;
import com.example.tacos.model.User;

@Configuration
public class DataLoaderConfig {
  @Bean
  CommandLineRunner dataLoaderIngredient(IngredientRepository repo) {
    return args -> {
      repo.save(new Ingredient("FLTO", "Flour Tortilla", Type.WRAP));
      repo.save(new Ingredient("COTO", "Corn Tortilla", Type.WRAP));
      repo.save(new Ingredient("GRBF", "Ground Beef", Type.PROTEIN));
      repo.save(new Ingredient("CARN", "Carnitas", Type.PROTEIN));
      repo.save(new Ingredient("TMTO", "Diced Tomatoes", Type.VEGGIES));
      repo.save(new Ingredient("LETC", "Lettuce", Type.VEGGIES));
      repo.save(new Ingredient("CHED", "Cheddar", Type.CHEESE));
      repo.save(new Ingredient("JACK", "Monterrey Jack", Type.CHEESE));
      repo.save(new Ingredient("SLSA", "Salsa", Type.SAUCE));
      repo.save(new Ingredient("SRCR", "Sour Cream", Type.SAUCE));
    };
  }

  @Bean
  ApplicationRunner dataLoaderUser(UserRepository repo, PasswordEncoder encoder) {
    return args -> {
      repo.save(User.builder().username("taco").password(encoder.encode("password")).build());
    };
  }
}
