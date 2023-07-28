package com.jessica.taco.client.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import com.jessica.taco.client.entity.Ingredient;
import com.jessica.taco.client.service.IngredientService;

@RestController
@RequestMapping(path = "/ingredients", produces = "application/json")
public class IngredientController {

  private IngredientService ingredientService;

  IngredientController(IngredientService ingredientService) {
    this.ingredientService = ingredientService;
  }

  @GetMapping
  public Iterable<Ingredient> allIngredients() {
    return ingredientService.findAll();
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public Ingredient saveIngredient(@RequestBody Ingredient ingredient) {
    return ingredientService.addIngredient(ingredient);
  }

}
