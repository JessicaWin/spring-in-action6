package com.jessica.taco.client.service;

import com.jessica.taco.client.entity.Ingredient;

public interface IngredientService {
  Iterable<Ingredient> findAll();

  Ingredient addIngredient(Ingredient ingredient);
}
