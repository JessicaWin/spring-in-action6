package com.example.tacos.dao;

import java.util.List;
import java.util.Optional;

import com.example.tacos.model.Ingredient;

public interface IngredientRepository {
	List<Ingredient> findAll();

	Optional<Ingredient> findById(String id);

	Ingredient save(Ingredient ingredient);

}