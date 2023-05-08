package com.example.tacos.dao;

import org.springframework.data.repository.CrudRepository;

import com.example.tacos.model.Ingredient;

public interface IngredientRepository extends CrudRepository<Ingredient, String> {

}