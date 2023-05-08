package com.example.tacos.dao;

import org.springframework.data.repository.CrudRepository;

import com.example.tacos.model.TacoOrder;

public interface OrderRepository extends CrudRepository<TacoOrder, String> {
}
