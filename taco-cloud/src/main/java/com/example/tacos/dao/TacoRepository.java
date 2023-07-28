package com.example.tacos.dao;

import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.CrudRepository;

import com.example.tacos.model.Taco;

public interface TacoRepository extends CrudRepository<Taco, Long> {
    List<Taco> findAll(Pageable pageable);
}
