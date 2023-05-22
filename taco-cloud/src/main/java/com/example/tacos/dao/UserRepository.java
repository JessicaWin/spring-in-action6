package com.example.tacos.dao;

import org.springframework.data.repository.CrudRepository;

import com.example.tacos.model.User;

public interface UserRepository extends CrudRepository<User, Long> {
	User findByUsername(String username);

}
