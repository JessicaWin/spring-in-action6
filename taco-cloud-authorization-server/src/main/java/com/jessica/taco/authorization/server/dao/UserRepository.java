package com.jessica.taco.authorization.server.dao;

import org.springframework.data.repository.CrudRepository;

import com.jessica.taco.authorization.server.entity.User;

public interface UserRepository extends CrudRepository<User, Long> {
    User findByUsername(String username);

}
