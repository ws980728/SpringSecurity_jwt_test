package com.chen.repository;

import com.chen.entity.User;
import org.springframework.data.repository.CrudRepository;

/**
 * author:chen
 */
public interface UserRepository extends CrudRepository<User, Integer> {
    User findByUsername(String username);
}
