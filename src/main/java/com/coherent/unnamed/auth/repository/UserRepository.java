package com.coherent.unnamed.auth.repository;

import com.coherent.unnamed.auth.model.enity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

 /*   User findByEmailAndIsActive(String email, Object one);*/

    User findByEmailAndIsActive(String email, Object one);

 /*   void updateBlockUser(@Param(value = "userId")long userId);*/
}