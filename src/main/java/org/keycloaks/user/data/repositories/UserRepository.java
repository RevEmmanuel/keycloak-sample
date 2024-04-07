package org.keycloaks.user.data.repositories;

import org.keycloaks.user.data.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {

    boolean existsByEmail(String email);

    void deleteById(String userId);

    Optional<User> findByEmail(String email);
}
