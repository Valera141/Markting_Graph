package com.example.Marketing.repository;

import com.example.Marketing.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    // Método para buscar un rol por su nombre (ej. "ADMIN")
    Optional<Role> findByName(String name);
}