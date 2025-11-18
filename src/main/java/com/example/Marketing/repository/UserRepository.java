package com.example.Marketing.repository;

import com.example.Marketing.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional; // <-- 1. IMPORTA ESTO

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    // --- 2. AÑADE ESTE MÉTODO ---
    // (Equivalente al 'findByUsername' del maestro)
    Optional<User> findByEmail(String email);
    
}