package com.example.Marketing.configuration;

import com.example.Marketing.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfiguration {

    private final UserRepository userRepository;

    /**
     * Este Bean le dice a Spring Security cómo cargar un usuario.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username) // <-- Usamos tu método findByEmail
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con email: " + username));
    }

    /**
     * --- ESTE ES EL BLOQUE CORREGIDO ---
     * * Este Bean es el "proveedor" de autenticación.
     * Usamos el constructor moderno para pasar el PasswordEncoder
     * y luego configuramos el UserDetailsService.
     */
    @SuppressWarnings("deprecation")
    @Bean
    public AuthenticationProvider authenticationProvider() {
        // 1. Llama al constructor que SÍ incluye el PasswordEncoder
        // (Esto elimina la primera advertencia)
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(passwordEncoder());
        
        // 2. Establece el UserDetailsService
        // (Esto elimina la segunda advertencia)
        authProvider.setUserDetailsService(userDetailsService());
        
        return authProvider;
    }

    /**
     * Este Bean (que usa el maestro) provee el 'PasswordEncoder'.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Este Bean (que usa el maestro) provee el 'AuthenticationManager',
     * que usaremos en el endpoint de /login.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}