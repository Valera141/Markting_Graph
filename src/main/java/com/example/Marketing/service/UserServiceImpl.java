package com.example.Marketing.service;

import com.example.Marketing.dto.UserLoginRequest;
import com.example.Marketing.dto.UserLoginResponse;
import com.example.Marketing.model.User;
import com.example.Marketing.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Override
    public UserLoginResponse login(UserLoginRequest request) {
        // 1. Valida el usuario y contraseña contra la BD
        // (Usa el AuthenticationProvider que creamos en el Paso 5)
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // 2. Si la autenticación es exitosa, busca al usuario
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        
        // 3. Genera un token JWT para ese usuario
        String token = jwtService.generateToken(user);

        // 4. Devuelve el token y el nombre del usuario
        return UserLoginResponse.builder()
                .token(token)
                .fullName(user.getFullName())
                .build();
    }
}