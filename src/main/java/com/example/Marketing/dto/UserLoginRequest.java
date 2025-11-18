package com.example.Marketing.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserLoginRequest {
    @Email
    @NotBlank
    private String email; // Usaremos email como username

    @NotBlank
    private String password;
}