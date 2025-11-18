package com.example.Marketing.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserLoginResponse {
    private String token; // El token JWT
    private String fullName;
}