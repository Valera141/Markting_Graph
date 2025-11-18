package com.example.Marketing.service;

import com.example.Marketing.dto.UserLoginRequest;
import com.example.Marketing.dto.UserLoginResponse;

public interface UserService {
    UserLoginResponse login(UserLoginRequest request);
}