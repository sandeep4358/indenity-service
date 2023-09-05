package com.javafruit.controller;

import com.javafruit.dto.AuthRequest;
import com.javafruit.entity.UserCredential;
import com.javafruit.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Slf4j
@RequiredArgsConstructor
public class AuthController {
    final private AuthService service;

    final private AuthenticationManager authenticationManager;

    final  private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public String addNewUser(@RequestBody UserCredential user) {
        return service.saveUser(user);
    }

    @PostMapping("/token")
    public String getToken(@RequestBody AuthRequest authRequest) {
      log.info("enter in the get token method.");
        Authentication authenticate = null;
        try {
            log.info("Password : userName :: "+authRequest.getPassword()+ " : "+authRequest.getUsername());
            authenticate = authenticate(authRequest.getUsername(), authRequest.getPassword());
        }catch (Exception e){
            e.printStackTrace();
        }
            
        if (authenticate.isAuthenticated()) {
            log.info("ture");
            return service.generateToken(authRequest.getUsername());
        } else {
            throw new RuntimeException("invalid access");
        }
    }

    @GetMapping("/validate")
    public String validateToken(@RequestParam("token") String token) {
        log.info("enter in the validation.");
        service.validateToken(token);
        return "Token is valid";
    }

    private Authentication authenticate(String username, String password) throws Exception {
        try {
           return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            log.error(e.getMessage());
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            log.error(e.getMessage());
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
