package com.mrdevv.controllers;


import com.mrdevv.controllers.request.CreateUserDTO;
import com.mrdevv.models.ERole;
import com.mrdevv.models.RoleEntity;
import com.mrdevv.models.UserEntity;
import com.mrdevv.repositories.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class PrincipalController {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/hello")
    public String hello() {
        return "Hello World Not Secured";
    }

    @GetMapping("/helloSecured")
    public String helloSecured() {
        return "Hello World Secured";
    }

    @PostMapping("/createUser")
    ResponseEntity<?> createUser(@Valid @RequestBody CreateUserDTO createUserDTO) {

        Set<RoleEntity> roles = createUserDTO.getRoles().stream()
                .map(rol -> RoleEntity.builder()
                        .name(ERole.valueOf(rol))
                        .build())
                .collect(Collectors.toSet());

        UserEntity userEntity = UserEntity.builder().
                username(createUserDTO.getUsername())
                .password(passwordEncoder.encode(createUserDTO.getPassword()))
                .email(createUserDTO.getEmail())
                .roles(roles)
                .build();

        userRepository.save(userEntity);

        return ResponseEntity.ok(userEntity);
    }

    @DeleteMapping("/deleteUser/{id}")
    String deleteUser(@PathVariable Long id){
        userRepository.deleteById(id);
        return "Se ha borrado el user con el id ".concat(id.toString());
    }

}
