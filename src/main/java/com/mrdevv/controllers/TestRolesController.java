package com.mrdevv.controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
public class TestRolesController {

    @GetMapping("/accessAdmin")
    @PreAuthorize("hasRole('ADMIN')")
    public String accessAdmin(){
        return "Hola has accedido con rol de ADMIN";
    }

    @GetMapping("/accessUser")
    @PreAuthorize("hasRole('USER')")
    public String accessUser(){
        return "Hola has accedido con rol de USER";
    }

    @GetMapping("/accessInvited")
    @PreAuthorize("hasRole('INVITED')")
    public String accessInvited(){
        return "Hola has accedido con rol de INVITED";
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGenericException(Exception exception, HttpServletRequest request){
        Map<String, String> apiError = new HashMap<>();
        apiError.put("message", exception.getLocalizedMessage());
        apiError.put("timestamp", new Date().toString());
        apiError.put("url", request.getRequestURL().toString());
        apiError.put("http-method", request.getMethod());

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

        if (exception instanceof AccessDeniedException){
            status = HttpStatus.FORBIDDEN;
        }

        return ResponseEntity.status(status).body(apiError);
    }

}
