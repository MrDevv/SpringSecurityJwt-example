package com.mrdevv.security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mrdevv.models.RoleEntity;
import com.mrdevv.models.UserEntity;
import com.mrdevv.security.jwt.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private JwtUtils jwtUtils;

    public JwtAuthenticationFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UserEntity userEntity = null;

        String username = "";
        String password = "";

        try {
            userEntity = new ObjectMapper().readValue(request.getInputStream(), UserEntity.class);
            username = userEntity.getUsername();
            password = userEntity.getPassword();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        return getAuthenticationManager().authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {//Ob
//      Obtenemos el usuario logeado correctamente
        User user = (User) authResult.getPrincipal();
        Set<String> roles = user.getAuthorities().stream().map(role -> {
            return role.getAuthority();
        }).collect(Collectors.toSet());

//      Pasamos el username y los roles al metodo para crear el token
        String token = jwtUtils.generateAccessToken(user.getUsername(), roles);

        response.addHeader("Authorization", token);

        Map<String, Object> httpResponse = new HashMap<>();
        httpResponse.put("token", token);
        httpResponse.put("message", "Autenticacion correcta");
        httpResponse.put("username", user.getUsername());
        httpResponse.put("roles", roles);

        response.getWriter().write(new ObjectMapper().writeValueAsString(httpResponse));
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().flush();
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        Map<String, Object> httpResponse = new HashMap<>();
        httpResponse.put("message", "Username o password incorrectos");
        httpResponse.put("error", failed.getMessage());

        response.getWriter().write(new ObjectMapper().writeValueAsString(httpResponse));
        response.setStatus(401);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    }
}
