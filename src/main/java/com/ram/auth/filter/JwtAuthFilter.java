package com.ram.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ram.auth.dto.LoginDetail;
import com.ram.auth.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

public class JwtAuthFilter extends OncePerRequestFilter {
    @Autowired
    private AuthenticationManager authenticationManager;

    public JwtAuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("inside cus filter");

        System.out.println(UUID.randomUUID());

        if (!request.getServletPath().equals("/token")) {
            filterChain.doFilter(request, response);
            return;
        }

        System.out.println("inside cus filter");

        ObjectMapper objectMapper = new ObjectMapper();
        LoginDetail loginDetail = objectMapper.readValue(request.getInputStream(), LoginDetail.class);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken
                (loginDetail.getName(), loginDetail.getPassword());

        Authentication authenticate =this.authenticationManager.authenticate(authenticationToken);

        if(authenticate.isAuthenticated()){
            String token= JWTUtil.generateToken(authenticate.getName(),1);
            response.setHeader("Authorization","Bearer "+token);

            String refreshToken=JWTUtil.generateToken(authenticate.getName(),7*24*60);

            Cookie cookie=new Cookie("refreshToken",refreshToken);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            //cookie.setPath();
            cookie.setMaxAge(7*24*60*60);

            response.addCookie(cookie);
        }

    }
}
