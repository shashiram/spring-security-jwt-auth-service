package com.ram.auth.filter;

import com.ram.auth.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtValidationFilter extends OncePerRequestFilter {
    private UserDetailsService userDetailsService;
    @Autowired
    public JwtValidationFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String bearerToken =extractJwtTokenFromRequest(request);

        if(bearerToken!=null){
            System.out.println(bearerToken);

            String userName= JWTUtil.getUser(bearerToken);

            UserDetails userDetails=this.userDetailsService.loadUserByUsername(userName);

            UsernamePasswordAuthenticationToken authentication=new
                    UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request,response);

    }

    private String extractJwtTokenFromRequest(HttpServletRequest request){

        String bearerToken =request.getHeader("Authorization");
        if(bearerToken!=null){
            return  bearerToken.substring(7);
        }
        return null;
    }
}
