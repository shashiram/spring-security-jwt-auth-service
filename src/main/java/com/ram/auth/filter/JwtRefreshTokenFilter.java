package com.ram.auth.filter;

import com.ram.auth.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.swing.text.html.Option;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

public class JwtRefreshTokenFilter extends OncePerRequestFilter {
    private UserDetailsService userDetailsService;

    public JwtRefreshTokenFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!request.getServletPath().equals("/refresh-token")) {
            filterChain.doFilter(request, response);
            return;
        }

        String refreshToken=extractJwtTokenFromRequest(request);

        if(refreshToken==null || !JWTUtil.validateToken(refreshToken)){
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String userName=JWTUtil.getUser(refreshToken);
        UserDetails userDetails=userDetailsService.loadUserByUsername(userName);
        UsernamePasswordAuthenticationToken authenticationToken=new
                UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

        if(authenticationToken.isAuthenticated()){
            String token= JWTUtil.generateToken(authenticationToken.getName(),5);
            response.setHeader("Authorization","Bearer "+token);
        }

    }

    private String extractJwtTokenFromRequest(HttpServletRequest request){
        Cookie[] cookies=request.getCookies();
        if(cookies!=null){
            Optional<Cookie> cookie =Arrays.stream(cookies)
                    .filter(x-> x.getName().equals("refreshToken")).findAny();
            if(cookie.isPresent()){
                return cookie.get().getValue();
            }
        }
        return null;
    }
}
