package com.example.oauth_jdbc_authentication.Config;

import com.example.oauth_jdbc_authentication.enums.Authority;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    DefaultRedirectStrategy redirect = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        if (authentication.getAuthorities().contains(Authority.OP_ADMIN)) {

            redirect.sendRedirect(request, response, "/admin");

        } else if (authentication.getAuthorities().contains(Authority.OP_USER)) {

            redirect.sendRedirect(request, response, "/user");

        } else {

            redirect.sendRedirect(request, response, "/");

        }
    }
}