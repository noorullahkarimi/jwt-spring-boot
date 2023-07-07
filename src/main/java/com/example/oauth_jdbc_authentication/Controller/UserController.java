package com.example.oauth_jdbc_authentication.Controller;

import com.example.oauth_jdbc_authentication.Model.JwtAuth;
import com.example.oauth_jdbc_authentication.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

@Controller
public class UserController {
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    @Autowired
    public UserController(AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @GetMapping("/login")
    public String login(){
        return "/login.html";
    }

//    @PreAuthorize("hasAnyAuthority('OP_ADMIN_PANEL')")
    @GetMapping("/")
    @ResponseBody
    public String index(){
        return "original page";
    }

    @PreAuthorize("hasAnyAuthority('OP_ADMIN')")
    @GetMapping("/admin")
    @ResponseBody
    public String admin(){
        return "admin page";
    }

    @PreAuthorize("hasAnyAuthority('OP_USER')")
    @GetMapping("/user")
    @ResponseBody
    public String users(){
        return "users page";
    }

    @GetMapping("/error")
    @ResponseBody
    public String error(){
        return "error page";
    }

    @GetMapping("/getCookie")
    @ResponseBody
    public String getCookie(HttpServletRequest request){
        for (Cookie cookie : request.getCookies()){
            System.out.println(cookie.getName()+" : "+cookie.getValue());
        }
        return "cookie page";
    }

    @GetMapping("/info")
    public @ResponseBody Principal info(Principal principal){
        return principal;
    }

    @PostMapping("/jwt/login")
    public @ResponseBody
    ResponseEntity<?> jwtLogin (@RequestBody JwtAuth jwtAuth, HttpServletResponse response){
        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(jwtAuth.getUsername(),jwtAuth.getPassword()));
        }catch (Exception e){
            return  new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        response.addHeader("Authorization", jwtUtils.generateToken(jwtAuth.getUsername()));
        return  new ResponseEntity<>(HttpStatus.OK);
    }
}
