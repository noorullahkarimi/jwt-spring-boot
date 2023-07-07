package com.example.oauth_jdbc_authentication.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@Controller
public class UserController {

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

}
