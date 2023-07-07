package com.example.oauth_jdbc_authentication.Config;

import com.example.oauth_jdbc_authentication.Model.Users;
import com.example.oauth_jdbc_authentication.Repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class Oauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public Oauth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        Users users = userRepository.findByEmail(oAuth2User.getAttribute("email"));
        if (users == null){
        users = new Users();
        users.setEmail(oAuth2User.getAttribute("email"));
        }
//        users.setEmail(oAuth2User.getAttribute("name"));
//        for (String s : oAuth2User.getAttributes().keySet())
//            System.out.println(s + " : " + oAuth2User.getAttributes(s));
//        return super.loadUser(userRequest);
//        users.set
        users = userRepository.save(users);
        return users;
    }
}
