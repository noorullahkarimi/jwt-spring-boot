package com.example.oauth_jdbc_authentication.Model;

import javax.persistence.*;
import java.io.Serializable;
import java.util.*;

import com.example.oauth_jdbc_authentication.Config.Oauth2UserService;
import com.example.oauth_jdbc_authentication.enums.Authority;
import com.example.oauth_jdbc_authentication.enums.UserRoles;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Entity
public class Users implements Serializable, UserDetails, OAuth2User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String password;

    private boolean enabled;

    @Override
    public Map<String, Object> getAttributes() {
        return new HashMap<>();
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (roles != null && !roles.isEmpty()) {
            for (Roles roles : roles)
                authorities.addAll(roles.getAuthorities());
        }else{
            authorities.add(Authority.OP_USER);
        }
        return authorities;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    //    @ElementCollection(targetClass = UserRoles.class, fetch = FetchType.EAGER)
//    @CollectionTable(name = "authorities", joinColumns = @JoinColumn(name = "email", referencedColumnName = "email"))
//    @Enumerated(EnumType.STRING)
//    private List<UserRoles> userRoles;
    @ManyToMany(fetch = FetchType.EAGER)
    private List<Roles> roles;

    public Users() {}

    public Users(Long id, String email, String password) {
        this.id = id;
        this.email = email;
        this.password = password;
    }

    @Override
    public String toString() {
        return "Users{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                '}';
    }

    public List<Roles> getRoles() {
        return roles;
    }

    public void setRoles(List<Roles> roles) {
        this.roles = roles;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
