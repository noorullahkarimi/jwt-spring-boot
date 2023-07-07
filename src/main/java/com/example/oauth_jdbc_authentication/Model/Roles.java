package com.example.oauth_jdbc_authentication.Model;

import com.example.oauth_jdbc_authentication.enums.Authority;

import javax.persistence.*;
import java.util.List;

@Entity
public class Roles {

    @Id
    @GeneratedValue
    private long id;
    private String name;

    @ElementCollection(targetClass = Authority.class,fetch = FetchType.EAGER)
    private List<Authority> authorities;

    public Roles() {}

    public Roles(long id, String name) {
        this.id = id;
        this.name = name;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<Authority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<Authority> authorities) {
        this.authorities = authorities;
    }
}
