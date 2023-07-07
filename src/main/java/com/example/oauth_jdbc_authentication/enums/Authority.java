package com.example.oauth_jdbc_authentication.enums;

import org.springframework.security.core.GrantedAuthority;

public enum Authority implements GrantedAuthority {

    OP_ADMIN,
    OP_USER;

    @Override
    public String getAuthority() {
        return this.name();
    }
}
