package com.chen.model;

import lombok.Getter;
import lombok.Setter;

/**
 * author:chen
 */
@Setter
@Getter
public class LoginUser {

    private String username;
    private String password;
    private Integer rememberMe;

    public LoginUser(String username,String password){
        this.username=username;
        this.password=password;
    }

}
