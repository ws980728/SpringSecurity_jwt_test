package com.chen.entity;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

/**
 * author:chen
 */
@Entity
@Getter
@Setter
@Table(name = "user_test")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "role")
    private String role;

}
