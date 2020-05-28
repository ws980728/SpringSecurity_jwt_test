package com.chen.controller;

import com.chen.entity.User;
import com.chen.repository.UserRepository;
import com.chen.utils.RestResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * author:chen
 */
@RestController
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/register")
    public RestResponse registerUser(String username, String password){
        User user = new User();
        user.setUsername(username);
        //对密码进行编码
        user.setPassword(bCryptPasswordEncoder.encode(password));
        //不对密码进行编码，存储明文
        //user.setPassword(password);
        user.setRole("ROLE_USER");
        User save = userRepository.save(user);
        return RestResponse.ok().item(save);
    }
}
