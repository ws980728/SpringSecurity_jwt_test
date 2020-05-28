package com.chen.controller;

import com.chen.utils.RestResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * author:chen
 */
@RestController
public class TaskController {

    @PostMapping
    @PreAuthorize("hasRole('ROLE_USER')")
    public RestResponse welcome(){
        return RestResponse.ok("欢迎~~~");
    }

}
