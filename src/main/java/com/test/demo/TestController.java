package com.test.demo;
/*
 * @author frank
 * @created 16 Mar,2021 - 2:35 PM
 */

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class TestController {

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String getHome(){
        return "html/home.html";
    }
}
