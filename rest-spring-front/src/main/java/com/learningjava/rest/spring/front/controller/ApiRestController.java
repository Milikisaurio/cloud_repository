package com.learningjava.rest.spring.front.controller;


import com.learningjava.rest.spring.core.ReadDB;
import com.learningjava.rest.spring.core.Restaurant;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * com.learningjava.rest.spring.front
 * Class
 * By berto. 12/02/2018
 */
@RestController
@RequestMapping(path = "/rest/api/v1")
public class ApiRestController {

    private static final String template = "Hello, %s!";
    private final AtomicLong counter = new AtomicLong();



    @RequestMapping(path = "/restaurants",method = RequestMethod.GET)
    public List<Restaurant> list() {
        ReadDB pollagorda = new ReadDB();
        List<Restaurant> arrData = pollagorda.readRestaurant();
        return arrData;
    }

}
