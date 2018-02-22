package com.learningjava.rest.spring.front.controller;

import com.learningjava.rest.spring.core.ReadDB;
import com.learningjava.rest.spring.core.Restaurant;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.ui.Model;


import java.util.ArrayList;
import java.util.List;

@Controller
public class HomeController {
    @RequestMapping("/")
    public String index(Model model) {
        ReadDB pollagorda = new ReadDB();
        List<Restaurant> restaurants = pollagorda.readRestaurant();
        model.addAttribute("restaurants", restaurants);
        return "index";
    }
}