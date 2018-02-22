package com.learningjava.rest.spring.front.seguretat;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
@Configuration
public class ConfSeguretat extends WebSecurityConfigurerAdapter{
    @Autowired
    public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("admin").password("yuhu").roles("ADMIN");
        auth.inMemoryAuthentication().withUser("user").password("tuno").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/public/**").permitAll()
                .antMatchers("/rest/api/v1/restaurants").hasRole("ADMIN")
                .and().formLogin()
                .and().httpBasic()
                .and().logout()
                .permitAll()
        ;
    }


}


