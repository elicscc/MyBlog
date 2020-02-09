package com.zhy.config;

import com.zhy.service.security.CustomUserServiceImpl;
import com.zhy.utils.MD5Util;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author: zhangocean
 * @Date: 2018/6/5 18:45
 * Describe: SpringSecurity配置
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    UserDetailsService customUserService(){
        return new CustomUserServiceImpl();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserService())
            //启动MD5加密
            .passwordEncoder(new PasswordEncoder() {
                MD5Util md5Util = new MD5Util();
                @Override
                public String encode(CharSequence rawPassword) {
                    return md5Util.encode((String) rawPassword);
                }

                @Override
                public boolean matches(CharSequence rawPassword, String encodedPassword) {
                    return encodedPassword.equals(md5Util.encode((String)rawPassword));
                }
            });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/","/index","/aboutme","/archives","/categories","/friendlylink","/tags","/update","/yesterday","/ali","/today","/mylove")
                .permitAll()
                .antMatchers("/editor","/user").hasAnyRole("USER")
                .antMatchers().hasAnyRole("ADMIN")
                .antMatchers("/superadmin","/myheart").hasAnyRole("SUPERADMIN")
                .and()
               // .formLogin().loginPage("/login").failureUrl("/login?error").defaultSuccessUrl("/")
                .formLogin().loginPage("/login").failureUrl("/login?error").defaultSuccessUrl("https://blog.ccstay.com")
                .and()
                .headers().frameOptions().sameOrigin()
                .and()
                .logout().logoutUrl("/logout").logoutSuccessUrl("https://blog.ccstay.com");

        http.csrf().disable();
    }
}
