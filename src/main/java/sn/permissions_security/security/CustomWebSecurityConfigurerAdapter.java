package sn.permissions_security.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import sn.permissions_security.filters.CustomAuthorizationFilter;
import sn.permissions_security.services.UserService;
import sn.permissions_security.utils.JwtUtils;

import javax.servlet.http.HttpServletResponse;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class CustomWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    private final CustomAuthenticationProvider customAuthenticationProvider;
    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final CustomPermissionEvaluator permissionEvaluator;

    private static final String[] AUTH_LIST = {
            "/api/login/**",
            "/api/token/refresh/**",
    };

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(customAuthenticationProvider);
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //for username and password auth
        http.cors().disable();
        http.csrf().disable();
        http.authorizeRequests().antMatchers(AUTH_LIST).permitAll();
        http.authorizeRequests().anyRequest().authenticated();
        http.exceptionHandling().authenticationEntryPoint((request, response, ex) -> response.sendError(
                HttpServletResponse.SC_UNAUTHORIZED,
                ex.getMessage()));
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);


        // using for username and password authentication filter
        http.addFilterAfter(new CustomAuthorizationFilter(List.of(AUTH_LIST), userService, jwtUtils), UsernamePasswordAuthenticationFilter.class);
        // handle exception for permissions
        http.exceptionHandling().accessDeniedHandler(new AccessDenied());
    }

    @Override
    public void configure(WebSecurity web) {
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        web.expressionHandler(handler);
    }

}
