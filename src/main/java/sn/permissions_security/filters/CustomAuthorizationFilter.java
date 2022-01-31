package sn.permissions_security.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import sn.permissions_security.entity.User;
import sn.permissions_security.exceptions.BadRightsException;
import sn.permissions_security.services.UserService;
import sn.permissions_security.utils.JwtUtils;

import javax.persistence.EntityNotFoundException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private final List<String> authList;
    private final UserService userService;
    private final JwtUtils jwtUtils;

    public CustomAuthorizationFilter(List<String> authList, UserService userService, JwtUtils jwtUtils) {
        this.authList = authList;
        this.userService = userService;
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        AtomicBoolean wasPublicUrl = new AtomicBoolean(false);
        // authorize public url
        authList.forEach(path -> {
            if (path.contains(request.getServletPath())) {
                try {
                    filterChain.doFilter(request, response);
                    wasPublicUrl.set(true);
                } catch (IOException | ServletException e) {
                    e.printStackTrace();
                }
            }
        });
        //if url is public, don't continue
        if (wasPublicUrl.get())
            return;
        //if url is private verify the authorization
        try {
            //processing for private url
            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                String token = authorizationHeader.substring("Bearer ".length());
                Claims claims = jwtUtils.getClaims(token);
                User user = this.userService.findByUsername(claims.getSubject());
                List<String> roles = (List<String>) claims.get("roles");
                Collection<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                filterChain.doFilter(request, response);
            } else {
                throw new BadRightsException("You don't have permission to access to this resource");
            }
        } catch (EntityNotFoundException | JwtException | BadRightsException exception) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            Map<String, String> errors = new HashMap<>();
            errors.put("error", exception.getMessage());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), errors);
        }

    }
}
