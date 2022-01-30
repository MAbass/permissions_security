package sn.permissions_security.controller;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import sn.permissions_security.controller.forms.AuthRequest;
import sn.permissions_security.controller.forms.CreateNewUser;
import sn.permissions_security.entity.CustomUserDetails;
import sn.permissions_security.entity.User;
import sn.permissions_security.security.CustomAuthenticationProvider;
import sn.permissions_security.services.UserService;
import sn.permissions_security.utils.JwtUtils;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@Slf4j
@RequiredArgsConstructor
public class UserController {

    private final CustomAuthenticationProvider authenticationProvider;
    private final JwtUtils jwtUtils;
    private final UserService userService;

    @PreAuthorize("hasPermission('USER', 'CREATE')")
    @PostMapping("/register/user")
    public ResponseEntity<?> createUser(@RequestBody @Valid CreateNewUser user) {
        try {
            User userCreated = userService.saveUser(new User(null,
                    user.getUsername(), user.getPassword(), null, null, null, null));
            for (String role : user.getRoles()) {
                userService.addRoleToUser(userCreated.getUsername(), role);
            }
            return ResponseEntity.ok("User created");
        } catch (ClassNotFoundException | DataIntegrityViolationException exception) {
            exception.printStackTrace();
            Map<String, String> response = new HashMap<>();
            response.put("error:", exception.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginPage(@Valid @RequestBody AuthRequest authRequest) {
        Map<String, String> response = new HashMap<>();
        try {
            UsernamePasswordAuthenticationToken token =
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword());
            Authentication authentication = authenticationProvider.authenticate(token);
            List<String> authorities = authentication.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            String access_token = jwtUtils.generateToken(authentication.getName(), authorities, "ACCESS_TOKEN");
            String refresh_token = jwtUtils.generateToken(authentication.getName(), authorities, "REFRESH_TOKEN");
            response.put("access_token", access_token);
            response.put("refresh_token", refresh_token);
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException exception) {
            response.put("error", exception.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }
    }
}
