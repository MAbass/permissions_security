package sn.permissions_security.services.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import sn.permissions_security.entity.CustomUserDetails;
import sn.permissions_security.entity.Privilege;
import sn.permissions_security.entity.User;
import sn.permissions_security.repository.PrivilegeRepository;
import sn.permissions_security.repository.UserRepository;
import sn.permissions_security.services.UserService;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(rollbackOn = EntityNotFoundException.class)
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;
    private final PrivilegeRepository privilegeRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
        return new CustomUserDetails(user);

    }

    @Override
    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public void addRoleToUser(String username, String role) throws ClassNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new ClassNotFoundException("The user is not found"));

        Privilege privilege = privilegeRepository.findByName(role).orElseThrow(() -> new ClassNotFoundException("The privilege is not found"));
        Collection<Privilege> privileges = user.getPrivileges();
        if (privileges == null) {
            user.setPrivileges(new HashSet<>(Collections.singleton(privilege)));
        } else {
            privileges.add(privilege);
            user.setPrivileges(privileges);
        }
        userRepository.save(user);

    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(() -> new EntityNotFoundException("User is not found"));
    }

    @Override
    public User saveNewUserWithRoles(User user, List<String> roles) {
        User userSaved = this.saveUser(user);
        Collection<Privilege> privileges = roles.stream()
                .map(role -> this.privilegeRepository.findByName(role).orElseThrow(() -> new EntityNotFoundException("Privilege is not found")))
                .collect(Collectors.toList());
        userSaved.setPrivileges(privileges);
        return this.saveUser(user);
    }


}
