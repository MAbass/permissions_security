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

import javax.transaction.Transactional;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(rollbackOn = ClassNotFoundException.class)
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;
    private final PrivilegeRepository privilegeRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            return new CustomUserDetails(user.get());
        } else {
            throw new UsernameNotFoundException(username);
        }

    }

    @Override
    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public void addRoleToUser(String username, String role) throws ClassNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);

        if (user.isPresent()) {
            Optional<Privilege> privilege = privilegeRepository.findByName(role);
            if (privilege.isPresent()) {
                Collection<Privilege> privileges = user.get().getPrivileges();
                if (privileges == null) {
                    user.get().setPrivileges(new HashSet<>(Collections.singleton(privilege.get())));
                } else {
                    privileges.add(privilege.get());
                    user.get().setPrivileges(privileges);
                }
                userRepository.save(user.get());

            } else {
                throw new ClassNotFoundException("The role is not found");
            }
        } else {
            throw new ClassNotFoundException("The user is not found");
        }
    }

    @Override
    public User findByUsername(String username) throws ClassNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            return user.get();
        } else {
            throw new ClassNotFoundException("The user is not found");
        }
    }

    @Override
    public User saveNewUserWithRoles(User user, List<String> roles) throws ClassNotFoundException {
        AtomicReference<Boolean> error = new AtomicReference<>(false);
        User userSaved = this.saveUser(user);
        Collection<Privilege> privileges = roles.stream().map(role -> {
            Optional<Privilege> privilege = this.privilegeRepository.findByName(role);
            if (privilege.isPresent()) {
                return privilege.get();
            } else {
                error.set(true);
                return null;
            }
        }).collect(Collectors.toList());
        if (error.get())
            throw new ClassNotFoundException("The role is not found");
        userSaved.setPrivileges(privileges);
        return this.saveUser(user);
    }


}
