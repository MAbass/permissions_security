package sn.permissions_security.services;

import org.springframework.dao.DataIntegrityViolationException;
import sn.permissions_security.entity.User;

import java.util.List;

public interface UserService {
    User saveUser(User user) throws DataIntegrityViolationException;
    void addRoleToUser(String username, String role) throws ClassNotFoundException;

    User findByUsername(String username) throws ClassNotFoundException;

    User saveNewUserWithRoles(User user, List<String> roles) throws ClassNotFoundException;
}
