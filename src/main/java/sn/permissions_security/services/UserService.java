package sn.permissions_security.services;

import org.springframework.dao.DataIntegrityViolationException;
import sn.permissions_security.entity.User;

public interface UserService {
    User saveUser(User user) throws DataIntegrityViolationException;
    void addRoleToUser(String username, String role) throws ClassNotFoundException;

    User findByUsername(String username) throws ClassNotFoundException;
}
