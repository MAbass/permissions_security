package sn.permissions_security.services;

import org.springframework.dao.DataIntegrityViolationException;
import sn.permissions_security.entity.User;

import javax.persistence.EntityNotFoundException;
import java.util.List;

public interface UserService {
    User saveUser(User user) throws DataIntegrityViolationException;
    void addRoleToUser(String username, String role) throws ClassNotFoundException;

    User findByUsername(String username) throws EntityNotFoundException;

    User saveNewUserWithRoles(User user, List<String> roles) throws EntityNotFoundException;
}
