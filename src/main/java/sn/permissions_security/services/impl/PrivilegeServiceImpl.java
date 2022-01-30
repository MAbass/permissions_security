package sn.permissions_security.services.impl;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Service;
import sn.permissions_security.entity.Privilege;
import sn.permissions_security.repository.PrivilegeRepository;
import sn.permissions_security.services.PrivilegeService;

@Service
@AllArgsConstructor
public class PrivilegeServiceImpl implements PrivilegeService {

    private final PrivilegeRepository privilegeRepository;

    @Override
    public Privilege addPrivilege(Privilege privilege) {
        return privilegeRepository.save(privilege);
    }
}
