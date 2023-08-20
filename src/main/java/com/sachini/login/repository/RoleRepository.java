package com.sachini.login.repository;

import com.sachini.login.enums.ERoles;
import com.sachini.login.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

     Optional<Role> findByName(ERoles name);
}
