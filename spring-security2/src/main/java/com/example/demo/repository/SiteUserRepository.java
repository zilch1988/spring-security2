package com.example.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.model.SiteUser;

public interface SiteUserRepository extends JpaRepository<SiteUser, Long> {
	SiteUser findByUsername(String usernmae);
	
	boolean existsByUsername(String username);
}
