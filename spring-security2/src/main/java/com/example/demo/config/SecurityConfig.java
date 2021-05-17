package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.demo.util.Role;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final UserDetailsService userDetailsService;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		// セキュリティ設定を、無視（ignoring）するパスを指定
		// css, js etc.
		web.ignoring().antMatchers("/css/**", "/webjars/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			// 「login」をアクセス可能に
			.antMatchers("/login", "/register").permitAll()
			// 「admin」はadminユーザのみ
			.antMatchers("/admin/**").hasRole(Role.ADMIN.name())
			.anyRequest().authenticated()
			.and()
		// ログイン
		.formLogin()
			// ログイン時のURLを指定
			.loginPage("/login")
			// 認証後にリダイレクトする場所を指定
			.defaultSuccessUrl("/")
			.and()
		// ログアウト
		.logout()
			// ログアウト時のURLを指定
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.and()
		// ブラウザ閉じた後もログイン状態を保持
		.rememberMe();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService)
			.passwordEncoder(passwordEncoder());
	}
}
