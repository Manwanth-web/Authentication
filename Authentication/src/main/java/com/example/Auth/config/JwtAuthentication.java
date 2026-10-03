package com.example.Auth.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.Auth.service.JwtUtil;
import com.example.Auth.service.UserDetailsServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthentication extends OncePerRequestFilter {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		String authorizationHeader = request.getHeader("Authorization");

		logger.info("Authorization Header: " + authorizationHeader);

		String username = null;
		String jwt = null;

		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

			jwt = authorizationHeader.substring(7);

			logger.info("Extracted JWT: " + jwt);

			try {
				username = jwtUtil.extractUsername(jwt);
				logger.info("Extracted Username: " + username);
			} catch (Exception e) {
				logger.info("Invalid JWT token");
			}
		}

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

			logger.info("Loaded UserDetails: " + userDetails.getUsername());

			try {

				if (jwtUtil.validateToken(jwt, userDetails.getUsername())) {

					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
							userDetails, null, userDetails.getAuthorities());

					authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

					SecurityContextHolder.getContext().setAuthentication(authenticationToken);

					logger.info("Authentication set in context");

				} else {

					logger.info("JWT token validation failed");
				}

			} catch (Exception e) {

				logger.info("JWT token validation failed");
			}

		} else {

			logger.info("Username not found or authentication already set");
		}

		chain.doFilter(request, response);
	}
}