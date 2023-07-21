package com.example.tacos.listener;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class CustomAuthenticationEventListener {
	@EventListener
	public void onSuccess(AuthenticationSuccessEvent success) {
		log.info("AuthenticationSuccessEvent");
	}

	@EventListener
	public void onFailure(AbstractAuthenticationFailureEvent failures) {
		log.info("AbstractAuthenticationFailureEvent");
	}
}
