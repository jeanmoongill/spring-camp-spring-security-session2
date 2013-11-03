package org.springcamp.security.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class CommonControllerAdvice {
	private static final Logger log = LoggerFactory.getLogger(CommonControllerAdvice.class);
	
	@ExceptionHandler(Exception.class)
	public void exceptionHandler(Exception e) {
		log.error("error!!!", e);
	}
	
}
