package org.springcamp.security.infra;

import java.io.Serializable;

public class AuthorizationMeta implements Serializable{
	private static final long serialVersionUID = 1L;
	private String path;
	private String expression;
	private String securityChannel;

	public AuthorizationMeta(String path, String expression, String securityChannel) {
		this.path = path;
		this.expression = expression;
		this.securityChannel = securityChannel;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public String getPath() {
		return path;
	}

	public String getExpression() {
		return expression;
	}

	public String getSecurityChannel() {
		return securityChannel;
	}


}