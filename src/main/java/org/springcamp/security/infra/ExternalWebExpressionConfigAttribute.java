package org.springcamp.security.infra;

import org.springframework.expression.Expression;
import org.springframework.security.access.ConfigAttribute;

class ExternalWebExpressionConfigAttribute implements ConfigAttribute {
	private static final long serialVersionUID = 1L;
	private final Expression authorizeExpression;

    public ExternalWebExpressionConfigAttribute(Expression authorizeExpression) {
        this.authorizeExpression = authorizeExpression;
    }

    Expression getAuthorizeExpression() {
        return authorizeExpression;
    }

    public String getAttribute() {
        return null;
    }

    @Override
    public String toString() {
        return authorizeExpression.getExpressionString();
    }
}