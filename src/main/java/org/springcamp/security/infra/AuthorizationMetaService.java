package org.springcamp.security.infra;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

public class AuthorizationMetaService {
	private JdbcTemplate jdbc;
	private String resourceQuery;

	public void setJdbc(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	public void setResourceQuery(String resourceQuery) {
		this.resourceQuery = resourceQuery;
	}

	public List<AuthorizationMeta> getRepositoryList() {
		return jdbc.query(resourceQuery, new RowMapper<AuthorizationMeta>() {
			public AuthorizationMeta mapRow(ResultSet rs, int rowNum)
					throws SQLException {
				String path = rs.getString(1);
				String expression = rs.getString(2);
				String channel = rs.getString(3);
				AuthorizationMeta resource = new AuthorizationMeta(path, expression, channel);
				return resource;
			}
		});
	}

	/**
	 * DB에서 조회한 데이터로 path, expression Map을 생성
	 * 
	 * @return
	 */
	public Map<String, String> findAllAuthMetaData() {
		Map<String, String> resourceMap = new LinkedHashMap<String, String>();
		for (AuthorizationMeta repo : getRepositoryList()) {
			String path = repo.getPath();
			String expression = repo.getExpression();
			if (resourceMap.containsKey(path)) {
				String value = resourceMap.get(path);
				resourceMap.put(path, value + " or " + expression);
			} else {
				resourceMap.put(path, expression);
			}
		}
		return resourceMap;
	}

	/**
	 * 권한 Expression 문자열 생성
	 * 
	 * @param role
	 * @return
	 */
	private String makeHasRole(String role) {
		String result = "";
		if (role.contains("hasRole(") || !role.startsWith("ROLE_")) {
			result = role;
		} else {
			result = String.format("hasRole('%s')", role);
		}
		return result;
	}
}