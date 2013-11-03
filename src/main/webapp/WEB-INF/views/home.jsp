<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ page contentType="text/html; UTF-8" pageEncoding="UTF-8"%>
<html>
<head>
	<title>Home</title>
</head>
<body>
<sec:authorize access="!isAuthenticated()">
<h2><a href="/spring_security_login">Local Login</a></h2>
</sec:authorize>
<sec:authorize access="isAuthenticated()">
	<h2><a href="/logout">Logout</a></h2>
</sec:authorize>
<hr/> 
<h3>principal : <sec:authentication property="principal" /></h3> 
<h3>details : <sec:authentication property="details" /></h3> 
<h3>authorities : <sec:authentication property="authorities" /></h3> 
<hr/>
<sec:authorize access="hasRole('facebook')">
<h1>
	Facebook 인증 했을 때만 보여지는 화면입니다.   
</h1>
</sec:authorize>
<sec:authorize access="hasRole('member')">
<h1>
	member 권한가진 사람만 인증 했을 때만 보여지는 화면입니다.   
</h1>
</sec:authorize>
<hr/>
<ul>
	<li><a href="member/">member</a></li>
	<li><a href="school/">school</a></li>
</ul>
</body>
</html>
