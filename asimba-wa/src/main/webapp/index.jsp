<%--
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see www.gnu.org/licenses
 * 
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
--%>
<%@ page contentType="text/html; charset=UTF-8" 
	language="java" isErrorPage="false" isELIgnored ="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<c:if test="${requestScope.sessionLocale != null}">
	<fmt:setLocale value="${requestScope.sessionLocale}"/>
</c:if>
<fmt:setBundle 
	basename="com.alfaariss.oa.resources.messages" 
	var="messages" scope="request"/> 
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<link rel="stylesheet" href="static/css/default.css" type="text/css">
		<link rel="shortcut icon" href="static/images/logo.ico"  type="image/x-icon" />
		<title>
			<fmt:message bundle='${messages}' key='page_title'/>					
		</title>
	</head>
	<body>
		<div id="header">
			<img 
				src="<fmt:message bundle='${messages}' key='page_logo' />" 
				alt="<fmt:message bundle='${messages}' key='page_logo_alt' />" 
				id="headerlogo">
			<h1><fmt:message bundle='${messages}' key='page_title'/></h1>
		</div>
		<div id="subheader">
			<fmt:message bundle='${messages}' key='page_subtitle'/>
		</div>
		<div id="content">	
			<div>
				<p>
					<fmt:message bundle='${messages}' key='welcome'/>
				</p>
			</div>
		</div>
		<div id="footer">
			<div id="footer1">
				&nbsp;
			</div>
			<div id="footer2">	
				<a href="http://www.asimba.org">Asimba</a> - Serious Open Source SSO				
			</div>
		</div>
	</body>	 
</html>
