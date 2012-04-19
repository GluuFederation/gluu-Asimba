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
	language="java" isErrorPage="true" isELIgnored ="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">

<c:if test="${requestScope.sessionLocale != null}">
	<fmt:setLocale value="${requestScope.sessionLocale}"/>
</c:if>

<fmt:setBundle basename="com.alfaariss.oa.profile.aselect.resources.errors" 
	var="errors" scope="request"/>
<fmt:setBundle basename="com.alfaariss.oa.profile.aselect.resources.warnings" 
	var="warnings" scope="request"/>  
<fmt:setBundle basename="com.alfaariss.oa.profile.aselect.resources.messages" 
	var="messages" scope="request"/> 

<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<link rel="stylesheet" href="${pageContext.request.contextPath}/static/css/default.css" type="text/css" />
		<link rel="shortcut icon" href="${pageContext.request.contextPath}/static/images/logo.ico"  type="image/x-icon" />
		<title>
			<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>			
		</title>
	</head>
	<body>
		<div id="container">
			<div id="header">
				<img 
					src="${pageContext.request.contextPath}/<fmt:message bundle='${messages}' key='page_logo' />" 
					alt="<fmt:message bundle='${messages}' key='page_logo_alt' />" 
					id="headerlogo" />
				<h1><fmt:message bundle='${messages}' key='page_title'/></h1>
			</div>
			<div id="subheader">
				<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
			</div>		
			<div id="content">	
				<div id="contentError" class="error">
					<h2>
						<c:choose>
							<c:when test="${requestScope.userEvent != null}">
								<fmt:message bundle="${errors}" key="${requestScope.userEvent}"/>
							</c:when>
							<c:otherwise>
								<fmt:message bundle="${messages}" key="default_error_message" />
							</c:otherwise>
						</c:choose>
					</h2>
				</div>
				<div id="contentWarning" class="warning">
					<c:if test="${requestScope.details != null && fn:length(requestScope.details) > 0}">				
						<ul>
							<c:forEach items="${requestScope.details}" var="warning">
								<li><fmt:message bundle="${warnings}" key="${warning}" /></li>
							</c:forEach>
						</ul>					
					</c:if>	
					<p>			
						<c:if test="${requestScope.requestor.friendlyName != null}">
							<fmt:message bundle="${messages}" key="error_detail">
								<fmt:param><c:out value="${requestScope.requestor.friendlyName}"/></fmt:param>
							</fmt:message>
						</c:if>
						<c:choose>
							<c:when test="${requestScope.requestor.properties['maintainer_email'] != null}">
								<fmt:message bundle="${messages}" key="error_action_link" >
									<fmt:param><c:out value="${requestScope.requestor.properties['maintainer_email']}"/></fmt:param>
								</fmt:message>
							</c:when>
							<c:otherwise>
								<fmt:message bundle="${messages}" key="error_action" />
							</c:otherwise>
						</c:choose>
					</p>	
				</div>
			</div>
			<div id="footer">
				<div id="footer1">
					<c:out value="${requestScope.serverInfo.friendlyName}"/> (<c:out value="${requestScope.serverInfo.ID}"/>)
				</div>
				<div id="footer2">	
					<a href="http://www.asimba.org">Asimba</a> - Serious Open Source SSO				
				</div>
			</div>
		</div>
	</body>
</html>
