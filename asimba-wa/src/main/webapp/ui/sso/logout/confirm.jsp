<%--
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2009 Alfa & Ariss B.V.
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
	language="java" isErrorPage="false" isELIgnored="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<c:if test="${requestScope.sessionLocale != null}">
	<fmt:setLocale value="${requestScope.sessionLocale}"/>
</c:if>
<fmt:setBundle
	basename="com.alfaariss.oa.sso.web.profile.logout.resources.messages" 
	var="messages" scope="request"/> 
<fmt:setBundle
	basename="com.alfaariss.oa.sso.web.profile.logout.resources.warnings" 
	var="warnings" scope="request"/>  	
<fmt:setBundle
	basename="com.alfaariss.oa.sso.web.profile.logout.resources.errors" 
	var="errors" scope="request"/> 
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<link rel="stylesheet" href="${pageContext.request.contextPath}/static/css/default.css" type="text/css" />
		<link rel="shortcut icon" href="${pageContext.request.contextPath}/static/images/logo.ico"  type="image/x-icon" />
		<title>
			<fmt:message bundle="${messages}" key="confirm_logout_page_title">
				<fmt:param>
					<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
				</fmt:param>
				<fmt:param>
					<fmt:message bundle='${messages}' key='confirm_logout' />	
				</fmt:param>
			</fmt:message>
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
				<div id="contentHeader">
					<h2>
						<fmt:message bundle='${messages}' key='confirm_logout' />
					</h2>
				</div>
				<div id="contentMain">
					<div id="confirmText">
						<p>
							<fmt:message bundle='${messages}' key='confirm_message'>
								<fmt:param>
									<c:out value="${requestScope.requestor}"/>
								</fmt:param>
							</fmt:message>
						</p>
					</div>
					<div id="userinfo">
						<form action="" method="post" id="userinfo_form" name="userinfo_form">
							<fieldset>
								<legend><fmt:message bundle="${messages}" key="confirm_user_legend"/>	</legend>
							
								<div>
									<label><fmt:message bundle="${messages}" key="confirm_user_id_label"/></label>
									<input type="text" disabled value="<c:out value='${requestScope.user.ID}'/>">						
								</div>				
								
								<div>
									<label><fmt:message bundle="${messages}" key="confirm_user_organization_label"/></label>
									<c:choose>
										<c:when test='${requestScope.user.organization eq requestScope.serverInfo.organization.ID}'>
											<input type="text" disabled value="<c:out value='${requestScope.serverInfo.organization.friendlyName}'/>">
										</c:when>
										<c:otherwise>
											<input type="text" disabled value="<c:out value='${requestScope.user.organization}'/>">
										</c:otherwise>
									</c:choose>
								</div>
							</fieldset>
							<fieldset>
								<legend><fmt:message bundle="${messages}" key='confirm_description'/></legend>
								
								<div>
									<label><fmt:message bundle="${messages}" key='confirm_requestors_label'/></label>
									<c:choose>
										<c:when test="${fn:length(requestScope.requestors) > 0}">					
											<ul>
												<c:forEach var="requestor" 
													items="${requestScope.requestors}">
													<li><c:out value='${requestor.friendlyName}'/></li>							
												</c:forEach>
											</ul>
										</c:when>
										<c:otherwise>
											<br>
										</c:otherwise>
									</c:choose>	
								</div>
							</fieldset>
						</form>
					</div>
										
					<form action="${pageContext.request.contextPath}/sso/logout" method="post" id="logout_form" name="logout_form">
						<c:if test="${requestScope.asid != null}">
							<input type="hidden" name="asid" value='<c:out value="${requestScope.asid}"/>'>
						</c:if>
						<input type="submit" name="confirm" value="<fmt:message bundle='${messages}' key='confirm_logout_button'/>">
					</form>
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