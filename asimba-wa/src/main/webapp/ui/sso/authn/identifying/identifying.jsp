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
	language="java" isELIgnored ="false"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<c:if test="${requestScope.sessionLocale != null}">
	<fmt:setLocale value="${requestScope.sessionLocale}"/>
</c:if>
<fmt:setBundle 
	basename="com.alfaariss.oa.authentication.identifying.resources.warnings" 
	var="warnings" scope="request"/> 
<fmt:setBundle 
	basename="com.alfaariss.oa.authentication.identifying.resources.messages" 
	var="messages" scope="request"/> 
<fmt:setBundle 
	basename="com.alfaariss.oa.authentication.identifying.resources.errors" 
	var="errors" scope="request"/>	
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<link rel="stylesheet" href="${pageContext.request.contextPath}/static/css/default.css" type="text/css">
		<link rel="shortcut icon" href="${pageContext.request.contextPath}/static/images/logo.ico"  type="image/x-icon" />
		<script type="text/javascript">
		
			//Focus on field
			function autoFocus()
			{
				document.getElementById('user_id').focus();				
			}
					
		</script>				
		<title>
			<fmt:message bundle="${messages}" key="identifying_page_title">
				<fmt:param>
					<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
				</fmt:param>
				<fmt:param>
					<c:out value="${requestScope.methodFriendlyName}" />
				</fmt:param>
			</fmt:message>		
		</title>
	</head>
	<body onLoad="autoFocus()">
		<div id="container">
			<div id="header">
				<img 
					src="${pageContext.request.contextPath}/<fmt:message bundle='${messages}' key='page_logo' />" 
					alt="<fmt:message bundle='${messages}' key='page_logo_alt' />" 
					id="headerlogo">
				<h1><fmt:message bundle='${messages}' key='page_title'/></h1>
			</div>
			<div id="subheader">
				<c:out value="${requestScope.serverInfo.organization.friendlyName}"/>
			</div>		
			<div id="content">			
				<div id="contentHeader">		
					<h2>
						<c:out value="${requestScope.methodFriendlyName}" />
					</h2>
				</div>
				<c:if test="${requestScope.userEvent != null}">
					<div id="contentError" class="warning">				
						<ul>
							<li><fmt:message bundle="${errors}" key="${requestScope.userEvent}"/></li>
						</ul>						
					</div>
				</c:if>				
				<c:if test="${requestScope.details != null && fn:length(requestScope.details) > 0}">
					<div id="contentWarning" class="warning">				
						<ul>
							<c:forEach items="${requestScope.details}" var="warning">
								<li><fmt:message bundle="${warnings}" key="${warning}" /></li>
							</c:forEach>
						</ul>							
					</div>
				</c:if>	
				<div id="contentMain">	
					<form id="identifyingForm" class="oaForm" action="${pageContext.request.contextPath}/sso/web" method="post" name="login">	
						<fieldset>
		  					<legend><fmt:message bundle="${messages}" key="user_id_message"/></legend>
		  					<div>			
								<input type="hidden" name="asid" value='<c:out value="${requestScope.asid}"/>'>				
								<label><fmt:message bundle="${messages}" key="user_id_label"/></label>		
								<input class="oa" type="text" id="user_id" name="user_id" size="30">
							</div>
							<div>
								<label></label>
								<input type="submit" name="login" 
									value='<fmt:message bundle="${messages}" key="login_button"/>'>
								<input type="submit" name="cancel" 
									value='<fmt:message bundle="${messages}" key="cancel_button"/>'>
							</div>
						</fieldset>
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