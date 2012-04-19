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
	language="java" isErrorPage="false" isELIgnored ="false" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<form action="" method="post" id="userinfo_form" name="userinfo_form">
	<fieldset>
		<legend><fmt:message bundle="${messages}" key="info_user_legend"/>	</legend>
	
		<div>
			<label><fmt:message bundle="${messages}" key="info_user_id_label"/></label>
			<input type="text" disabled value="<c:out value='${requestScope.userInfo.user.ID}'/>">						
		</div>				
		
		<div>
			<label><fmt:message bundle="${messages}" key="info_user_organization_label"/></label>
			<c:choose>
				<c:when test='${requestScope.userInfo.user.organization eq requestScope.serverInfo.organization.ID}'>
					<input type="text" disabled value="<c:out value='${requestScope.serverInfo.organization.friendlyName}'/>">
				</c:when>
				<c:otherwise>
					<input type="text" disabled value="<c:out value='${requestScope.userInfo.user.organization}'/>">
				</c:otherwise>
			</c:choose>
		</div>
	</fieldset>
	<fieldset>
		<legend>
			<fmt:message bundle="${messages}" key="info_authn_legend"/>
		</legend>
		<div>
			<label><fmt:message bundle="${messages}" key="info_authn_tgt_exp_label"/></label>
			<input type="text" disabled value="<fmt:formatDate type="both" dateStyle="long" 
				value="${requestScope.userInfo.expireTime}"/>">
		</div>
		
		<div>
			<br>
		</div>
		
		<div>
			<label><fmt:message bundle="${messages}" key="info_authn_requestors_label"/></label>	
			<c:choose>
				<c:when test="${fn:length(requestScope.userInfo.requestors) > 0}">					
					<ul>
						<c:forEach var="requestor" 
							items="${requestScope.userInfo.requestors}">
							<li><c:out value='${requestor.friendlyName}'/></li>							
						</c:forEach>
					</ul>
				</c:when>
				<c:otherwise>
					<br>
				</c:otherwise>
			</c:choose>					
		</div>

		<div>
			<br>
		</div>
		
		<div>
			<label><fmt:message bundle="${messages}" key="info_authn_authnprofiles_label"/></label>
			<ul>
				<c:forEach var="authnProfile" 
					items="${requestScope.userInfo.authnProfiles}">
					<li>
						<c:out value='${authnProfile.friendlyName}'/>
						<ul>
							<c:forEach var="authnMethod" 
								items="${authnProfile.authenticationMethods}">
								<li>
									<c:out value='${authnMethod.ID}'/>
								</li>
							</c:forEach>
						</ul>
					</li>							
				</c:forEach>
			</ul>
		</div>
	</fieldset>
		
	<c:if test="${fn:length(requestScope.userInfo.userAttributes) > 0}">
		<fieldset>
			<legend>
				<fmt:message bundle="${messages}" key="info_attributes_legend"/>
			</legend>
			<c:forEach var="attribute" items="${requestScope.userInfo.userAttributes}">
				<div>
					<label class="attributeName" title="<c:out value='${attribute.name}'/>"><c:out value='${attribute.name}'/>:</label>
					<input type="text" disabled class="attributeValue" 
						value="<c:out value='${attribute.value}'/>">
				</div>							
			</c:forEach>
		</fieldset>	
	</c:if>
</form>