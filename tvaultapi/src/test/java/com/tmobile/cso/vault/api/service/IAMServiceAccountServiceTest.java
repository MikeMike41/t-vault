/** *******************************************************************************
 *  Copyright 2020 T-Mobile, US
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  See the readme.txt file for additional language around disclaimer of warranties.
 *********************************************************************************** */
package com.tmobile.cso.vault.api.service;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import com.google.gson.JsonElement;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.utils.*;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.tmobile.cso.vault.api.common.IAMServiceAccountConstants;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.controller.OIDCUtil;

import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;

@RunWith(PowerMockRunner.class)
@ComponentScan(basePackages = { "com.tmobile.cso.vault.api" })
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@PrepareForTest({ ControllerUtil.class, JSONUtil.class, PolicyUtils.class, OIDCUtil.class })
@PowerMockIgnore({ "javax.management.*", "javax.net.ssl.*", "javax.script.*" })
public class IAMServiceAccountServiceTest {

	@InjectMocks
	IAMServiceAccountsService iamServiceAccountsService;

	@Mock
	private RequestProcessor reqProcessor;

	@Mock
	AccessService accessService;

	String token;

	@Mock
	UserDetails userDetails;

	@Mock
	LdapTemplate ldapTemplate;

	@Mock
	StatusLine statusLine;

	@Mock
	HttpEntity mockHttpEntity;

	@Mock
	CloseableHttpClient httpClient;

	@Mock
	CloseableHttpResponse httpResponse;

	@Mock
	HttpUtils httpUtils;

	@Mock
	PolicyUtils policyUtils;

	@Mock
	OIDCUtil OIDCUtil;

	@Mock
	AppRoleService appRoleService;

	@Mock
	TokenUtils tokenUtils;

	@Mock
	EmailUtils emailUtils;

	@Mock
	IAMServiceAccountUtils iamServiceAccountUtils;

	@Mock
	DirectoryService directoryService;

	@Mock
	AWSAuthService awsAuthService;

	@Mock
	AWSIAMAuthService awsiamAuthService;

	@Before
	public void setUp()
			throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, NoSuchFieldException {
		PowerMockito.mockStatic(ControllerUtil.class);
		PowerMockito.mockStatic(OIDCUtil.class);
		PowerMockito.mockStatic(JSONUtil.class);

		Whitebox.setInternalState(ControllerUtil.class, "log", LogManager.getLogger(ControllerUtil.class));
		Whitebox.setInternalState(OIDCUtil.class, "log", LogManager.getLogger(OIDCUtil.class));
		when(JSONUtil.getJSON(Mockito.any(ImmutableMap.class))).thenReturn("log");
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ReflectionTestUtils.setField(iamServiceAccountsService, "iamSelfSupportAdminPolicyName", "iamportal_admin_policy");
		Map<String, String> currentMap = new HashMap<>();
		currentMap.put("apiurl", "http://localhost:8080/vault/v2/identity");
		currentMap.put("user", "");
		ThreadLocalContext.setCurrentMap(currentMap);
	}

	Response getMockResponse(HttpStatus status, boolean success, String expectedBody) {
		Response response = new Response();
		response.setHttpstatus(status);
		response.setSuccess(success);
		if (!expectedBody.equals("")) {
			response.setResponse(expectedBody);
		}
		return response;
	}

	UserDetails getMockUser(boolean isAdmin) {
		token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		userDetails = new UserDetails();
		userDetails.setUsername("normaluser");
		userDetails.setAdmin(isAdmin);
		userDetails.setClientToken(token);
		userDetails.setSelfSupportToken(token);
		return userDetails;
	}

	private IAMServiceAccount generateIAMServiceAccount(String userName, String awsAccountId, String owner) {
		IAMServiceAccount iamServiceAccount = new IAMServiceAccount();
		iamServiceAccount.setUserName(userName);
		iamServiceAccount.setAwsAccountId(awsAccountId);
		iamServiceAccount.setAwsAccountName("testaccount1");
		iamServiceAccount.setOwnerNtid(owner);
		iamServiceAccount.setOwnerEmail("normaluser@testmail.com");
		iamServiceAccount.setApplicationId("app1");
		iamServiceAccount.setApplicationName("App1");
		iamServiceAccount.setApplicationTag("App1");
		iamServiceAccount.setCreatedAtEpoch(12345L);
		iamServiceAccount.setSecret(generateIAMSecret());
		return iamServiceAccount;
	}

	private List<IAMSecrets> generateIAMSecret() {
		List<IAMSecrets> iamSecrets = new ArrayList<>();
		IAMSecrets iamSecret = new IAMSecrets();
		iamSecret.setAccessKeyId("testaccesskey555");
		iamSecret.setExpiryDateEpoch(7776000000L);
		iamSecrets.add(iamSecret);
		return iamSecrets;
	}

	public String getJSON(Object obj) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			return mapper.writeValueAsString(obj);
		} catch (JsonProcessingException e) {
			return TVaultConstants.EMPTY_JSON;
		}
	}

	private IAMServiceAccountMetadataDetails populateIAMSvcAccMetaData(IAMServiceAccount iamServiceAccount) {

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = new IAMServiceAccountMetadataDetails();
		List<IAMSecretsMetadata> iamSecretsMetadatas = new ArrayList<>();
		iamServiceAccountMetadataDetails.setUserName(iamServiceAccount.getUserName());
		iamServiceAccountMetadataDetails.setAwsAccountId(iamServiceAccount.getAwsAccountId());
		iamServiceAccountMetadataDetails.setAwsAccountName(iamServiceAccount.getAwsAccountName());
		iamServiceAccountMetadataDetails.setApplicationId(iamServiceAccount.getApplicationId());
		iamServiceAccountMetadataDetails.setApplicationName(iamServiceAccount.getApplicationName());
		iamServiceAccountMetadataDetails.setApplicationTag(iamServiceAccount.getApplicationTag());
		iamServiceAccountMetadataDetails.setCreatedAtEpoch(iamServiceAccount.getCreatedAtEpoch());
		iamServiceAccountMetadataDetails.setOwnerEmail(iamServiceAccount.getOwnerEmail());
		iamServiceAccountMetadataDetails.setOwnerNtid(iamServiceAccount.getOwnerNtid());
		if (iamServiceAccount.getSecret() != null) {
			for (IAMSecrets iamSecrets : iamServiceAccount.getSecret()) {
				IAMSecretsMetadata iamSecretsMetadata = new IAMSecretsMetadata();
				iamSecretsMetadata.setAccessKeyId(iamSecrets.getAccessKeyId());
				iamSecretsMetadata.setExpiryDuration(iamSecrets.getExpiryDateEpoch());
				iamSecretsMetadatas.add(iamSecretsMetadata);
			}
		}
		iamServiceAccountMetadataDetails.setSecret(iamSecretsMetadatas);

		return iamServiceAccountMetadataDetails;
	}

	@Test
	public void test_getIAMServiceAccountsList_successfully() {
		userDetails = getMockUser(false);
		token = userDetails.getClientToken();
		String [] policies = {"r_users_s1", "w_users_s2", "r_shared_s3", "w_shared_s4", "r_apps_s5", "w_apps_s6", "d_apps_s7", "w_svcacct_test", "r_iamsvcacc_1234567890_test"};
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getIAMServiceAccountsList(userDetails, token);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_getIAMServiceAccountsList_admin_successfully() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"test=.4,1,2.3\" ]}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getIAMServiceAccountsList(userDetails, token);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_AssociateAppRole_succssfully() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle successfully associated with IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}",token)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.associateApproletoIAMsvcacc(userDetails, token, serviceAccountApprole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_associateApproletoIAMsvcacc_approle_metadata_update_no_content_failure() {
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Approle configuration failed. Please try again\"]}");
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}", tkn)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"testuser\",\"name\":\"svc_vault_test5\",\"users\":{\"testuser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.associateApproletoIAMsvcacc(userDetails, tkn, serviceAccountApprole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_associateApproletoIAMsvcacc_approle_configure_approle_bad_request_failure() {
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Failed to add Approle to the IAM Service Account\"]}");
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}", tkn)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.associateApproletoIAMsvcacc(userDetails, tkn, serviceAccountApprole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_AssociateAppRole_succssfully_admin_approle() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle successfully associated with IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("AzureADRoleManager", "cloudsecurity_iam_admin_approle", "read", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567891_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"cloudsecurity_iam_admin_approle\"}",token)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currnetPolicies = new ArrayList<>();
		currnetPolicies.add("iamportal_admin_policy");
		when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(currnetPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.associateApproletoIAMsvcacc(userDetails, token, serviceAccountApprole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_AssociateAppRole_failed_admin_approle() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to add Approle to this iam service account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("AzureADRoleManager", "cloudsecurity_iam_admin_approle", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567891_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"cloudsecurity_iam_admin_approle\"}",token)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currnetPolicies = new ArrayList<>();
		currnetPolicies.add("iamportal_admin_policy");
		when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(currnetPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.associateApproletoIAMsvcacc(userDetails, token, serviceAccountApprole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_hasAddOrRemovePermission_as_admin_successfully() {
		assertTrue(iamServiceAccountsService.hasAddOrRemovePermission(getMockUser(true), null, null));
	}

	@Test
	public void testOnboardIAMServiceAccountSuccss() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setAdSelfSupportGroup("group1");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.anyString(), Mockito.any())).thenReturn(createPolicyResponse);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully completed onboarding of IAM service account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// changes for add self support group
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "rotate", "1234567");
		userDetails = getMockUser(false);

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccountSuccssWithSpacesinAWSAccountName() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = new IAMServiceAccount();
		serviceAccount.setUserName("testaccount");
		serviceAccount.setAwsAccountId("1234567");
		serviceAccount.setAwsAccountName("testaccount 1");
		serviceAccount.setOwnerNtid("normaluser");
		serviceAccount.setOwnerEmail("normaluser@testmail.com");
		serviceAccount.setApplicationId("app1");
		serviceAccount.setApplicationName("App1");
		serviceAccount.setApplicationTag("App1");
		serviceAccount.setCreatedAtEpoch(125L);
		serviceAccount.setSecret(generateIAMSecret());
		serviceAccount.setExpiryDateEpoch(7776000000L);
		serviceAccount.setAdSelfSupportGroup("group1");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.anyString(), Mockito.any())).thenReturn(createPolicyResponse);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully completed onboarding of IAM service account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// changes for add self support group
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "rotate", "1234567");
		userDetails = getMockUser(false);

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_onboardIAMServiceAccount_unauthorized_failure() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setAdSelfSupportGroup("group1");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.anyString(), Mockito.any())).thenReturn(createPolicyResponse);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// System under test
		String expectedResponse = "{\"errors\":[\"Access denied. Not authorized to perform onboarding for IAM service accounts.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenThrow(new IOException());
		} catch (IOException e) {
			e.printStackTrace();
		}

		// changes for add self support group
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "rotate", "1234567");
		userDetails = getMockUser(false);

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccountSuccssSelfSupportGroupFailed() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setAdSelfSupportGroup("group1");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.anyString(), Mockito.any())).thenReturn(createPolicyResponse);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully completed onboarding of IAM service account. But failed to add write permission to group1\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// changes for add self support group
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "rotate", "1234567");
		userDetails = getMockUser(false);

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, false, ""));
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccount_secret_failed() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setAdSelfSupportGroup("group1");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.anyString(), Mockito.any())).thenReturn(createPolicyResponse);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to onboard IAM service account. Updating legacy accesses key ids failed.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// changes for add self support group
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "rotate1", "1234567");
		userDetails = getMockUser(false);

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(groupResp);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		ResponseEntity<String> rollBackResponse = ResponseEntity.status(HttpStatus.OK).body("");
		when(accessService.deletePolicyInfo(Mockito.any(), Mockito.any())).thenReturn(rollBackResponse);
		when(reqProcessor.process("/delete","{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_success() throws IOException {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"ad_group\":\"group1\",\"application_id\":\"app1\",\"application_name\":\"App1\"," +
				"\"application_tag\":\"App1\",\"expiryDateEpoch\":\"99999\",\"expiryDuration\":\"1234\"," +
				"\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"}," +
				"\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\"," +
				"\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDateEpoch\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(tkn))).thenReturn(userResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(tkn)))
				.thenReturn(userResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// Send email
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(tkn,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"messages\":[\"IAM Service Account has been successfully updated.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_email_given_no_ntid_failure() throws IOException {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				null, "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"ad_group\":\"group1\",\"application_id\":\"app1\",\"application_name\":\"App1\"," +
				"\"application_tag\":\"App1\",\"expiryDateEpoch\":\"99999\",\"expiryDuration\":\"1234\"," +
				"\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"}," +
				"\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\"," +
				"\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDateEpoch\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(tkn,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Update Failed. Owner_ntid is required when owner_email is given.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_invalid_account_failure() throws IOException {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"ad_group\":\"group1\",\"application_id\":\"app1\",\"application_name\":\"App1\"," +
				"\"application_tag\":\"App1\",\"expiryDateEpoch\":\"99999\",\"expiryDuration\":\"1234\"," +
				"\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"}," +
				"\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\"," +
				"\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDateEpoch\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_some_other_account\" ]}"));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(tkn,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Invalid username or awsAccountId.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_no_ownerNTID_success() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				null, null, null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Update metadata
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"messages\":[\"IAM Service Account has been successfully updated.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_io_exception_failure() throws IOException {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"ad_group\":\"group1\",\"application_id\":\"app1\",\"application_name\":\"App1\"," +
				"\"application_tag\":\"App1\",\"expiryDateEpoch\":\"99999\"" +
				"\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"}," +
				"\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\"," +
				"\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(tkn))).thenReturn(userResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(tkn)))
				.thenReturn(userResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// Send email
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(tkn,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Failed to get metadata for this IAM Service Account.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_cannot_add_write_permission_failure() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		Response response = getMockResponse(HttpStatus.NOT_FOUND, false, "{}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(token))).thenReturn(userResponse).thenReturn(response);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(userResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// Send email
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}");
		assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_ownerNTID_exists_no_ownerEmail_failure() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"test", null, null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Update metadata
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Update failed. Owner_email is required when owner_ntid is given.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_with_new_app_details() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", "app2", "newname", "wow", null);

		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(token))).thenReturn(userResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		// Add User to Service Account
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// Send email
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"messages\":[\"IAM Service Account has been successfully updated.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_with_ad_group() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, iamSvcAccGroup.getGroupname());

		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String serviceAccountMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response serviceAccountMetadataResponse = getMockResponse(HttpStatus.OK, true, serviceAccountMetadataBody);

		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Add Group
		userDetails = getMockUser(false);
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		Response groupMetadataResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}");
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token)))
				.thenReturn(serviceAccountMetadataResponse)
				.thenReturn(groupMetadataResponse);

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(token))).thenReturn(userResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);

		// create metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		// Add User to Service Account
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// Send email
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"messages\":[\"IAM Service Account has been successfully updated.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_owner_already_exists() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"normaluser", "newowner@t-mobile.com", null, null, null, null);

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Failed to transfer IAM Service Account owner. The owner given is already the current owner.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_not_authorized_failure() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newuser", "newowner@t-mobile.com", null, null, null, null);

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.FORBIDDEN, true, "{\"errors\":[\"Access denied. IAM admin approle not authorized.\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Access denied. IAM admin approle not authorized.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body(expectedResponse);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_failed_to_remove_user_permissions() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponseBadRequest = getMockResponse(HttpStatus.BAD_REQUEST, true, "{}");
		Response userResponseOk = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseBadRequest = getMockResponse(HttpStatus.BAD_REQUEST, true, "{\"policies\":null}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(token))).thenReturn(userResponseOk).
				thenReturn(userResponseOk).thenReturn(userResponseBadRequest);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseBadRequest);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent).thenReturn(responseBadRequest);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		// Add User to Service Account
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// Send email
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Failed to remove the user from the IAM Service Account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(expectedResponse);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_update_metadata_failure() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(token))).thenReturn(userResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);

		// Add User to Service Account
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.BAD_REQUEST, false,"{}"));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Metadata update failed for IAM Service Account.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.MULTI_STATUS).body(expectedResponse);
		assertEquals(HttpStatus.MULTI_STATUS, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_add_sudo_permission_failure() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(token))).thenReturn(userResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		// Add User to Service Account
		Response ldapConfigureResponse = getMockResponse(HttpStatus.BAD_REQUEST, false, "{}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Failed to configure policies for user newowner\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_add_sudo_permission_failed_reverted_successfully() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"1234567_testaccount\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(token))).thenReturn(userResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		// Add User to Service Account
		Response ldapConfigureResponse = getMockResponse(HttpStatus.BAD_REQUEST, false, "{}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"errors\":[\"Failed to configure policies for user newowner\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveUserFromIAMSvcAccLdapSuccess() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccountUser iamSvcAccUser = new IAMServiceAccountUser("testaccount", "testuser1", "read", "1234567");
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\", \"o_iamsvcacc_1234567_testaccount\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"testuser1\"}", token)).thenReturn(userResponse);
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("o_iamsvcacc_1234567_testaccount");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("testuser1"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully removed user from the IAM Service Account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeUserFromIAMServiceAccount(token,
				iamSvcAccUser, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveUserFromIAMSvcAccOidcSuccess() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccountUser iamSvcAccUser = new IAMServiceAccountUser("testaccount", "testuser1", "read", "1234567");
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\", \"o_iamsvcacc_1234567_testaccount\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"testuser1\"}", token)).thenReturn(userResponse);
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("o_iamsvcacc_1234567_testaccount");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("testuser1"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully removed user from the IAM Service Account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		// oidc test cases
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		String mountAccessor = "auth_oidc";
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUser1");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("testuser1");
		directoryUser.setUserName("testUser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);

		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		OIDCLookupEntityRequest oidcLookupEntityRequest = new OIDCLookupEntityRequest();
		oidcLookupEntityRequest.setId(null);
		oidcLookupEntityRequest.setAlias_id(null);
		oidcLookupEntityRequest.setName(null);
		oidcLookupEntityRequest.setAlias_name(directoryUser.getUserEmail());
		oidcLookupEntityRequest.setAlias_mount_accessor(mountAccessor);
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<DirectoryObjects> responseEntity1 = ResponseEntity.status(HttpStatus.OK).body(users);
		when(OIDCUtil.fetchMountAccessorForOidc(token)).thenReturn(mountAccessor);

		ResponseEntity<OIDCEntityResponse> responseEntity2 = ResponseEntity.status(HttpStatus.OK)
				.body(oidcEntityResponse);

		when(tokenUtils.getSelfServiceTokenWithAppRole()).thenReturn(token);
		String entityName = "entity";

		Response responseEntity3 = getMockResponse(HttpStatus.NO_CONTENT, true,
				"{\"data\": [\"safeadmin\",\"vaultadmin\"]]");
		when(OIDCUtil.updateOIDCEntity(Mockito.any(), Mockito.any())).thenReturn(responseEntity3);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(responseEntity2);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeUserFromIAMServiceAccount(token,
				iamSvcAccUser, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveUserFromIAMSvcAccUserpassSuccess() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccountUser iamSvcAccUser = new IAMServiceAccountUser("testaccount", "testuser1", "read", "1234567");
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\", \"o_iamsvcacc_1234567_testaccount\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/userpass/read", "{\"username\":\"testuser1\"}", token))
				.thenReturn(userResponse);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "userpass");
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("o_iamsvcacc_1234567_testaccount");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureUserpassUser(Mockito.eq("testuser1"), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully removed user from the IAM Service Account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeUserFromIAMServiceAccount(token,
				iamSvcAccUser, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeUserFromIAMServiceAccount_revert_unsuccessful_oidc_failure() {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccountUser iamSvcAccUser = new IAMServiceAccountUser("testaccount", "testuser1", "read", "1234567");
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\", \"o_iamsvcacc_1234567_testaccount\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		Response responseNotFound = getMockResponse(HttpStatus.NOT_FOUND, true, "{}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"testuser1\"}", tkn)).thenReturn(userResponse);
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("o_iamsvcacc_1234567_testaccount");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("testuser1"), Mockito.any(), Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNotFound);
		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to remove the user from the IAM Service Account. Metadata update failed\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(expectedResponse);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":" +
						"{\"normaluser\":\"sudo\"}}}"));
		// oidc test cases
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		String mountAccessor = "auth_oidc";
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUser1");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("testuser1");
		directoryUser.setUserName("testUser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);

		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		OIDCLookupEntityRequest oidcLookupEntityRequest = new OIDCLookupEntityRequest();
		oidcLookupEntityRequest.setId(null);
		oidcLookupEntityRequest.setAlias_id(null);
		oidcLookupEntityRequest.setName(null);
		oidcLookupEntityRequest.setAlias_name(directoryUser.getUserEmail());
		oidcLookupEntityRequest.setAlias_mount_accessor(mountAccessor);
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		when(OIDCUtil.fetchMountAccessorForOidc(tkn)).thenReturn(mountAccessor);

		ResponseEntity<OIDCEntityResponse> responseEntity2 = ResponseEntity.status(HttpStatus.OK)
				.body(oidcEntityResponse);

		when(tokenUtils.getSelfServiceTokenWithAppRole()).thenReturn(tkn);

		Response responseEntity3 = getMockResponse(HttpStatus.NO_CONTENT, true,
				"{\"data\": [\"safeadmin\",\"vaultadmin\"]]");
		when(OIDCUtil.updateOIDCEntity(Mockito.any(), Mockito.any())).thenReturn(responseEntity3);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(responseEntity2);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": " +
				"\"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": " +
				"\"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, " +
				"\"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": " +
				"\"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", tkn))
				.thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeUserFromIAMServiceAccount(tkn,
				iamSvcAccUser, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeUserFromIAMServiceAccount_revert_oidc_failure() {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccountUser iamSvcAccUser = new IAMServiceAccountUser("testaccount", "testuser1", "read", "1234567");
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\", \"o_iamsvcacc_1234567_testaccount\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		Response responseNotFound = getMockResponse(HttpStatus.NOT_FOUND, true, "{}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"testuser1\"}", tkn)).thenReturn(userResponse);
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("o_iamsvcacc_1234567_testaccount");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("testuser1"), Mockito.any(), Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNotFound);
		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to remove the user from the IAM Service Account. Metadata update failed\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(expectedResponse);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":" +
						"{\"normaluser\":\"sudo\"}}}"));
		// oidc test cases
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		String mountAccessor = "auth_oidc";
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUser1");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("testuser1");
		directoryUser.setUserName("testUser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);

		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		OIDCLookupEntityRequest oidcLookupEntityRequest = new OIDCLookupEntityRequest();
		oidcLookupEntityRequest.setId(null);
		oidcLookupEntityRequest.setAlias_id(null);
		oidcLookupEntityRequest.setName(null);
		oidcLookupEntityRequest.setAlias_name(directoryUser.getUserEmail());
		oidcLookupEntityRequest.setAlias_mount_accessor(mountAccessor);
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		when(OIDCUtil.fetchMountAccessorForOidc(tkn)).thenReturn(mountAccessor);

		ResponseEntity<OIDCEntityResponse> responseEntity2 = ResponseEntity.status(HttpStatus.OK)
				.body(oidcEntityResponse);

		when(tokenUtils.getSelfServiceTokenWithAppRole()).thenReturn(tkn);

		Response responseEntity3 = getMockResponse(HttpStatus.NO_CONTENT, true,
				"{\"data\": [\"safeadmin\",\"vaultadmin\"]]");
		when(OIDCUtil.updateOIDCEntity(Mockito.any(), Mockito.any())).thenReturn(responseEntity3);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(responseEntity2);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": " +
				"\"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": " +
				"\"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, " +
				"\"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": " +
				"\"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", tkn))
				.thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeUserFromIAMServiceAccount(tkn,
				iamSvcAccUser, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeUserFromIAMServiceAccount_revert_failure() {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccountUser iamSvcAccUser = new IAMServiceAccountUser("testaccount", "testuser1", "read",
				"1234567");
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\", \"o_iamsvcacc_1234567_testaccount\"]," +
						"\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		Response responseNotFound = getMockResponse(HttpStatus.NOT_FOUND, false, "{}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"testuser1\"}", tkn)).thenReturn(userResponse);
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("o_iamsvcacc_1234567_testaccount");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("testuser1"), Mockito.any(), Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNotFound);
		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to remove the user from the IAM Service Account. Metadata update failed\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(expectedResponse);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":" +
						"{\"normaluser\":\"sudo\"}}}"));
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": " +
				"\"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": " +
				"\"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":" +
				"[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", tkn))
				.thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeUserFromIAMServiceAccount(tkn,
				iamSvcAccUser, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveUserFromIAMSvcACcFailureNotauthorized() {
		userDetails = getMockUser(false);
		token = userDetails.getClientToken();
		IAMServiceAccountUser iamSvcAccUser = new IAMServiceAccountUser("testaccount", "testuser1", "read", "1234567");
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("o_iamsvcacc_1234567_testaccount");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		// System under test
		String expectedResponse = "{\"errors\":[\"Access denied: No permission to remove user from this IAM service account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body(expectedResponse);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeUserFromIAMServiceAccount(token,
				iamSvcAccUser, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveUserFromIAMSvcAccFailure400() {
		userDetails = getMockUser(false);
		token = userDetails.getClientToken();
		IAMServiceAccountUser iamSvcAccUser = new IAMServiceAccountUser("testaccount", "testuser1", "reads", "1234567");
		// System under test
		String expectedResponse = "{\"errors\":[\"Invalid value specified for access. Valid values are read, write, deny\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body(expectedResponse);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeUserFromIAMServiceAccount(token,
				iamSvcAccUser, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testAddGroupToIAMSvcAccSuccessfully() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Group is successfully associated with IAM Service Account\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testAddGroupToIAMSvcACcOidcSuccessfully() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Group is successfully associated with IAM Service Account\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		List<String> policie = new ArrayList<>();
		policie.add("default");
		policie.add("w_shared_mysafe02");
		policie.add("r_shared_mysafe01");
		List<String> currentpolicies = new ArrayList<>();
		currentpolicies.add("default");
		currentpolicies.add("w_shared_mysafe01");
		currentpolicies.add("w_shared_mysafe02");
		OIDCGroup oidcGroup = new OIDCGroup("123-123-123", currentpolicies);
		when(OIDCUtil.getIdentityGroupDetails("mygroup01", token)).thenReturn(oidcGroup);

		Response response = new Response();
		response.setHttpstatus(HttpStatus.NO_CONTENT);
		when(OIDCUtil.updateGroupPolicies(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_addGroupToIAMSvcAcc_io_exception_failure() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Group is successfully associated with IAM Service Account\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenThrow(new IOException());
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testAddGroupToIAMSvcAccMetadataFailure() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Group configuration failed. Please try again\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(response404);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_addGroupToIAMSvcAcc_metadata_oidc_failure() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Group configuration failed. Please try again\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(response404);

		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		List<String> policiesList = new ArrayList<>();
		policiesList.add("default");
		policiesList.add("w_shared_mysafe02");
		policiesList.add("r_shared_mysafe01");
		List<String> currentpolicies = new ArrayList<>();
		currentpolicies.add("default");
		currentpolicies.add("w_shared_mysafe01");
		currentpolicies.add("w_shared_mysafe02");
		OIDCGroup oidcGroup = new OIDCGroup("123-123-123", currentpolicies);
		when(OIDCUtil.getIdentityGroupDetails(Mockito.any(), Mockito.any())).thenReturn(oidcGroup);
		when(OIDCUtil.updateGroupPolicies(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testAddGroupToIAMSvcAccFailure() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Unable to update group policies for group group1\"]}");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response404);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testAddGroupToIAMSvcAccFailure403() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Access denied: No permission to add groups to this IAM service account\"]}");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		String[] policies = { "w_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response404);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testAddGroupToIAMSvcAccFailureInitialActivate() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "read", "1234567");
		userDetails = getMockUser(false);
		token = userDetails.getClientToken();
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
				"{\"errors\":[\"Failed to add group permission to IAM Service account. Only Rotate permissions can be added to the self support group as part of Onboard.\"]}");
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":false,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, true);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveGroupFromIAMSvcAccSuccessfully() {
		token = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Group is successfully removed from IAM Service Account\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(token,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveGroupFromIAMSvcAccOidcSuccessfully() {
		userDetails = getMockUser(false);
		token = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Group is successfully removed from IAM Service Account\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		List<String> policie = new ArrayList<>();
		policie.add("default");
		policie.add("w_shared_mysafe02");
		policie.add("r_shared_mysafe01");
		List<String> currentpolicies = new ArrayList<>();
		currentpolicies.add("default");
		currentpolicies.add("w_shared_mysafe01");
		currentpolicies.add("w_shared_mysafe02");
		OIDCGroup oidcGroup = new OIDCGroup("123-123-123", currentpolicies);
		when(OIDCUtil.getIdentityGroupDetails(Mockito.any(), Mockito.any())).thenReturn(oidcGroup);

		Response response1 = new Response();
		response1.setHttpstatus(HttpStatus.NO_CONTENT);
		when(OIDCUtil.updateGroupPolicies(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response1);
		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(token,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeGroupFromIAMServiceAccount_io_exception_failure() {
		String tkn = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Group is successfully removed from IAM Service Account\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", tkn)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenThrow(new IOException("whoops, something went wrong"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(tkn,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeGroupFromIAMServiceAccount_bad_group_name_failure() {
		String tkn = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Failed to remove group from IAM service account. Group association to IAM service account not found\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", tkn)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		String metdataJsonString = "{\"data\":{\"groups\": {\"fake_group\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(tkn,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeGroupFromIAMServiceAccount_invalid_access_failure() {
		String tkn = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "something_crazy", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Invalid value specified for access. Valid values are read, write, deny\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", tkn)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(tkn,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeGroupFromIAMServiceAccount_empty_response_map_failure() {
		String tkn = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Error Fetching existing IAM Service account info. please check the path specified\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", tkn)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		String metdataJsonString = "{}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(tkn,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveGroupFromIAMSvcAccFailureInitialActivation() {
		userDetails = getMockUser(false);
		token = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
				"{\"errors\":[\"Error Fetching existing IAM Service account info. please check the path specified\"]}");
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":false,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(token,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveGroupFromIAMSvcAccMetadataFailure() {
		userDetails = getMockUser(false);
		token = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Group configuration failed. Please try again\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(response404);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(token,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeGroupFromIAMSvcAcc_metadata_oidc_failure() {
		userDetails = getMockUser(false);
		String tkn = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Group configuration failed. Please try again\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", tkn)).thenReturn(groupResp);

		// OIDC
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		when(OIDCUtil.updateGroupPolicies(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent).thenReturn(response404);
		OIDCGroup oidcGroup = new OIDCGroup();
		oidcGroup.setPolicies(Arrays.asList(policies));
		when(OIDCUtil.getIdentityGroupDetails(Mockito.any(), Mockito.any())).thenReturn(oidcGroup);

		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(tkn))).thenReturn(response404);
		Response updateGroupResponse = new Response();
		updateGroupResponse.setHttpstatus(HttpStatus.NO_CONTENT);
		when(OIDCUtil.updateGroupPolicies(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(updateGroupResponse);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(tkn,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeGroupFromIAMServiceAccount_with_ssoToken_failure() {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Group configuration failed.Try Again\"]}");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", tkn)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);

		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response404);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(OIDCUtil.getSSOToken()).thenReturn("something");
		when(OIDCUtil.getGroupObjectResponse(Mockito.any(), Mockito.any())).thenReturn("someid");
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(tkn,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeGroupFromIAMServiceAccount_with_ssoToken_no_objectId_failure() {
		userDetails = getMockUser(true);
		String tkn = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"messages\":[\"Group configuration failed.Try again \"]}");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", tkn)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);

		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response404);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(OIDCUtil.getSSOToken()).thenReturn("something");
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(tkn,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveGroupFromIAMSVcAccFailure() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Group configuration failed.Try Again\"]}");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);

		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response404);
		String[] latestPolicies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(), userDetails.getUsername(), userDetails))
				.thenReturn(latestPolicies);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(token,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testRemoveGroupFromIAMSvcAccFailure403() {
		userDetails = getMockUser(false);
		token = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Access denied: No permission to remove groups from this IAM service account\"]}");
		Response response404 = getMockResponse(HttpStatus.NOT_FOUND, true, "");

		String[] policies = { "w_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response404);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(token,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_removeApproleFromIAMSvcAcc_succssfully() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle is successfully removed(if existed) from IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_1234567890_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}",token)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeApproleFromIAMSvcAcc(userDetails, token, serviceAccountApprole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}


	@Test
	public void test_removeApproleFromIAMSvcAcc_not_authorized_failure() throws Exception {
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Access denied: No permission to remove approle from Service Account\"]}");
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String[] policies = {};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_1234567890_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}", tkn)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeApproleFromIAMSvcAcc(userDetails, tkn, serviceAccountApprole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_removeApproleFromIAMSvcAcc_role_response_failure() {
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
				.body("{\"errors\":[\"Either Approle doesn't exists or you don't have enough permission to remove this approle from IAM Service Account\"]}");
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "{}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}", tkn)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeApproleFromIAMSvcAcc(userDetails, tkn, serviceAccountApprole);

		assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_removeApproleFromIAMSvcAcc_role_response_bad_request_failure() {
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Failed to remove approle from the Service Account\"]}");
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_1234567890_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}", tkn)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeApproleFromIAMSvcAcc(userDetails, tkn, serviceAccountApprole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_removeApproleFromIAMSvcAcc_configure_approle_failure() {
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"errors\":[\"Approle configuration failed. Please try again\"]}");
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_1234567890_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}", tkn)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeApproleFromIAMSvcAcc(userDetails, tkn, serviceAccountApprole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_removeApproleFromIAMSvcAcc_bad_role_name_failure() {
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Access denied: no permission to remove this AppRole to any Service Account\"]}");
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "iamportal_admin_approle", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_1234567890_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"iamportal_admin_approle\"}", tkn)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeApproleFromIAMSvcAcc(userDetails, tkn, serviceAccountApprole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_removeApproleFromIAMSvcAcc_invalid_permission_failure() {
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Invalid value specified for access. Valid values are read, write, deny\"]}");
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname",
				"role2", "some_crazy_nonexistant_permission", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"scnep_iamsvcacc_1234567890_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role2\"}", tkn)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeApproleFromIAMSvcAcc(userDetails, tkn, serviceAccountApprole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_getOnboardedIAMServiceAccounts_successfully() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		String[] policies = { "r_users_s1", "w_users_s2", "r_shared_s3", "w_shared_s4", "r_apps_s5", "w_apps_s6",
				"d_apps_s7", "w_svcacct_test", "o_iamsvcacc_1234567890_test" };
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(
				"{\"keys\":{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}}");

		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getOnboardedIAMServiceAccounts(token,
				userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_getOnboardedIAMServiceAccounts_admin_successfully() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(true);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(
				"{\"keys\":{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}}");

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"test=.4,1,2.3\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getOnboardedIAMServiceAccounts(token,
				userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_listAllOnboardedIAMServiceAccounts_successfully() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_test0=.4,1,2.3\",\"12234237890_svc_test0=.5,2,3.4\" ]}"));
		StringBuffer responseStr = new StringBuffer().append("{" );
		responseStr.append("\"userName\": \"svc_tvt_test0=.4,1,2.3\"," );
		responseStr.append("\"metaDataName\": \"12234237890_svc_test0=.4,1,2.3\"," );
		responseStr.append("\"accountID\": \"12234237890\"" );
		responseStr.append("}," );
		responseStr.append("{" );
		responseStr.append("\"userName\": \"svc_tvt_test0=.5,2,3.4\"," );
		responseStr.append("\"metaDataName\": \"12234237890_svc_test0=.5,2,3.4\"," );
		responseStr.append("\"accountID\": \"12234237890\"" );
		responseStr.append("}\n" );

		StringBuffer responseJSONStr = new StringBuffer().append("{");
		responseJSONStr.append("\"keys\":");
		responseJSONStr.append(responseStr.toString());
		responseJSONStr.append("" );
		responseJSONStr.append("}");
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJSONStr.toString());


		when(JSONUtil.getJSON(Mockito.any())).thenReturn(responseStr.toString());
		ResponseEntity<String> responseEntity = iamServiceAccountsService.listAllOnboardedIAMServiceAccounts(token,
				userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_listAllOnboardedIAMServiceAccounts_notfound() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, "{\"keys\":[]}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"keys\":[]}");
		ResponseEntity<String> responseEntity = iamServiceAccountsService.listAllOnboardedIAMServiceAccounts(token, userDetails);
		assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_listAllOnboardedIAMServiceAccounts_AccesDenied() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"default\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("default");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		StringBuffer responseStr = new StringBuffer().append("{\"errors\":[\"Access denied. Not authorized to perform this operation.\"]}");

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body(responseStr.toString());
		ResponseEntity<String> responseEntity = iamServiceAccountsService.listAllOnboardedIAMServiceAccounts(token,
				userDetails);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}



	@Test
	public void test_getIAMServiceAccountDetail_successfully() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		String iamSvcaccName = "1234567890_testiamsvc";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(
				"{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"Nithin.Nazeer1@T-mobile.com\",\"owner_ntid\":\"NNazeer1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"604800000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"nnazeer1\":\"write\"},\"createdDate\":\"2004-06-01 12:30:00\"}");

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"Nithin.Nazeer1@T-mobile.com\",\"owner_ntid\":\"NNazeer1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"expiryDuration\": 604800000,\"users\":{\"nnazeer1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getIAMServiceAccountDetail(token, iamSvcaccName);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getIAMServiceAccountSecretKey_successfully() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "1234567890_testiamsvcacc01";
		String folderName = "testiamsvc_01";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(
				"{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}");

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getIAMServiceAccountSecretKey(token, iamSvcaccName, folderName);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_activateIAMServiceAccount_successfull() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 1)
					return metaActivatedResponse;

				return metaResponse;
			}
		});

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);


		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"IAM Service account activated successfully\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.activateIAMServiceAccount(token, userDetails, iamServiceAccountName, awsAccountId);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_activateIAMServiceAccount_failed_403() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String [] policies = {"defaullt"};
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied: No permission to activate this IAM service account\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.activateIAMServiceAccount(token, userDetails, iamServiceAccountName, awsAccountId);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_activateIAMServiceAccount_failure_already_activated() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(metaActivatedResponse);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Service Account is already activated. You can now grant permissions from Permissions menu\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.activateIAMServiceAccount(token, userDetails, iamServiceAccountName, awsAccountId);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_activateIAMServiceAccount_failed_owner_association() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 1)
					return metaActivatedResponse;

				return metaResponse;
			}
		});

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");
		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.OK).body("{\"errors\":[\"Failed to activate IAM Service account. IAM secrets are rotated and saved in T-Vault. However failed to add permission to owner. Owner info not found in Metadata.\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.activateIAMServiceAccount(token, userDetails, iamServiceAccountName, awsAccountId);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_activateIAMServiceAccount_failed_add_user() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 1)
					return metaActivatedResponse;

				return metaResponse;
			}
		});

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);


		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to activate IAM Service account. IAM secrets are rotated and saved in T-Vault. However owner permission update failed.\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.activateIAMServiceAccount(token, userDetails, iamServiceAccountName, awsAccountId);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_activateIAMServiceAccount_failed_to_save_secret() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 1)
					return metaActivatedResponse;

				return metaResponse;
			}
		});

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(null);


		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to activate IAM Service account. Failed to rotate secrets for one or more AccessKeyIds.\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.activateIAMServiceAccount(token, userDetails, iamServiceAccountName, awsAccountId);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_activateIAMServiceAccount_failed_metadata_update() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 1)
					return metaActivatedResponse;

				return metaResponse;
			}
		});

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, false, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to activate IAM Service account. IAM secrets are rotated and saved in T-Vault. However metadata update failed.\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.activateIAMServiceAccount(token, userDetails, iamServiceAccountName, awsAccountId);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_rotateIAMServiceAccount_successfull() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";


		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"folder_1\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"testaccesskey\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"1234567890\",\"expiryDateEpoch\":1609845308000,\"userName\":\"svc_vault_test5\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"IAM Service account secret rotated successfully\"]}");
		IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
		ResponseEntity<String> actualResponse = iamServiceAccountsService.rotateIAMServiceAccount(token, iamServiceAccountRotateRequest, userDetails);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_rotateIAMServiceAccount_successfull_admin() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";


		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"folder_1\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"testaccesskey\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"1234567890\",\"expiryDateEpoch\":1609845308000,\"userName\":\"svc_vault_test5\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"IAM Service account secret rotated successfully\"]}");
		IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
		ResponseEntity<String> actualResponse = iamServiceAccountsService.rotateIAMServiceAccount(token, iamServiceAccountRotateRequest, getMockUser(true));
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_rotateIAMServiceAccount_failed_403() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test1 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test1");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied: No permission to rotate secret for IAM service account.\"]}");
		IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
		ResponseEntity<String> actualResponse = iamServiceAccountsService.rotateIAMServiceAccount(token, iamServiceAccountRotateRequest, userDetails);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_rotateIAMServiceAccount_faile_to_rotate_secret() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";


		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(null);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"folder_1\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"testaccesskey\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"1234567890\",\"expiryDateEpoch\":1609845308000,\"userName\":\"svc_vault_test5\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to rotate secret for IAM Service account Access Key Id\"]}");
		IAMServiceAccountRotateRequest iamServiceAccountRotateRequest = new IAMServiceAccountRotateRequest(accessKeyId, iamServiceAccountName, awsAccountId);
		ResponseEntity<String> actualResponse = iamServiceAccountsService.rotateIAMServiceAccount(token, iamServiceAccountRotateRequest, userDetails);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_addUserToIAMServiceAccount_successfull() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);


		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully added user to the IAM Service Account\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read",awsAccountId);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(token, userDetails, iamServiceAccountUser, false);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_addUserToIAMServiceAccount_successfull_oidc() {

		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");

		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies1 = new ArrayList<>();
		policies1.add("safeadmin");
		oidcEntityResponse.setPolicies(policies1);
		ResponseEntity<OIDCEntityResponse> responseEntity2 = ResponseEntity.status(HttpStatus.OK)
				.body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(responseEntity2);

		when(OIDCUtil.updateOIDCEntity(Mockito.any(), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully added user to the IAM Service Account\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read",awsAccountId);
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(token, userDetails, iamServiceAccountUser, false);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_addUserToIAMServiceAccount_oidc_exception_failure() {
		String iamServiceAccountName = "svc_vault_test5";
		String tkn = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");

		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(tkn, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(tkn), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(tkn, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies1 = new ArrayList<>();
		policies1.add("safeadmin");
		oidcEntityResponse.setPolicies(policies1);
		ResponseEntity<OIDCEntityResponse> responseEntity2 = ResponseEntity.status(HttpStatus.OK)
				.body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(responseEntity2);

		when(OIDCUtil.updateOIDCEntity(Mockito.any(), Mockito.any())).thenThrow(new IllegalStateException());
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Failed to configure policies for user normaluser\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read",awsAccountId);
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		assertEquals(expectedResponse, iamServiceAccountsService.addUserToIAMServiceAccount(tkn, userDetails, iamServiceAccountUser, false));
	}

	@Test
	public void test_addUserToIAMServiceAccount_metadata_update_failure() {
		String iamServiceAccountName = "svc_vault_test5";
		String tkn = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		Response responseNotFound = getMockResponse(HttpStatus.NOT_FOUND, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(tkn, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(tkn), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(tkn, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", tkn)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(tkn)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNotFound);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("{\"messages\":[\"Failed to add user to the Service Account. Metadata update failed\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read",awsAccountId);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(tkn, userDetails, iamServiceAccountUser, false);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_addUserToIAMServiceAccount_oidc_bad_response_failure() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");

		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies1 = new ArrayList<>();
		policies1.add("safeadmin");
		oidcEntityResponse.setPolicies(policies1);
		ResponseEntity<OIDCEntityResponse> responseEntity2 = ResponseEntity.status(HttpStatus.NOT_FOUND)
				.body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(responseEntity2);

		when(OIDCUtil.updateOIDCEntity(Mockito.any(), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.NOT_FOUND)
				.body("{\"messages\":[\"User configuration failed. Invalid user\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read",awsAccountId);
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(token, userDetails, iamServiceAccountUser, false);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_addUserToIAMServiceAccount_oidc_forbidden_failure() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");

		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies1 = new ArrayList<>();
		policies1.add("safeadmin");
		oidcEntityResponse.setPolicies(policies1);
		ResponseEntity<OIDCEntityResponse> responseEntity2 = ResponseEntity.status(HttpStatus.FORBIDDEN)
				.body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(responseEntity2);

		when(OIDCUtil.updateOIDCEntity(Mockito.any(), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.FORBIDDEN)
				.body("{\"messages\":[\"User configuration failed. Please try again.\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read",awsAccountId);
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(token, userDetails, iamServiceAccountUser, false);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_addUserToIAMServiceAccount_not_authorized_failure() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.FORBIDDEN)
				.body("{\"errors\":[\"Access denied: No permission to add users to this IAM service account\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read",awsAccountId);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(token, userDetails, iamServiceAccountUser, false);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_addUserToIAMServiceAccount_bad_user_response_failure() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "{}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read",awsAccountId);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(token, userDetails, iamServiceAccountUser, false);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_addUserToIAMServiceAccount_cannot_add_permission_failure() {
		String iamServiceAccountName = "svc_vault_test5";
		String tkn = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(tkn);
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(tkn))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(tkn, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(tkn), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(tkn, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", tkn)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(tkn)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Failed to add user permission to IAM Service account. Only Sudo and Write permissions can be added as part of Onboard.\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "read", awsAccountId);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", tkn))
				.thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(tkn, userDetails, iamServiceAccountUser, true);
		assertEquals(expectedResponse, actualResponse);
	}

	private IAMServiceAccountMetadataDetails populateIAMSvcAccMetaData(
			IAMServiceAccountOffboardRequest iamServiceAccount) {

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = new IAMServiceAccountMetadataDetails();
		iamServiceAccountMetadataDetails.setUserName(iamServiceAccount.getIamSvcAccName());
		iamServiceAccountMetadataDetails.setAwsAccountId(iamServiceAccount.getAwsAccountId());
		return iamServiceAccountMetadataDetails;
	}

	@Test
	public void testoffboardIAMServiceAccountLdap_succss() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully offboarded IAM service account (if existed) from T-Vault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true,
				""));
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"aws123\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOffboardIAMServiceAccountLdapSuccssWithAWSEc2Role() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully offboarded IAM service account (if existed) from T-Vault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true,
				""));
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"ec2\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"aws123\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(awsAuthService.configureAWSRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testoffboardIAMServiceAccountLdap_succss_aws_role_removal_failed() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully offboarded IAM service account (if existed) from T-Vault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true,
				""));

		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"aws123\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}


	@Test
	public void testoffboardIAMServiceAccountOIDC_succss() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		List<String> currentpolicies = new ArrayList<>();
		currentpolicies.add("default");
		currentpolicies.add("w_shared_mysafe01");
		currentpolicies.add("w_shared_mysafe02");
		OIDCGroup oidcGroup = new OIDCGroup("123-123-123", currentpolicies);
		when(OIDCUtil.getIdentityGroupDetails("testgroup1", token)).thenReturn(oidcGroup);
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully offboarded IAM service account (if existed) from T-Vault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true,
				""));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testoffboardIAMServiceAccountOIDC_failed_403() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("default");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// System under test
		String expectedResponse = "{\"errors\":[\"Access denied. Not authorized to perform offboarding of IAM service accounts.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body(expectedResponse);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testoffboardIAMServiceAccountOIDC_failed_to_delete_policy() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body("");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to Offboard IAM service account. Policy deletion failed.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(expectedResponse);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testoffboardIAMServiceAccountOIDC_failed_to_delete_secret() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		List<String> currentpolicies = new ArrayList<>();
		currentpolicies.add("default");
		currentpolicies.add("w_shared_mysafe01");
		currentpolicies.add("w_shared_mysafe02");
		OIDCGroup oidcGroup = new OIDCGroup("123-123-123", currentpolicies);
		when(OIDCUtil.getIdentityGroupDetails("testgroup1", token)).thenReturn(oidcGroup);
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to offboard IAM service account from TVault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.MULTI_STATUS).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.MULTI_STATUS, true,
				""));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.MULTI_STATUS, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testoffboardIAMServiceAccountOIDC_failed_to_delete_folder() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		List<String> currentpolicies = new ArrayList<>();
		currentpolicies.add("default");
		currentpolicies.add("w_shared_mysafe01");
		currentpolicies.add("w_shared_mysafe02");
		OIDCGroup oidcGroup = new OIDCGroup("123-123-123", currentpolicies);
		when(OIDCUtil.getIdentityGroupDetails("testgroup1", token)).thenReturn(oidcGroup);
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to offboard IAM service account from TVault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.MULTI_STATUS).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 2)
					return getMockResponse(HttpStatus.MULTI_STATUS, true,"");

				return getMockResponse(HttpStatus.NO_CONTENT, true,"");
			}
		});

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.MULTI_STATUS, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testoffboardIAMServiceAccountOIDC_failed_to_delete_metadata() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		List<String> currentpolicies = new ArrayList<>();
		currentpolicies.add("default");
		currentpolicies.add("w_shared_mysafe01");
		currentpolicies.add("w_shared_mysafe02");
		OIDCGroup oidcGroup = new OIDCGroup("123-123-123", currentpolicies);
		when(OIDCUtil.getIdentityGroupDetails("testgroup1", token)).thenReturn(oidcGroup);
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to offboard IAM service account from TVault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.MULTI_STATUS).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 1)
					return getMockResponse(HttpStatus.MULTI_STATUS, true,"");

				return getMockResponse(HttpStatus.NO_CONTENT, true,"");
			}
		});

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.MULTI_STATUS, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_readFolders_successfully() throws IOException {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String path = "iamsvcacc/123456789012_testiamsvcacc01";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(
				"{\"folders\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"],\"path\":\"123456789012_testiamsvcacc01\",\"iamsvcaccName\":\"testiamsvcacc01\"}");

		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.readFolders(token, path);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_readFolders_failure() throws IOException {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String path = "iamsvcacc/123456789012_testiamsvcacc01";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body(
				"{\"errors\":[\"Unable to read the given path :" + path + "\"]}");

		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.FORBIDDEN, false, "{\"errors\":[\"1 error occurred:\n\t* permission denied\n\n\"]}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.readFolders(token, path);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createRole_success() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role created \"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		AWSLoginRole awsLoginRole = new AWSLoginRole("ec2", "mytestawsrole", "ami-fce3c696",
				"1234567890123", "us-east-2", "vpc-2f09a348", "subnet-1122aabb",
				"arn:aws:iam::8987887:role/test-role", "arn:aws:iam::877677878:instance-profile/exampleinstanceprofile",
				"\"[prod, dev\"]");
		when(awsAuthService.createRole(token, awsLoginRole, userDetails)).thenReturn(responseEntityExpected);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.createAWSRole(userDetails, token, awsLoginRole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_createIAMRole_success() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role created \"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		AWSIAMRole awsiamRole = new AWSIAMRole();
		awsiamRole.setAuth_type("iam");
		String[] arns = {"arn:aws:iam::123456789012:user/tst"};
		awsiamRole.setBound_iam_principal_arn(arns);
		String[] policies = {"default"};
		awsiamRole.setPolicies(policies);
		awsiamRole.setResolve_aws_unique_ids(true);
		awsiamRole.setRole("string");
		when(awsiamAuthService.createIAMRole(awsiamRole, token, userDetails)).thenReturn(responseEntityExpected);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.createIAMRole(userDetails, token, awsiamRole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_addAwsRoleToIAMSvcacc_succssfully_iam() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role successfully associated with IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"\\\"[prod\",\"dev\\\"]\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.addAwsRoleToIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_addAwsRoleToIAMSvcacc_succssfully_ec2() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role successfully associated with IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"\\\"[prod\",\"dev\\\"]\" ], \"auth_type\":\"ec2\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(awsAuthService.configureAWSRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.addAwsRoleToIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_addAwsRoleToIAMSvcacc_ec2_metadata_failure() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Please try again\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"\\\"[prod\",\"dev\\\"]\" ], \"auth_type\":\"ec2\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(awsAuthService.configureAWSRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.addAwsRoleToIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_addAwsRoleToIAMSvcacc_iam_metadata_failure() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Please try again\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"\\\"[prod\",\"dev\\\"]\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.addAwsRoleToIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_addAwsRoleToIAMSvcacc_failure() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Role configuration failed. Try Again\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"\\\"[prod\",\"dev\\\"]\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.addAwsRoleToIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_addAwsRoleToIAMSvcacc_failure_403() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to add AWS Role to this IAM service account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.addAwsRoleToIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_removeAWSRoleFromIAMSvcacc_succssfully_iam() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role is successfully removed from IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeAWSRoleFromIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_removeAWSRoleFromIAMSvcacc_succssfully_ec2() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role is successfully removed from IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"ec2\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(awsAuthService.configureAWSRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeAWSRoleFromIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);

	}

	@Test
	public void test_removeAWSRoleFromIAMSvcacc_metadata_failure() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Please try again\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"ec2\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(awsAuthService.configureAWSRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeAWSRoleFromIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_removeAWSRoleFromIAMSvcacc_failure() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to remove AWS Role from the IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"ec2\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.BAD_REQUEST, true, "");
		when(awsAuthService.configureAWSRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeAWSRoleFromIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_removeAWSRoleFromIAMSvcacc_failure_403() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to remove AWS Role from IAM Service Account\"]}");
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "read", "1234568990");

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeAWSRoleFromIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}



	@Test
	public void testOnboardIAMServiceAccountNotAuthorized() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);
		// System under test
		String expectedResponse = "{\"errors\":[\"Access denied. Not authorized to perform onboarding for IAM service accounts.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body(expectedResponse);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccount_invalid_secret() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");

		List<IAMSecrets> iamSecrets = new ArrayList<>();
		IAMSecrets iamSecret = new IAMSecrets();
		iamSecret.setAccessKeyId("testaccesskey555");
		iamSecrets.add(iamSecret);
		iamSecret.setAccessKeyId("testaccesskey555");
		iamSecrets.add(iamSecret);
		serviceAccount.setSecret(iamSecrets);

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to onboard IAM service account. Invalid secret data in request.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccount_duplicate_secret() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");

		List<IAMSecrets> iamSecrets = new ArrayList<>();
		IAMSecrets iamSecret = new IAMSecrets();
		iamSecret.setAccessKeyId("testaccesskey555");
		iamSecret.setExpiryDateEpoch(123L);
		iamSecrets.add(iamSecret);
		serviceAccount.setSecret(iamSecrets);
		IAMSecrets iamSecret2 = new IAMSecrets();
		iamSecret2.setAccessKeyId("testaccesskey555");
		iamSecret2.setExpiryDateEpoch(123L);
		iamSecrets.add(iamSecret2);
		serviceAccount.setSecret(iamSecrets);

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to onboard IAM service account. Invalid secret data in request.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccount_invalid_secret_expiry() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");

		List<IAMSecrets> iamSecrets = new ArrayList<>();
		IAMSecrets iamSecret = new IAMSecrets();
		iamSecret.setAccessKeyId("testaccesskey555");
		iamSecrets.add(iamSecret);
		iamSecret.setAccessKeyId("testaccesskey555");
		iamSecrets.add(iamSecret);
		serviceAccount.setSecret(iamSecrets);

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to onboard IAM service account. Invalid secret data in request.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccount_invalid_secret_empty() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");

		List<IAMSecrets> iamSecrets = new ArrayList<>();
		serviceAccount.setSecret(iamSecrets);

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to onboard IAM service account. Invalid secret data in request.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccountAlreadyExists() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("svc_tvt_test13", "12234237890", "normaluser");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		String expectedResponse = "{\"errors\":[\"Failed to onboard IAM Service Account. IAM Service account is already onboarded\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(expectedResponse);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccountMetaDataCreationFailed() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(false);

		// System under test
		String expectedResponse = "{\"errors\":[\"Metadata creation failed for IAM Service Account.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.MULTI_STATUS).body(expectedResponse);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.MULTI_STATUS, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccountPolicyCreationFailed() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.MULTI_STATUS)
				.body("{\"messages\":[\"Failed to create some of the policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.any(), Mockito.any())).thenReturn(createPolicyResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.any(), Mockito.any())).thenReturn(deletePolicyResponse);

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true,""));

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to onboard IAM service account. Policy creation failed.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(expectedResponse);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void testOnboardIAMServiceAccountAddOwnerFailed() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = new IAMServiceAccount();
		serviceAccount.setUserName("testaccount");
		serviceAccount.setAwsAccountId("1234567");
		serviceAccount.setAwsAccountName("testaccount1");
		serviceAccount.setOwnerNtid("normaluser");
		serviceAccount.setOwnerEmail("normaluser@testmail.com");
		serviceAccount.setApplicationId("app1");
		serviceAccount.setApplicationName("App1");
		serviceAccount.setApplicationTag("App1");
		serviceAccount.setCreatedAtEpoch(12345L);

		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.any(), Mockito.any())).thenReturn(createPolicyResponse);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, false, "{\"errors\":[\"Failed to add user to the IAM Service Account\"]}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
//		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
//				.thenReturn(ldapConfigureResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 1)
					return getMockResponse(HttpStatus.OK, true, "");

				return ldapConfigureResponse;
			}
		});

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.any(), Mockito.any())).thenReturn(deletePolicyResponse);

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true,""));

		// System under test
		String expectedResponse = "{\"errors\":[\"Failed to onboard IAM service account. Association of owner permission failed\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_deleteIAMServiceAccountCreds_Successfull() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);
		IAMServiceAccountAccessKey iamServiceAccountAccessKey = new IAMServiceAccountAccessKey(accessKeyId, iamServiceAccountName, awsAccountId);
		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"folder_1\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"testaccesskey\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"1234567890\",\"expiryDateEpoch\":1609845308000,\"userName\":\"svc_vault_test5\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		when(iamServiceAccountUtils.deleteAccessKeyFromIAMSvcAccMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId)).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, iamMetaDataStr));

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"IAM Service account access key deleted successfully\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.deleteIAMServiceAccountCreds(userDetails, token, iamServiceAccountAccessKey);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_deleteIAMServiceAccountCreds_IAM_Filed() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(false);
		IAMServiceAccountAccessKey iamServiceAccountAccessKey = new IAMServiceAccountAccessKey(accessKeyId, iamServiceAccountName, awsAccountId);
		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));

		when(iamServiceAccountUtils.deleteAccessKeyFromIAMSvcAccMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId)).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, iamMetaDataStr));

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to delete IAM Service account access key from IAM.\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.deleteIAMServiceAccountCreds(userDetails, token, iamServiceAccountAccessKey);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_deleteIAMServiceAccountCreds_Metadata_Update_Failed() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);
		IAMServiceAccountAccessKey iamServiceAccountAccessKey = new IAMServiceAccountAccessKey(accessKeyId, iamServiceAccountName, awsAccountId);
		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"folder_1\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"testaccesskey\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"1234567890\",\"expiryDateEpoch\":1609845308000,\"userName\":\"svc_vault_test5\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		when(iamServiceAccountUtils.deleteAccessKeyFromIAMSvcAccMetadata(token, awsAccountId, iamServiceAccountName, accessKeyId)).thenReturn(getMockResponse(HttpStatus.BAD_REQUEST, true, iamMetaDataStr));

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add IAM Service account accesskey. Metadata update failed.\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.deleteIAMServiceAccountCreds(userDetails, token, iamServiceAccountAccessKey);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_deleteIAMServiceAccountCreds_Failed() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));
		when(iamServiceAccountUtils.deleteIAMAccesskeyFromIAM(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);
		IAMServiceAccountAccessKey iamServiceAccountAccessKey = new IAMServiceAccountAccessKey(accessKeyId, iamServiceAccountName, awsAccountId);
		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.FORBIDDEN, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"folder_1\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"testaccesskey\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"1234567890\",\"expiryDateEpoch\":1609845308000,\"userName\":\"svc_vault_test5\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to delete IAM Service account access key. Invalid metadata.\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.deleteIAMServiceAccountCreds(userDetails, token, iamServiceAccountAccessKey);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_deleteIAMServiceAccountCreds_failed_NoPermission() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"r_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("r_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));
		IAMServiceAccountAccessKey iamServiceAccountAccessKey = new IAMServiceAccountAccessKey(accessKeyId, iamServiceAccountName, awsAccountId);
		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied: No permission to delete this IAM service account access key\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.deleteIAMServiceAccountCreds(userDetails, token, iamServiceAccountAccessKey);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_deleteIAMServiceAccountCreds_failed_InvalidMetadata() {
		String iamServiceAccountName = "svc_vault_test5";
		String token = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_svc_vault_test5 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("w_iamsvcacc_1234567890_svc_vault_test5");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));
		IAMServiceAccountAccessKey iamServiceAccountAccessKey = new IAMServiceAccountAccessKey(accessKeyId, iamServiceAccountName, awsAccountId);
		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to delete IAM Service account accesskey. The given accesKey is not available in T-Vault with given IAM service account.\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.deleteIAMServiceAccountCreds(userDetails, token, iamServiceAccountAccessKey);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void test_writeIAMKey_successful() throws Exception {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testaccount";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey01";
		String accessKeySecret = "testsecret";
		Long expiryDateEpoch = new Long(1627603345);
		String createDate = "July 30, 2021 12:02:25 AM";
		String status = "";
		String path = "iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		String folderName = "secret_2";
		IAMServiceAccountSecret iamServiceAccount = new IAMServiceAccountSecret(iamSvcaccName, accessKeyId, accessKeySecret, expiryDateEpoch, awsAccountId, createDate, status);

		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount\", \"createdAtEpoch\": 1619823077, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":1627685477}]}, \"path\": \"iamsvcacc/1234567890_testaccount\"}";
		String metadataPath = "metadata/iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		when(reqProcessor.process("/read", "{\"path\":\""+metadataPath+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			IAMServiceAccountNode node = new IAMServiceAccountNode();
			List<String> folders = new ArrayList<String>();
			folders.add("secret_1");
			node.setPath(path);
			node.setIamsvcaccName(iamSvcaccName);
			node.setFolders(folders);
			String nodeStr = getJSON(node);
			when(JSONUtil.getJSON(Mockito.any(IAMServiceAccountNode.class))).thenReturn(nodeStr);
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"secret_1\"]}"));
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, path+"/"+folderName, iamSvcaccName, iamServiceAccount)).thenReturn(true);
			when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(token, awsAccountId, iamSvcaccName, iamServiceAccount)).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, iamMetaDataStr));
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
			when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		ResponseEntity<String> responseEntityExpected =  ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully added accesskey for the IAM service account\"]}");
		ResponseEntity<String> responseEntityActual = iamServiceAccountsService.writeIAMKey(token, iamServiceAccount);
		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_writeIAMKey_NoAccount() throws Exception {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testaccount";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey01";
		String accessKeySecret = "testsecret";
		Long expiryDateEpoch = new Long(1627603345);
		String createDate = "July 30, 2021 12:02:25 AM";
		String status = "";
		String path = "iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		String folderName = "secret_2";
		IAMServiceAccountSecret iamServiceAccount = new IAMServiceAccountSecret(iamSvcaccName, accessKeyId, accessKeySecret, expiryDateEpoch, awsAccountId, createDate, status);

		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount\", \"createdAtEpoch\": 1619823077, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":1627685477}]}, \"path\": \"iamsvcacc/1234567890_testaccount\"}";
		String metadataPath = "metadata/iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		when(reqProcessor.process("/read", "{\"path\":\""+metadataPath+"\"}", token)).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, iamMetaDataStr));

		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			IAMServiceAccountNode node = new IAMServiceAccountNode();
			List<String> folders = new ArrayList<String>();
			folders.add("secret_1");
			node.setPath(path);
			node.setIamsvcaccName(iamSvcaccName);
			node.setFolders(folders);
			String nodeStr = getJSON(node);
			when(JSONUtil.getJSON(Mockito.any(IAMServiceAccountNode.class))).thenReturn(nodeStr);
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"secret_1\"]}"));
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, path+"/"+folderName, iamSvcaccName, iamServiceAccount)).thenReturn(true);
			when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(token, awsAccountId, iamSvcaccName, iamServiceAccount)).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, iamMetaDataStr));
		} catch (IOException e) {
			e.printStackTrace();
		}
		ResponseEntity<String> responseEntityExpected =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add IAM Service account access key. Either account does not exist or invalid information (metadata) found for the account.\"]}");
		ResponseEntity<String> responseEntityActual = iamServiceAccountsService.writeIAMKey(token, iamServiceAccount);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_writeIAMKey_TwoKeysPresent() throws Exception {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testaccount";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey01";
		String accessKeySecret = "testsecret";
		Long expiryDateEpoch = new Long(1627603345);
		String createDate = "July 30, 2021 12:02:25 AM";
		String status = "";
		String path = "iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		String folderName = "secret_2";
		IAMServiceAccountSecret iamServiceAccount = new IAMServiceAccountSecret(iamSvcaccName, accessKeyId, accessKeySecret, expiryDateEpoch, awsAccountId, createDate, status);

		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount\", \"createdAtEpoch\": 1619823077, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":1627685477},{\"accessKeyId\":\"testaccesskey2\", \"expiryDuration\":1627685477}]}, \"path\": \"iamsvcacc/1234567890_testaccount\"}";
		String metadataPath = "metadata/iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		when(reqProcessor.process("/read", "{\"path\":\""+metadataPath+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			IAMServiceAccountNode node = new IAMServiceAccountNode();
			List<String> folders = new ArrayList<String>();
			folders.add("secret_1");
			node.setPath(path);
			node.setIamsvcaccName(iamSvcaccName);
			node.setFolders(folders);
			String nodeStr = getJSON(node);
			when(JSONUtil.getJSON(Mockito.any(IAMServiceAccountNode.class))).thenReturn(nodeStr);
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"secret_1\"]}"));
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, path+"/"+folderName, iamSvcaccName, iamServiceAccount)).thenReturn(true);
			when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(token, awsAccountId, iamSvcaccName, iamServiceAccount)).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, iamMetaDataStr));
		} catch (IOException e) {
			e.printStackTrace();
		}
		ResponseEntity<String> responseEntityExpected =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add IAM Service account accesskey. There are already two accesskeys available for this IAM Service Account.\"]}");
		ResponseEntity<String> responseEntityActual = iamServiceAccountsService.writeIAMKey(token, iamServiceAccount);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_writeIAMKey_ExistingKey() throws Exception {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testaccount";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String accessKeySecret = "testsecret";
		Long expiryDateEpoch = new Long(1627603345);
		String createDate = "July 30, 2021 12:02:25 AM";
		String status = "";
		String path = "iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		String folderName = "secret_2";
		IAMServiceAccountSecret iamServiceAccount = new IAMServiceAccountSecret(iamSvcaccName, accessKeyId, accessKeySecret, expiryDateEpoch, awsAccountId, createDate, status);

		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount\", \"createdAtEpoch\": 1619823077, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":1627685477}]}, \"path\": \"iamsvcacc/1234567890_testaccount\"}";
		String metadataPath = "metadata/iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		when(reqProcessor.process("/read", "{\"path\":\""+metadataPath+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			IAMServiceAccountNode node = new IAMServiceAccountNode();
			List<String> folders = new ArrayList<String>();
			folders.add("secret_1");
			node.setPath(path);
			node.setIamsvcaccName(iamSvcaccName);
			node.setFolders(folders);
			String nodeStr = getJSON(node);
			when(JSONUtil.getJSON(Mockito.any(IAMServiceAccountNode.class))).thenReturn(nodeStr);
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"secret_1\"]}"));
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, path+"/"+folderName, iamSvcaccName, iamServiceAccount)).thenReturn(true);
			when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(token, awsAccountId, iamSvcaccName, iamServiceAccount)).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, iamMetaDataStr));
		} catch (IOException e) {
			e.printStackTrace();
		}
		ResponseEntity<String> responseEntityExpected =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add IAM Service account accesskey. The given AccesKey is already available in T-Vault. Please delete it and add again.\"]}");
		ResponseEntity<String> responseEntityActual = iamServiceAccountsService.writeIAMKey(token, iamServiceAccount);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_writeIAMKey_MetadataUpdateFailed() throws Exception {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testaccount";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String accessKeySecret = "testsecret";
		Long expiryDateEpoch = new Long(1627603345);
		String createDate = "July 30, 2021 12:02:25 AM";
		String status = "";
		String path = "iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		String folderName = "secret_2";
		IAMServiceAccountSecret iamServiceAccount = new IAMServiceAccountSecret(iamSvcaccName, accessKeyId, accessKeySecret, expiryDateEpoch, awsAccountId, createDate, status);

		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount\", \"createdAtEpoch\": 1619823077, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_testaccount\"}";
		String metadataPath = "metadata/iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		when(reqProcessor.process("/read", "{\"path\":\""+metadataPath+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			IAMServiceAccountNode node = new IAMServiceAccountNode();
			List<String> folders = new ArrayList<String>();
			folders.add("secret_1");
			node.setPath(path);
			node.setIamsvcaccName(iamSvcaccName);
			node.setFolders(folders);
			String nodeStr = getJSON(node);
			when(JSONUtil.getJSON(Mockito.any(IAMServiceAccountNode.class))).thenReturn(nodeStr);
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"secret_1\"]}"));
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, path+"/"+folderName, iamSvcaccName, iamServiceAccount)).thenReturn(true);
			when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(token, awsAccountId, iamSvcaccName, iamServiceAccount)).thenReturn(null);
		} catch (IOException e) {
			e.printStackTrace();
		}
		ResponseEntity<String> responseEntityExpected =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add IAM Service account accesskey. Metadata update failed.\"]}");
		ResponseEntity<String> responseEntityActual = iamServiceAccountsService.writeIAMKey(token, iamServiceAccount);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}
	@Test
	public void test_writeIAMKey_Fail() throws Exception {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testaccount";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey";
		String accessKeySecret = "testsecret";
		Long expiryDateEpoch = new Long(1627603345);
		String createDate = "July 30, 2021 12:02:25 AM";
		String status = "";
		String path = "iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		String folderName = "secret_2";
		IAMServiceAccountSecret iamServiceAccount = new IAMServiceAccountSecret(iamSvcaccName, accessKeyId, accessKeySecret, expiryDateEpoch, awsAccountId, createDate, status);

		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount\", \"createdAtEpoch\": 1619823077, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_testaccount\"}";
		String metadataPath = "metadata/iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		when(reqProcessor.process("/read", "{\"path\":\""+metadataPath+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			IAMServiceAccountNode node = new IAMServiceAccountNode();
			List<String> folders = new ArrayList<String>();
			folders.add("secret_1");
			node.setPath(path);
			node.setIamsvcaccName(iamSvcaccName);
			node.setFolders(folders);
			String nodeStr = getJSON(node);
			when(JSONUtil.getJSON(Mockito.any(IAMServiceAccountNode.class))).thenReturn(nodeStr);
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"secret_1\"]}"));
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, path+"/"+folderName, iamSvcaccName, iamServiceAccount)).thenReturn(false);
			when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(token, awsAccountId, iamSvcaccName, iamServiceAccount)).thenReturn(null);
		} catch (IOException e) {
			e.printStackTrace();
		}
		ResponseEntity<String> responseEntityExpected =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to add IAM Service account accesskey.\"]}");
		ResponseEntity<String> responseEntityActual = iamServiceAccountsService.writeIAMKey(token, iamServiceAccount);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}
	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_successfully() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_as_admin_successfully() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(true));
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_read_identity_policy_successfully() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"default\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("default");
		policies.add("r_iamsvcacc_1234567890_testiamsvcacc01");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_write_identity_policy_successfully() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"default\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("default");
		policies.add("w_iamsvcacc_1234567890_testiamsvcacc01");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_with_approle_success() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		UserDetails userDetails = getMockUser(false);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"read\"}, \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		Map<String, Object> appRoleMap = new HashMap<>();
		appRoleMap.put("approle1", "read");
		when(ControllerUtil.parseJson("{\"approle1\":\"read\"}")).thenReturn(appRoleMap);

		AppRoleMetadata appRoleMetadata = new AppRoleMetadata();
		AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
		appRoleMetadataDetails.setCreatedBy(userDetails.getUsername());
		appRoleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);
		when(appRoleService.readAppRoleMetadata(Mockito.any(), Mockito.any())).thenReturn(appRoleMetadata);

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_with_awsrole_success() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		UserDetails userDetails = getMockUser(false);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"read\"}, \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		Map<String, Object> appRoleMap = new HashMap<>();
		appRoleMap.put("approle1", "read");
		when(ControllerUtil.parseJson("{\"approle1\":\"read\"}")).thenReturn(appRoleMap);

		AppRoleMetadata appRoleMetadata = new AppRoleMetadata();
		AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
		appRoleMetadataDetails.setCreatedBy("aPerson");
		appRoleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);
		when(appRoleService.readAppRoleMetadata(Mockito.any(), Mockito.any())).thenReturn(appRoleMetadata);

		Map<String, Object> awsRoleMap = new HashMap<>();
		awsRoleMap.put("awsrole1", "write");
		when(ControllerUtil.parseJson("{\"aws123\":\"read\"}")).thenReturn(awsRoleMap);

		when(reqProcessor.process(Mockito.eq("/read"), Mockito.eq("{\"path\":\"metadata/awsrole/awsrole1\"}"), Mockito.any()))
				.thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"createdBy\":\"normaluser\",\"name\":\"test\",\"sharedTo\":null}}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_with_approle_deny_failure() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		UserDetails userDetails = getMockUser(false);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"app-roles\":{\"approle1\":\"deny\"}, \"aws-roles\": {\"aws123\": \"read\"}, \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		Map<String, Object> appRoleMap = new HashMap<>();
		appRoleMap.put("approle1", "deny");
		when(ControllerUtil.parseJson("{\"approle1\":\"deny\"}")).thenReturn(appRoleMap);

		AppRoleMetadata appRoleMetadata = new AppRoleMetadata();
		AppRoleMetadataDetails appRoleMetadataDetails = new AppRoleMetadataDetails();
		appRoleMetadataDetails.setCreatedBy(userDetails.getUsername());
		appRoleMetadata.setAppRoleMetadataDetails(appRoleMetadataDetails);
		when(appRoleService.readAppRoleMetadata(Mockito.any(), Mockito.any())).thenReturn(appRoleMetadata);

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, userDetails);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_with_awsrole_deny_failure() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		UserDetails userDetails = getMockUser(false);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"deny\"}, \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		Map<String, Object> awsRoleMap = new HashMap<>();
		awsRoleMap.put("awsrole1", "deny");
		when(ControllerUtil.parseJson("{\"aws123\":\"deny\"}")).thenReturn(awsRoleMap);

		when(reqProcessor.process(Mockito.eq("/read"), Mockito.eq("{\"path\":\"metadata/awsrole/awsrole1\"}"), Mockito.any()))
				.thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"createdBy\":\"normaluser\",\"name\":\"test\",\"sharedTo\":null}}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, userDetails);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_with_approle_null_metadata_failure() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"read\"}, \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		Map<String, Object> appRoleMap = new HashMap<>();
		appRoleMap.put("approle1", "read");
		when(ControllerUtil.parseJson("{\"approle1\":\"read\"}")).thenReturn(appRoleMap);

		Map<String, Object> awsRoleMap = new HashMap<>();
		appRoleMap.put("awsrole1", "write");
		when(ControllerUtil.parseJson("{\"aws123\":\"read\"}")).thenReturn(awsRoleMap);

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_empty_response_map_failure() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser1\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_notauthorized_failed() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"default\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("default");

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("default");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		// System under test
		String expectedResponse = "{\"errors\":[\"Access denied. Not authorized to perform getting the list of IAM service account access keys.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_deny_failed() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":" +
				"[\"r_iamsvcacc_1234567890_testiamsvcacc01, d_iamsvcacc_1234567890_testiamsvcacc01 \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("default");
		policies.add("r_iamsvcacc_1234567890_testiamsvcacc01");
		policies.add("d_iamsvcacc_1234567890_testiamsvcacc01");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		// System under test
		String expectedResponse = "{\"errors\":[\"Access denied. Not authorized to perform getting the list of IAM service account access keys.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_failed_Empty() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"123456789012\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test.test1@T-mobile.com\",\"owner_ntid\":\"testuser\",\"secret\":[],\"userName\":\"testiamsvcacc01\",\"users\":{\"testuser1\":\"write\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
	}

	@Test
	public void test_getListOfIAMServiceAccountAccessKeys_no_account_found_failure() throws IOException {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";

		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		when(OIDCUtil.renewUserToken(tkn)).thenReturn(lookupResponse);
		Map<String, Object> dataMap = new HashMap<>();
		List<String> policies = new ArrayList<>();
		policies.add("iamportal_admin_policy");
		dataMap.put("policies", policies);
		when(ControllerUtil.parseJson(lookupResponse.getResponse())).thenReturn(dataMap);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567890_testiamsvcacc01\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(
				getMockResponse(HttpStatus.NOT_FOUND, false, "{}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.getListOfIAMServiceAccountAccessKeys(tkn, iamSvcaccName, awsAccountId, getMockUser(false));
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntity.getBody(), "{\"errors\":[\"No Iam Service Account with testiamsvcacc01.\"]}");
	}

	@Test
	public void test_createAccessKeys_success() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process("/iamsvcacct", "{\"path\":\"" + path + "\"}", token)).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, ""));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_as_admin_successfully() {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String[] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		UserDetails userDetails = getMockUser(true);
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process("/iamsvcacct", "{\"path\":\"" + path + "\"}", tkn)).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, ""));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(tkn), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, tkn, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_io_exception_failure() {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		JsonElement jsonElement = mock(JsonElement.class);
		when(jsonElement.getAsJsonArray()).thenThrow(new IllegalStateException("..."){ });

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process("/iamsvcacct", "{\"path\":\"" + path + "\"}", tkn)).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, ""));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(tkn), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, tkn, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_no_secret_found_failure() {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process("/iamsvcacct", "{\"path\":\"" + path + "\"}", tkn))
				.thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, ""));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(tkn), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(tkn)))
				.thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, false, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, tkn, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_account_not_found_failure() {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process("/iamsvcacct", "{\"path\":\"" + path + "\"}", tkn))
				.thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, ""));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(tkn), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(tkn)))
				.thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, false, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, tkn, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_access_denied_failure() {
		String tkn = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(tkn, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", tkn)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", tkn)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process("/iamsvcacct", "{\"path\":\"" + path + "\"}", tkn))
				.thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, ""));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(tkn), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(tkn)))
				.thenReturn(getMockResponse(HttpStatus.FORBIDDEN, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(tkn))).thenReturn(getMockResponse(HttpStatus.OK, false, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, tkn, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_failed_two_key_exists() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}, {\"accessKeyId\":\"1212zdasd1\",\"expiryDuration\":\"1086073200000\"}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to create access key secrets for IAM service account. Two AccessKeyIds already available for this IAM Service Account.\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_failed_invalid_metadata() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true,
				""));

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to read metadata for this IAM Service account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_success_second_key() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\": {\"accessKeyId\":\"1212zdasd\",\"expiryDateEpoch\":1086073200000}}"));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_failed_406() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(406);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(null);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to create access key secrets for IAM Service Account. Cannot exceed quota (2) for AccessKeys Per IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_failed_500() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(500);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(null);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to create access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_createAccessKeys_failed_403() {
		String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"r_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"r_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied: No permission to create secrets for this IAM service account.\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.FORBIDDEN, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
	@Test
	public void testRemoveGroupFromIAMSvcAcc_failure() {
		token = userDetails.getClientToken();
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Group is successfully removed from IAM Service Account\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		String metdataJsonString = "{\"data\":{\"groups\": {\"group1\": \"write\"},\"app-roles\":{\"selfserviceoidcsupportrole\":\"read\"},\"application_id\":1222,\"application_name\":\"T-Vault\",\"application_tag\":\"TVT\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"AWS-SEC\",\"createdAtEpoch\":1086073200000,\"isActivated\":true,\"owner_email\":\"test@testmail.com\",\"owner_ntid\":\"testid\",\"secret\":[{\"accessKeyId\":\"1212zdasd\",\"expiryDuration\":\"1086073200000\"}],\"userName\":\"testaccount\",\"users\":{\"testid\":\"write\"}}}";
		Response readResponse = getMockResponse(HttpStatus.OK, true, metdataJsonString);
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(readResponse);
		Map<String,Object> reqparams = null;
		try {
			reqparams = new ObjectMapper().readValue(metdataJsonString, new TypeReference<Map<String, Object>>(){});
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.parseJson(Mockito.any())).thenReturn(reqparams);
		ResponseEntity<String> responseEntity = iamServiceAccountsService.removeGroupFromIAMServiceAccount(token,
				iamSvcAccGroup, userDetails);
		assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, responseEntity.getStatusCode());

	}
	@Test
	public void test_readFolders_failurenotfound() throws IOException {
		String token = "testtoken";
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, false, "null"));
		String path = "iamsvcacc/123456789012_testiamsvcacc01";
		ResponseEntity<String> responseEntity = iamServiceAccountsService.readFolders(token, path);
		assertEquals(HttpStatus.NOT_FOUND, responseEntity.getStatusCode());
	}
	@Test
	public void test_readFolders_failure_internalservererror() throws IOException {
		String token = "testtoken";
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.INTERNAL_SERVER_ERROR, false, "{\"errors\":[\"1 error occurred:\n\t* internalservererror\n\n\"]}"));
		String path = "iamsvcacc/123456789012_testiamsvcacc01";
		ResponseEntity<String> responseEntity = iamServiceAccountsService.readFolders(token, path);
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntity.getStatusCode());

	}
	@Test
	public void test_AssociateAppRole_failure() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle successfully associated with IAM Service Account\"]}");
		String token = "testtoken";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}",token)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.associateApproletoIAMsvcacc(userDetails, token, serviceAccountApprole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());


	}

	@Test
	public void test_AssociateAppRole_exception() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle successfully associated with IAM Service Account\"]}");
		String token = "testtoken";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "*null");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}",token)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.associateApproletoIAMsvcacc(userDetails, token, serviceAccountApprole);

		assertEquals(HttpStatus.OK, responseEntityActual.getStatusCode());
	}
	@Test
	public void test_AssociateAppRole_nocontent() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle successfully associated with IAM Service Account\"]}");
		String token = "testtoken";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}",token)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.BAD_REQUEST, false, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.associateApproletoIAMsvcacc(userDetails, token, serviceAccountApprole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());


	}
	@Test
	public void test_removeApproleFromIAMSvcAcc_nocontent() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Approle is successfully removed(if existed) from IAM Service Account\"]}");
		String token = "testtoken";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountApprole serviceAccountApprole = new IAMServiceAccountApprole("testsvcname", "role1", "write", "1234567890");

		String [] policies = {"o_iamsvcacc_1234567890_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response appRoleResponse = getMockResponse(HttpStatus.OK, true, "{\"data\": {\"policies\":\"w_iamsvcacc_1234567890_testsvcname\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"role1\"}",token)).thenReturn(appRoleResponse);
		Response configureAppRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(appRoleService.configureApprole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAppRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.BAD_REQUEST, false, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeApproleFromIAMSvcAcc(userDetails, token, serviceAccountApprole);

		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseEntityActual.getStatusCode());


	}
	@Test
	public void test_addAwsRoleToIAMSvcacc_invalid() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role successfully associated with IAM Service Account\"]}");
		String token = "testtoken";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +" [ \"\\\"[prod\",\"dev\\\"]\" ], \"auth_type\":\"ec2\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(awsAuthService.configureAWSRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);

		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.addAwsRoleToIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());


	}
	@Test
	public void test_removeAWSRoleFromIAMSvcacc_invalid() throws Exception {

		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role is successfully removed from IAM Service Account\"]}");
		String token = "testtoken";
		UserDetails userDetails = getMockUser(false);
		IAMServiceAccountAWSRole serviceAccountAWSRole = new IAMServiceAccountAWSRole("testsvcname", "role1", "", "1234568990");

		String [] policies = {"o_iamsvcacc_1234568990_testsvcname"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"role1\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.OK, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);
		Response updateMetadataResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(ControllerUtil.updateMetadata(Mockito.anyMap(),Mockito.anyString())).thenReturn(updateMetadataResponse);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"initialPasswordReset\":true,\"managedBy\":\"auser\",\"name\":\"svc_vault_test5\",\"users\":{\"auser\":\"sudo\"}}}"));

		ResponseEntity<String> responseEntityActual =  iamServiceAccountsService.removeAWSRoleFromIAMSvcacc(userDetails, token, serviceAccountAWSRole);

		assertEquals(HttpStatus.BAD_REQUEST, responseEntityActual.getStatusCode());


	}
	@Test
	public void testAddGroupToIAMSvcAcc_acessinvalid() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "owner", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Invalid value specified for access. Valid values are read, write, deny\"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
	@Test
	public void testAddGroupToIAMSvcAcc_userpass() {
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "write", "1234567");
		userDetails = getMockUser(false);
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"This operation is not supported for Userpass authentication. \"]}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "userpass");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));
		ResponseEntity<String> responseEntity = iamServiceAccountsService.addGroupToIAMServiceAccount(token,
				iamSvcAccGroup, userDetails, false);
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
	@Test
	public void test_addUserToIAMServiceAccount_invalid_permission() {

		String iamServiceAccountName = "svc_vault_test5";
		String sampletok = "123123123123";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(sampletok);
		when(policyUtils.getCurrentPolicies(sampletok, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(sampletok))).thenReturn(metaActivatedResponse);

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", sampletok)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(sampletok, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(sampletok), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(sampletok, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);


		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", sampletok)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(sampletok)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Invalid value specified for access. Valid values are read, write, deny\"]}");
		IAMServiceAccountUser iamServiceAccountUser =  new IAMServiceAccountUser(iamServiceAccountName, "normaluser", "owner",awsAccountId);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", sampletok)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> actualResponse = iamServiceAccountsService.addUserToIAMServiceAccount(sampletok, userDetails, iamServiceAccountUser, false);
		assertEquals(expectedResponse, actualResponse);
	}

	@Test
	public void testOnboardIAMServiceAccountfail() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setAdSelfSupportGroup("group1");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.anyString(), Mockito.any())).thenReturn(createPolicyResponse);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully completed onboarding of IAM service account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(
				"{\"messages\":[\"Successfully completed onboarding of IAM service account\"]}");

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		DirectoryUser directoryUser = new DirectoryUser();


		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// changes for add self support group
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "rotate", "1234567");
		userDetails = getMockUser(false);

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
	@Test
	public void testOnboardIAMServiceAccountfailu() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setAdSelfSupportGroup("group1");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getUserName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;

		String metaDataStr = "{ \"data\": {}, \"path\": \"iamsvcacc/1234567_testaccount\"}";
		String metadatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\":{}}";

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":604800000}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDatajson = "{\"path\":\"iamsvcacc/1234567_testaccount\",\"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345L, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345L}]}}";

		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");

		Map<String, Object> iamSvcAccPolicyMap = new HashMap<>();
		iamSvcAccPolicyMap.put("isActivated", false);

		IAMServiceAccountMetadataDetails iamServiceAccountMetadataDetails = populateIAMSvcAccMetaData(serviceAccount);
		IAMSvccAccMetadata iamSvccAccMetadata = new IAMSvccAccMetadata(iamSvccAccPath,
				iamServiceAccountMetadataDetails);

		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.NOT_FOUND, true, "{\"keys\":[\"12234237890_svc_tvt_test13\",\"1223455345_svc_tvt_test9\"]}"));

		when(JSONUtil.getJSON(Mockito.any())).thenReturn(metaDataStr);
		when(ControllerUtil.parseJson(metaDataStr)).thenReturn(iamSvcAccPolicyMap);
		when(ControllerUtil.convetToJson(iamSvcAccPolicyMap)).thenReturn(metadatajson);
		when(reqProcessor.process("/write", metadatajson, token)).thenReturn(responseNoContent);

		// create metadata
		when(JSONUtil.getJSON(iamSvccAccMetadata)).thenReturn(iamMetaDataStr);
		Map<String, Object> rqstParams = new HashMap<>();
		rqstParams.put("isActivated", false);
		rqstParams.put("userName", "testaccount");
		rqstParams.put("awsAccountId", "1234567");
		rqstParams.put("awsAccountName", "testaccount1");
		rqstParams.put("createdAtEpoch", 12345L);
		rqstParams.put("owner_ntid", "normaluser");
		rqstParams.put("owner_email", "normaluser@testmail.com");
		rqstParams.put("application_id", "app1");
		rqstParams.put("application_name", "App1");

		when(ControllerUtil.parseJson(iamMetaDataStr)).thenReturn(rqstParams);
		when(ControllerUtil.convetToJson(rqstParams)).thenReturn(iamMetaDatajson);
		when(ControllerUtil.createMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(true);

		// CreateIAMServiceAccountPolicies
		ResponseEntity<String> createPolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.createPolicy(Mockito.anyString(), Mockito.any())).thenReturn(createPolicyResponse);

		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully completed onboarding of IAM service account\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// changes for add self support group
		IAMServiceAccountGroup iamSvcAccGroup = new IAMServiceAccountGroup("testaccount", "group1", "rotate", "1234567");
		userDetails = getMockUser(false);

		String[] policies = { "o_iamsvcacc_1234567_testaccount" };
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);
		Response groupResp = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\",\"w_shared_mysafe01\",\"w_shared_mysafe02\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"group1\"}", token)).thenReturn(groupResp);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "ldap");
		ObjectMapper objMapper = new ObjectMapper();
		String responseJson = groupResp.getResponse();
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			resList.add("w_shared_mysafe01");
			resList.add("w_shared_mysafe02");
			when(ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson)).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPGroup(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"managedBy\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"}}}"));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(reqProcessor.process("/read", "{\"path\":\"metadata/iamsvcacc/1234567_testaccount\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		ResponseEntity<String> responseEntity = iamServiceAccountsService.onboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
	@Test
	public void testoffboardIAMServiceAccountuserpass_succss() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "userpass");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;
		Response userResponse1 = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");

		when(reqProcessor.process("/auth/userpass/read","{\"username\":\"normaluser\"}",token)).thenReturn(userResponse1);
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully offboarded IAM service account (if existed) from T-Vault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true,
				""));
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"aws123\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
	@Test
	public void testoffboardIAMServiceAccountoidc_succss() {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		ReflectionTestUtils.setField(iamServiceAccountsService, "vaultAuthMethod", "oidc");
		IAMServiceAccountOffboardRequest serviceAccount = new IAMServiceAccountOffboardRequest("testaccount", "1234567");
		String iamSvcAccName = serviceAccount.getAwsAccountId() + "_" + serviceAccount.getIamSvcAccName();
		String iamSvccAccPath = IAMServiceAccountConstants.IAM_SVCC_ACC_PATH + iamSvcAccName;
		Response userResponse1 = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");

		when(reqProcessor.process("/auth/userpass/read","{\"username\":\"normaluser\"}",token)).thenReturn(userResponse1);
		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// oidc mock
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		oidcEntityResponse.setEntityName("entity");
		List<String> policies = new ArrayList<>();
		policies.add("safeadmin");
		oidcEntityResponse.setPolicies(policies);
		ResponseEntity<OIDCEntityResponse> oidcResponse = ResponseEntity.status(HttpStatus.OK).body(oidcEntityResponse);
		ResponseEntity<OIDCEntityResponse> oidcResponse1 = ResponseEntity.status(HttpStatus.FORBIDDEN).body(oidcEntityResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse);
		when(OIDCUtil.oidcFetchEntityDetails(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.eq("normaluser"), Mockito.any(), Mockito.eq(true))).thenReturn(oidcResponse1);

		// delete policy mock
		ResponseEntity<String> deletePolicyResponse = ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Successfully created policies for IAM service account\"]}");
		when(accessService.deletePolicyInfo(Mockito.anyString(), Mockito.any())).thenReturn(deletePolicyResponse);

		// metadata mock
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"isActivated\":true,\"owner_ntid\":\"normaluser\",\"name\":\"svc_vault_test5\",\"users\":{\"normaluser\":\"sudo\"},\"groups\":{\"testgroup1\":\"read\"},\"app-roles\":{\"approle1\":\"read\"}, \"aws-roles\": {\"aws123\": \"read\"}}}"));

		// Mock user response and config user
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);

		// Mock group response and config group
		Response groupResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/ldap/groups", "{\"groupname\":\"testgroup1\"}", token)).thenReturn(groupResponse);
		when(ControllerUtil.configureLDAPGroup(Mockito.eq("testgroup1"), Mockito.any(), Mockito.eq(token))).thenReturn(ldapConfigureResponse);

		// Mock approle response and config approle
		Response approleResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		when(reqProcessor.process("/auth/approle/role/read","{\"role_name\":\"approle1\"}", token)).thenReturn(approleResponse);
		when(appRoleService.configureApprole(Mockito.eq("approle1"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, ""));

		// System under test
		String expectedResponse = "{\"messages\":[\"Successfully offboarded IAM service account (if existed) from T-Vault\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expectedResponse);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process(Mockito.eq("/read"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		when(reqProcessor.process(Mockito.eq("/delete"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true,
				""));
		String responseBody = "{ \"bound_account_id\": [ \"1234567890123\"],\"bound_ami_id\": [\"ami-fce3c696\" ], \"bound_iam_instance_profile_arn\": [\n" +
				"  \"arn:aws:iam::877677878:instance-profile/exampleinstanceprofile\" ], \"bound_iam_role_arn\": [\"arn:aws:iam::8987887:role/test-role\" ], " +
				"\"bound_vpc_id\": [    \"vpc-2f09a348\"], \"bound_subnet_id\": [ \"subnet-1122aabb\"],\"bound_region\": [\"us-east-2\"],\"policies\":" +
				" [ \"w_svcacct_testsvcname\" ], \"auth_type\":\"iam\"}";
		Response awsRoleResponse = getMockResponse(HttpStatus.OK, true, responseBody);
		when(reqProcessor.process("/auth/aws/roles","{\"role\":\"aws123\"}",token)).thenReturn(awsRoleResponse);
		Response configureAWSRoleResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		when(awsiamAuthService.configureAWSIAMRole(Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenReturn(configureAWSRoleResponse);

		ResponseEntity<String> responseEntity = iamServiceAccountsService.offboardIAMServiceAccount(token,
				serviceAccount, userDetails);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
	@Test
	public void test_writeIAMKey_forbidden() throws Exception {
		token = userDetails.getClientToken();
		String iamSvcaccName = "testaccount";
		String awsAccountId = "1234567890";
		String accessKeyId = "testaccesskey01";
		String accessKeySecret = "testsecret";
		Long expiryDateEpoch = new Long(1627603345);
		String createDate = "July 30, 2021 12:02:25 AM";
		String status = "";
		String path = "iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		String folderName = "secret_2";
		IAMServiceAccountSecret iamServiceAccount = new IAMServiceAccountSecret(iamSvcaccName, accessKeyId, accessKeySecret, expiryDateEpoch, awsAccountId, createDate, status);

		Response lookupResponse = getMockResponse(HttpStatus.NOT_FOUND, true, "{\"policies\":[\"iamportal_admin_policy\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount\", \"createdAtEpoch\": 1619823077, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":1627685477}]}, \"path\": \"iamsvcacc/1234567890_testaccount\"}";
		String metadataPath = "metadata/iamsvcacc/" + awsAccountId + "_" + iamSvcaccName;
		when(reqProcessor.process("/read", "{\"path\":\""+metadataPath+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true, iamMetaDataStr));

		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			IAMServiceAccountNode node = new IAMServiceAccountNode();
			List<String> folders = new ArrayList<String>();
			folders.add("secret_1");
			node.setPath(path);
			node.setIamsvcaccName(iamSvcaccName);
			node.setFolders(folders);
			String nodeStr = getJSON(node);
			when(JSONUtil.getJSON(Mockito.any(IAMServiceAccountNode.class))).thenReturn(nodeStr);
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"secret_1\"]}"));
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
			when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, path+"/"+folderName, iamSvcaccName, iamServiceAccount)).thenReturn(true);
			when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(token, awsAccountId, iamSvcaccName, iamServiceAccount)).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, iamMetaDataStr));
			when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
			when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		ResponseEntity<String> responseEntityExpected =  ResponseEntity.status(HttpStatus.FORBIDDEN).body(
				"{\"errors\":[\"Access denied. Not authorized to write accesskeys for IAM service accounts.\"]}");
		ResponseEntity<String> responseEntityActual = iamServiceAccountsService.writeIAMKey(token, iamServiceAccount);
		assertEquals(HttpStatus.FORBIDDEN, responseEntityActual.getStatusCode());
		assertEquals(responseEntityExpected, responseEntityActual);
	}

	@Test
	public void test_activateIAMServiceAccount_fail() {

		String iamServiceAccountName = "svc_vault_test5";
		token = userDetails.getClientToken();
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_svc_vault_test5";
		String iamSecret = "abcdefgh";
		String accessKeyId = "testaccesskey";
		String [] policies = {"o_iamsvcacc_1234567890_svc_vault_test5"};
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "");
		String iamMetaDataStr = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		String iamMetaDataStrActivated = "{ \"data\": {\"userName\": \"svc_vault_test5\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";

		Response metaResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStr);
		Response metaActivatedResponse = getMockResponse(HttpStatus.OK, true, iamMetaDataStrActivated);
		when(tokenUtils.getSelfServiceToken()).thenReturn(token);
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenAnswer(new Answer() {
			private int count = 0;

			public Object answer(InvocationOnMock invocation) {
				if (count++ == 1)
					return metaActivatedResponse;

				return metaResponse;
			}
		});

		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret(iamServiceAccountName, accessKeyId, iamSecret, 1609754282000L, awsAccountId, "", "");

		when(iamServiceAccountUtils.rotateIAMSecret(Mockito.any())).thenReturn(iamServiceAccountSecret);
		when(iamServiceAccountUtils.writeIAMSvcAccSecret(token, "iamsvcacc/1234567890_svc_vault_test5/secret_1", iamServiceAccountName, iamServiceAccountSecret)).thenReturn(true);
		when(iamServiceAccountUtils.updateIAMSvcAccNewAccessKeyIdInMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamServiceAccountName), Mockito.eq(accessKeyId), Mockito.any())).thenReturn(responseNoContent);
		when(iamServiceAccountUtils.updateActivatedStatusInMetadata(token, iamServiceAccountName, awsAccountId)).thenReturn(responseNoContent);


		// Add User to Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true,
				"{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		ResponseEntity<String> expectedResponse =  ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"IAM Service account activated successfully\"]}");
		ResponseEntity<String> actualResponse = iamServiceAccountsService.activateIAMServiceAccount(token, userDetails, iamServiceAccountName, awsAccountId);
		assertEquals(expectedResponse, actualResponse);
	}
	@Test
	public void test_createAccessKeys_forbiddenfalse() {
		token = userDetails.getClientToken();
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process("/iamsvcacct", "{\"path\":\"" + path + "\"}", token)).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, ""));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.FORBIDDEN, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
	@Test
	public void test_createAccessKeys_otherfalse() {
		token = userDetails.getClientToken();
		String iamSvcaccName = "testiamsvcacc01";
		String awsAccountId = "1234567890";
		String path = "metadata/iamsvcacc/1234567890_testiamsvcacc01";
		String [] policies = {"w_iamsvcacc_1234567890_testiamsvcacc01"};
		when(policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails)).thenReturn(policies);

		// Mock approle permission check
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"w_iamsvcacc_1234567890_testiamsvcacc01\"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);

		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(Arrays.asList(policies));
			when(iamServiceAccountUtils.getIdentityPoliciesAsListFromTokenLookupJson(Mockito.any(), Mockito.any())).thenReturn(new ArrayList<>());
		} catch (IOException e) {
			e.printStackTrace();
		}

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testiamsvcacc01\", \"awsAccountId\": \"1234567890\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 1609754282000, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": true, \"secret\":[]}, \"path\": \"iamsvcacc/1234567890_svc_vault_test5\"}";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		IAMServiceAccountSecret iamServiceAccountSecret = new IAMServiceAccountSecret();

		iamServiceAccountSecret.setAccessKeyId("testaccesskey");
		iamServiceAccountSecret.setExpiryDateEpoch(244253345456L);
		IAMServiceAccountSecretResponse iamServiceAccountSecretResponse = new IAMServiceAccountSecretResponse();
		iamServiceAccountSecretResponse.setStatusCode(200);
		iamServiceAccountSecretResponse.setIamServiceAccountSecret(iamServiceAccountSecret);
		when(iamServiceAccountUtils.createAccessKeys(Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName))).thenReturn(iamServiceAccountSecretResponse);
		when(reqProcessor.process("/iamsvcacct", "{\"path\":\"" + path + "\"}", token)).thenReturn(getMockResponse(HttpStatus.NOT_FOUND, true, ""));

		when(iamServiceAccountUtils.writeIAMSvcAccSecret(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

		when(iamServiceAccountUtils.addIAMSvcAccNewAccessKeyIdToMetadata(Mockito.eq(token), Mockito.eq(awsAccountId), Mockito.eq(iamSvcaccName), Mockito.any())).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, ""));
		when(reqProcessor.process(Mockito.eq("/iam/list"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.NO_CONTENT, true, "{\"keys\":[\"testiamsvcacc01_01\",\"testiamsvcacc01_02\"]}"));
		when(reqProcessor.process(Mockito.eq("/iamsvcacct"),Mockito.any(),Mockito.eq(token))).thenReturn(getMockResponse(HttpStatus.OK, true, "{\"data\":{\"accessKeyId\":\"1212zdasd\",\"accessKeySecret\":\"assOOetcHce1VugthF6KE9hqv2PWWbX3ULrpe1T\",\"awsAccountId\":\"123456789012\",\"expiryDateEpoch\":1609845308000,\"userName\":\"testiamsvcacc01_01\",\"expiryDate\":\"2021-01-05 16:45:08\"}}"));
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Successfully created access key secrets for IAM Service Account\"]}");

		ResponseEntity<String> responseEntity = iamServiceAccountsService.createAccessKeys(userDetails, token, iamSvcaccName, awsAccountId);
		assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}

	@Test
	public void test_updateIAMServiceAccount_badreq() throws IOException {
		userDetails = getMockUser(true);
		token = userDetails.getClientToken();
		IAMServiceAccount serviceAccount = generateIAMServiceAccount("testaccount", "1234567", "normaluser");
		serviceAccount.setOwnerEmail("oldowner@email.com");
		IAMServiceAccountTransfer iamSvcAccTransfer = new IAMServiceAccountTransfer(serviceAccount.getUserName(), serviceAccount.getAwsAccountId(),
				"newowner", "newowner@t-mobile.com", null, null, null, null);

		String iamMetaDataStr = "{ \"data\": {\"userName\": \"testaccount\", \"awsAccountId\": \"1234567\", \"awsAccountName\": \"testaccount1\", \"createdAtEpoch\": 12345, \"owner_ntid\": \"normaluser\", \"owner_email\": \"normaluser@testmail.com\", \"application_id\": \"app1\", \"application_name\": \"App1\", \"application_tag\": \"App1\", \"isActivated\": false, \"secret\":[{\"accessKeyId\":\"testaccesskey\", \"expiryDuration\":12345}]}, \"path\": \"iamsvcacc/1234567_testaccount\"}";

		// Get metadata
		String expectedMetadataBody = "{\"data\":{\"application_id\":\"app1\",\"application_name\":\"App1\",\"application_tag\":\"App1\",\"awsAccountId\":\"1234567\",\"awsAccountName\":\"testaccount1\",\"createdAtEpoch\":12345,\"groups\":{\"group1\":\"write\"},\"isActivated\":true,\"owner_email\":\"normaluser@test.com\",\"owner_ntid\":\"normaluser\",\"secret\":[{\"accessKeyId\":\"123456789123456789\",\"expiryDuration\":12345}],\"userName\":\"testaccount\"}}";
		Response expectedMetadataResponse = getMockResponse(HttpStatus.OK, true, expectedMetadataBody);
		when(reqProcessor.process(Mockito.eq("/sdb"), Mockito.any(), Mockito.eq(token))).thenReturn(expectedMetadataResponse);

		String path = "metadata/iamsvcacc/1234567_testaccount";
		when(reqProcessor.process("/read", "{\"path\":\""+path+"\"}", token)).thenReturn(getMockResponse(HttpStatus.OK, true,
				iamMetaDataStr));

		// Validations
		Response lookupResponse = getMockResponse(HttpStatus.OK, true, "{\"policies\":[\"iamportal_admin_policy \"]}");
		when(reqProcessor.process("/auth/tvault/lookup","{}", token)).thenReturn(lookupResponse);
		List<String> currentPolicies = new ArrayList<>();
		currentPolicies.add("iamportal_admin_policy");
		try {
			when(iamServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(Mockito.any(),Mockito.any())).thenReturn(currentPolicies);
		} catch (IOException e) {
			e.printStackTrace();
		}

		when(JSONUtil.getJSON(Mockito.any())).thenReturn("{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"read\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");
		when(reqProcessor.process(Mockito.eq("/iam/onboardedlist"), Mockito.any(), Mockito.eq(token))).thenReturn(getMockResponse(
				HttpStatus.OK, true, "{\"keys\":[\"sampletext\" ]}"));
		when(JSONUtil.getJSON(Mockito.any())).thenReturn(
				"{\"shared\":[{\"s3\":\"read\"},{\"s4\":\"write\"}],\"users\":[{\"s1\":\"read\"},{\"s2\":\"write\"}],\"svcacct\":[{\"test\":\"read\"}],\"iamsvcacc\":[{\"test\":\"sudo\"}],\"apps\":[{\"s5\":\"read\"},{\"s6\":\"write\"},{\"s7\":\"deny\"}]}");

		// Process and remove user permission from IAM Service Account
		Response userResponse = getMockResponse(HttpStatus.OK, true, "{\"data\":{\"bound_cidrs\":[],\"max_ttl\":0,\"policies\":[\"default\"],\"ttl\":0,\"groups\":\"admin\"}}");
		Response responseNoContent = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process(Mockito.eq("/auth/ldap/users"),Mockito.any(),Mockito.eq(token))).thenReturn(userResponse);

		when(ControllerUtil.configureLDAPUser(Mockito.eq("normaluser"), Mockito.any(), Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.eq(token))).thenReturn(responseNoContent);

		// Update metadata for new owner
		when(ControllerUtil.updateMetadataOnIAMSvcUpdate(Mockito.anyString(), Mockito.any(),
				Mockito.anyString())).thenReturn(getMockResponse(HttpStatus.OK, true,"{}"));

		// Add User to Service Account
		Response ldapConfigureResponse = getMockResponse(HttpStatus.NO_CONTENT, true, "{\"policies\":null}");
		when(reqProcessor.process("/auth/ldap/users", "{\"username\":\"normaluser\"}", token)).thenReturn(userResponse);

		try {
			List<String> resList = new ArrayList<>();
			resList.add("default");
			when(ControllerUtil.getPoliciesAsListFromJson(Mockito.any(), Mockito.any())).thenReturn(resList);
		} catch (IOException e) {
			e.printStackTrace();
		}
		when(ControllerUtil.configureLDAPUser(Mockito.eq("newowner"), Mockito.any(), Mockito.any(), Mockito.eq(token)))
				.thenReturn(ldapConfigureResponse);
		when(ControllerUtil.updateMetadata(Mockito.any(), Mockito.any())).thenReturn(responseNoContent);

		// Send email
		DirectoryUser directoryUser = new DirectoryUser();
		directoryUser.setDisplayName("testUserfirstname,lastname");
		directoryUser.setGivenName("testUser");
		directoryUser.setUserEmail("testUser@t-mobile.com");
		directoryUser.setUserId("normaluser");
		directoryUser.setUserName("normaluser");

		List<DirectoryUser> persons = new ArrayList<>();
		persons.add(directoryUser);
		DirectoryObjects users = new DirectoryObjects();
		DirectoryObjectsList usersList = new DirectoryObjectsList();
		usersList.setValues(persons.toArray(new DirectoryUser[persons.size()]));
		users.setData(usersList);

		ResponseEntity<DirectoryObjects> responseEntityCorpExpected = ResponseEntity.status(HttpStatus.OK).body(users);
		when(directoryService.getUserDetailsByCorpId(Mockito.any())).thenReturn(directoryUser);

		ReflectionTestUtils.setField(iamServiceAccountsService, "supportEmail", "support@abc.com");
		Mockito.doNothing().when(emailUtils).sendHtmlEmalFromTemplate(Mockito.any(), Mockito.any(), Mockito.any(),
				Mockito.any());

		ResponseEntity<String> responseEntity = iamServiceAccountsService.updateIAMServiceAccount(token,
				userDetails, iamSvcAccTransfer);
		String expectedResponse = "{\"messages\":[\"IAM Service Account has been successfully updated.\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
				"{\"errors\":[\"Invalid username or awsAccountId.\"]}");
		assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
		assertEquals(responseEntityExpected, responseEntity);
	}
}
