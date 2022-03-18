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

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.tmobile.cso.vault.api.common.IAMServiceAccountConstants;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.utils.*;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.SerializationUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tomcat.jni.Directory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.tmobile.cso.vault.api.common.AzureServiceAccountConstants;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.controller.ControllerUtil;
import com.tmobile.cso.vault.api.controller.OIDCUtil;
import com.tmobile.cso.vault.api.exception.LogMessage;
import com.tmobile.cso.vault.api.exception.TVaultValidationException;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;

@Component
public class AzureServicePrincipalAccountsService {
	
	@Autowired
	private RequestProcessor reqProcessor;
	
	@Autowired
	private AccessService accessService;
	
	@Autowired
	private TokenUtils tokenUtils;
	
	@Autowired
    private DirectoryService directoryService;
	
	@Value("${ad.notification.fromemail}")
	private String supportEmail;
	
	@Autowired
	private EmailUtils emailUtils;
	
	@Autowired
	private PolicyUtils policyUtils;
	
	@Value("${vault.auth.method}")
	private String vaultAuthMethod;
	
	@Autowired
	private OIDCUtil oidcUtil;
	
	@Autowired
	AzureServiceAccountUtils azureServiceAccountUtils;
	
	@Autowired
	private AppRoleService appRoleService;
	
	@Autowired
	private AWSAuthService awsAuthService;

	@Autowired
	private AWSIAMAuthService awsiamAuthService;

	@Autowired
	private CommonUtils commonUtils;

	@Value("${azurePortal.auth.adminPolicy}")
	private String azureSelfSupportAdminPolicyName;
	
	private static final String[] ACCESS_PERMISSIONS = { "read", "rotate", "deny", "sudo" };
	
	private static Logger log = LogManager.getLogger(AzureServicePrincipalAccountsService.class);

	private static final String PATHSTR = "{\"path\":\"";
	private static final String DELETEPATH = "/delete";
	private static final String ACCOUNTSTR = "account [%s].";
	private static final String ERRORBODYSTR = "{\"errors\":[\"Invalid value specified for access. Valid values are read, rotate, deny\"]}";
	private static final String ERRORINVALIDSTR = "{\"messages\":[\"User configuration failed. Invalid user\"]}";
	private static final String READPATH = "/auth/userpass/read";
	private static final String USERPATH = "/auth/ldap/users";
	private static final String USERS = "users";
	private static final String ERRORSTR = "{\"error\":";
	private static final String SECRETNOTFOUND = "No secret found for the secretKey :";
	private static final String GROUPSTR = "groups";
	private static final String AWSROLES = "aws-roles";
	private static final String UPDATEPOLICYSTR = "updateUserPolicyAssociationOnAzureSvcaccDelete";
	private static final String USERNAMESTR = "{\"username\":\"";
	private static final String UPDATEGROUPPOLICYSTR = "updateGroupPolicyAssociationOnAzureSvcaccDelete";
	private static final String GROUPPATH = "/auth/ldap/groups";
	private static final String GROUPNAMESTR = "{\"groupname\":\"";
	private static final String READROLEPATH = "/auth/approle/role/read";
	private static final String ROLENAME = "{\"role_name\":\"";
	private static final String POLICIESSTR = "policies";
	private static final String DELETEAZURE = "deleteAzureSvcAccountSecrets";
	private static final String SECRETSTR = "secret";
	private static final String ACCESS = "access";
	private static final String DELETE = "delete";
	private static final String POLICYSTR = "policy is [%s]";
	
	/**
	 * Onboard an Azure service account
	 *
	 * @param token
	 * @param ServiceAccount
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> onboardAzureServiceAccount(String token, AzureServiceAccount azureServiceAccount,
			UserDetails userDetails) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
				.put(LogMessage.MESSAGE,String.format("Start trying to onboard an Azure Service Account [%s]",azureServiceAccount.getServicePrincipalName()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		if (!isAuthorizedForAzureOnboardAndOffboard(token)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
					.put(LogMessage.MESSAGE,
							"Access denied. Not authorized to perform onboarding for Azure service accounts.")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Access denied. Not authorized to perform onboarding for Azure service accounts.\"]}");
		}
		azureServiceAccount.setServicePrincipalName(azureServiceAccount.getServicePrincipalName().toLowerCase());
		List<String> onboardedList = getOnboardedAzureServiceAccountList(token);
		String azureSvcAccName = azureServiceAccount.getServicePrincipalName();
		if (onboardedList.contains(azureSvcAccName)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
					.put(LogMessage.MESSAGE,
							"Failed to onboard Azure Service Account. Azure Service account is already onboarded")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Failed to onboard Azure Service Account. Azure Service account is already onboarded\"]}");
		}

		String azureSvccAccMetaPath = AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH + azureSvcAccName;

		AzureServiceAccountMetadataDetails azureServiceAccountMetadataDetails = constructAzureSvcAccMetaData(
				azureServiceAccount);

		// Create Metadata
		ResponseEntity<String> metadataCreationResponse = createAzureSvcAccMetadata(token, azureServiceAccountMetadataDetails, azureSvccAccMetaPath);
		if (HttpStatus.OK.equals(metadataCreationResponse.getStatusCode())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
					.put(LogMessage.MESSAGE,
							String.format("Successfully created Metadata for the Azure Service Account [%s]",
									azureSvccAccMetaPath))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
					.put(LogMessage.MESSAGE, String.format("Creating metadata for Azure Service Account [%s] failed.", azureSvcAccName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.MULTI_STATUS)
					.body("{\"errors\":[\"Metadata creation failed for Azure Service Account.\"]}");
		}

		// Create policies
		boolean azureSvcAccOwnerPermissionAddStatus = createAzureSvcAccPolicies(azureServiceAccount, azureSvcAccName);
		if (azureSvcAccOwnerPermissionAddStatus) {
			// Add sudo permission to owner
			boolean azureSvcAccCreationStatus = addSudoPermissionToOwner(token, azureServiceAccount, userDetails,
					azureSvcAccName);
			if (azureSvcAccCreationStatus) {
				Map<String, String> mailTemplateVariables = new HashMap<>();
				mailTemplateVariables.put("azureSvcAccName", azureSvcAccName);
				mailTemplateVariables.put("contactLink", supportEmail);
				sendMailToAzureSvcAccOwner(azureServiceAccount, azureSvcAccName,
						AzureServiceAccountConstants.AZURE_ONBOARD_EMAIL_SUBJECT,
						AzureServiceAccountConstants.AZURE_EMAIL_TEMPLATE_NAME, mailTemplateVariables,null);
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
						.put(LogMessage.MESSAGE,
								String.format("Successfully onboarded the Azure Service Account [%s] with owner [%s]",
										azureServiceAccount.getServicePrincipalName(),azureServiceAccount.getOwnerEmail()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
						.build()));
				return ResponseEntity.status(HttpStatus.OK)
						.body("{\"messages\":[\"Successfully completed onboarding of Azure service account\"]}");
			}
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
					.put(LogMessage.MESSAGE, "Failed to onboard Azure service account. Owner association failed.")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return rollBackAzureOnboardOnFailure(azureServiceAccount, azureSvcAccName, "onOwnerAssociationFailure");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
				.put(LogMessage.MESSAGE, "Failed to onboard  service account. Policy creation failed.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		return rollBackAzureOnboardOnFailure(azureServiceAccount, azureSvcAccName, "onPolicyFailure");

	}

	/**
	 * To check if the user/token has permission for onboarding or offboarding
	 *  service account.
	 * 
	 * @param token
	 * @return
	 */
	private boolean isAuthorizedForAzureOnboardAndOffboard(String token) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
				.put(LogMessage.MESSAGE,"Start checking isAuthorized For AzureOnboardAndOffboard")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		ObjectMapper objectMapper = new ObjectMapper();
		List<String> currentPolicies ;
		Response response = reqProcessor.process("/auth/tvault/lookup", "{}", token);
		if (HttpStatus.OK.equals(response.getHttpstatus())) {
			String responseJson = response.getResponse();
			try {
				currentPolicies = azureServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(objectMapper,
						responseJson);
				if (currentPolicies.contains(azureSelfSupportAdminPolicyName)) {
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
							.put(LogMessage.MESSAGE,
									"The User/Token has required policies to onboard/offboard Azure Service Account.")
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
					return true;
				}
			} catch (IOException e) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, "isAuthorizedForAzureOnboardAndOffboard")
						.put(LogMessage.MESSAGE, "Failed to parse policies from token")
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
				.put(LogMessage.MESSAGE,
						"The User/Token does not have required policies to onboard/offboard Azure Service Account.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		return false;
	}

	/**
	 * Get onboarded Azure service account list
	 *
	 * @param token
	 * @param userDetails
	 * @return
	 */
	private List<String> getOnboardedAzureServiceAccountList(String token) {
		ResponseEntity<String> onboardedResponse = getAllOnboardedAzureServiceAccounts(token);

		ObjectMapper objMapper = new ObjectMapper();
		List<String> onboardedList = new ArrayList<>();
		Map<String, String[]> requestMap = null;
		try {
			requestMap = objMapper.readValue(onboardedResponse.getBody(), new TypeReference<Map<String, String[]>>() {
			});
			if (requestMap != null && null != requestMap.get("keys")) {
				onboardedList = new ArrayList<>(Arrays.asList(requestMap.get("keys")));
			}
		} catch (IOException e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "get onboarded  Service Account list")
					.put(LogMessage.MESSAGE, String.format("Error creating onboarded list [%s]", e.getMessage()))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		}
		return onboardedList;
	}
	
	
	/**
	 * To get all Azure service accounts
	 *
	 * @param token
	 * @return
	 */
	private ResponseEntity<String> getAllOnboardedAzureServiceAccounts(String token) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "getAllOnboardedAzureServiceAccounts")
				.put(LogMessage.MESSAGE, "Trying to get all onboaded Azure service accounts")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		String metadataPath = AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH;

		Response response = reqProcessor.process("/azure/onboardedlist", PATHSTR + metadataPath + "\"}", token);

		if (HttpStatus.OK.equals(response.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "getAllOnboardedAzureServiceAccounts")
					.put(LogMessage.MESSAGE, "Successfully retrieved the list of Azure Service Accounts")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		} else if (HttpStatus.NOT_FOUND.equals(response.getHttpstatus())) {
			return ResponseEntity.status(HttpStatus.OK).body("{\"keys\":[]}");
		}
		return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}

	/**
	 * Method to populate AzureServiceAccountMetadataDetails object
	 *
	 * @param azureServiceAccount
	 * @return
	 */
	private AzureServiceAccountMetadataDetails constructAzureSvcAccMetaData(AzureServiceAccount azureServiceAccount) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "AzureServiceAccountMetadataDetails")
				.put(LogMessage.MESSAGE,"Start trying to fetch AzureServiceAccountMetadataDetails")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));

		AzureServiceAccountMetadataDetails azureServiceAccountMetadataDetails = new AzureServiceAccountMetadataDetails();
		List<AzureSecretsMetadata> azureSecretsMetadatas = new ArrayList<>();
		azureServiceAccountMetadataDetails.setServicePrincipalName(azureServiceAccount.getServicePrincipalName());
		azureServiceAccountMetadataDetails.setServicePrincipalId(azureServiceAccount.getServicePrincipalId());
		azureServiceAccountMetadataDetails
				.setServicePrincipalClientId(azureServiceAccount.getServicePrincipalClientId());
		azureServiceAccountMetadataDetails.setApplicationId(azureServiceAccount.getApplicationId());
		azureServiceAccountMetadataDetails.setApplicationName(azureServiceAccount.getApplicationName());
		azureServiceAccountMetadataDetails.setApplicationTag(azureServiceAccount.getApplicationTag());
		azureServiceAccountMetadataDetails.setCreatedAtEpoch(azureServiceAccount.getCreatedAtEpoch());
		azureServiceAccountMetadataDetails.setOwnerEmail(azureServiceAccount.getOwnerEmail());
		azureServiceAccountMetadataDetails.setOwnerNtid(azureServiceAccount.getOwnerNtid());
		for (AzureSecrets azureSecrets : azureServiceAccount.getSecret()) {
			AzureSecretsMetadata azureSecretsMetadata = new AzureSecretsMetadata();
			azureSecretsMetadata.setSecretKeyId(azureSecrets.getSecretKeyId());
			azureSecretsMetadata.setExpiryDuration(azureSecrets.getExpiryDuration());
			azureSecretsMetadatas.add(azureSecretsMetadata);
		}
		azureServiceAccountMetadataDetails.setSecret(azureSecretsMetadatas);
		azureServiceAccountMetadataDetails.setTenantId(azureServiceAccount.getTenantId());
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "AzureServiceAccountMetadataDetails")
				.put(LogMessage.MESSAGE,"AzureServiceAccountMetadataDetails fetched successfully")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		return azureServiceAccountMetadataDetails;
	}
	
	/**
	 * To create Metadata for the Azure Service Account
	 *
	 * @param token
	 * @param azureServiceAccountMetadataDetails
	 * @param azureSvccAccMetaPath
	 * @return
	 */
	private ResponseEntity<String> createAzureSvcAccMetadata(String token,
			AzureServiceAccountMetadataDetails azureServiceAccountMetadataDetails, String azureSvccAccMetaPath) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "createAzureSvcAccMetadata")
				.put(LogMessage.MESSAGE,"Start trying to create AzureSvcAccMetadata")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));

		AzureSvccAccMetadata azureSvccAccMetadata = new AzureSvccAccMetadata(azureSvccAccMetaPath, azureServiceAccountMetadataDetails);

		String jsonStr = JSONUtil.getJSON(azureSvccAccMetadata);
		Map<String, Object> rqstParams = ControllerUtil.parseJson(jsonStr);
		rqstParams.put("path", azureSvccAccMetaPath);
		String azureSvcAccDataJson = ControllerUtil.convetToJson(rqstParams);

		boolean azureSvcAccMetaDataCreationStatus = ControllerUtil.createMetadata(azureSvcAccDataJson, token);
		if (azureSvcAccMetaDataCreationStatus) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "createAzureSvcAccMetadata")
					.put(LogMessage.MESSAGE,
							String.format("Successfully created metadata for the Azure Service Account [%s]",
									azureServiceAccountMetadataDetails.getServicePrincipalName()))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.OK)
					.body("{\"messages\":[\"Successfully created Metadata for the Azure Service Account\"]}");
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "createAzureSvcAccMetadata")
					.put(LogMessage.MESSAGE, "Unable to create Metadata for the Azure Service Account")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		}
		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Failed to create Metadata for the Azure Service Account\"]}");
	}
	
	/**
	 * Method to create Azure service account policies as part of Azure service account onboarding.
	 * @param azureServiceAccount
	 * @param azureSvcAccName
	 * @return
	 */
	private boolean createAzureSvcAccPolicies(AzureServiceAccount azureServiceAccount, String azureSvcAccName) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
				.put(LogMessage.MESSAGE,
						String.format("Start trying to create policies for Azure service account [%s].", azureSvcAccName))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		ResponseEntity<String> SvcAccPolicyCreationResponse = createAzureServiceAccountPolicies(azureSvcAccName);
		if (HttpStatus.OK.equals(SvcAccPolicyCreationResponse.getStatusCode())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
					.put(LogMessage.MESSAGE,
							String.format("Successfully created policies for Azure service account [%s].", azureSvcAccName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return true;
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
					.put(LogMessage.MESSAGE, String.format("Failed to create policies for Azure service account [%s].",
							azureServiceAccount))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return false;
		}
	}
	
	/**
	 * Create policies for Azure service account
	 *
	 * @param azureSvcAccName
	 * @return
	 */
	private ResponseEntity<String> createAzureServiceAccountPolicies(String azureSvcAccName) {
		int succssCount = 0;
		for (String policyPrefix : TVaultConstants.getSvcAccPolicies().keySet()) {
			AccessPolicy accessPolicy = new AccessPolicy();
			String accessId = new StringBuffer().append(policyPrefix)
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccName).toString();
			accessPolicy.setAccessid(accessId);
			HashMap<String, String> accessMap = new HashMap<>();
			String CredsPath=new StringBuffer().append(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureSvcAccName).append("/*").toString();
			accessMap.put(CredsPath, TVaultConstants.getSvcAccPolicies().get(policyPrefix));
			// Attaching write permissions for owner
			if (TVaultConstants.getSvcAccPolicies().get(policyPrefix).equals(TVaultConstants.SUDO_POLICY)) {
				accessMap.put(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + azureSvcAccName + "/*",
						TVaultConstants.WRITE_POLICY);
				accessMap.put(AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH + azureSvcAccName,
						TVaultConstants.WRITE_POLICY);
			}
			if (TVaultConstants.getSvcAccPolicies().get(policyPrefix).equals(TVaultConstants.WRITE_POLICY)) {
				accessMap.put(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + azureSvcAccName + "/*",
						TVaultConstants.WRITE_POLICY);
				accessMap.put(AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH + azureSvcAccName,
						TVaultConstants.WRITE_POLICY);
			}
			accessPolicy.setAccess(accessMap);
			ResponseEntity<String> policyCreationStatus = accessService.createPolicy(tokenUtils.getSelfServiceToken(), accessPolicy);
			if (HttpStatus.OK.equals(policyCreationStatus.getStatusCode())) {
				succssCount++;
			}
		}
		if (succssCount == TVaultConstants.getSvcAccPolicies().size()) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "createAzureServiceAccountPolicies")
					.put(LogMessage.MESSAGE, "Successfully created policies for Azure Service Principal.")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.OK)
					.body("{\"messages\":[\"Successfully created policies for Azure Service Principal\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "createAzureServiceAccountPolicies")
				.put(LogMessage.MESSAGE, "Failed to create some of the policies for Azure Service Principal.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		return ResponseEntity.status(HttpStatus.MULTI_STATUS)
				.body("{\"messages\":[\"Failed to create some of the policies for Azure Service Principal\"]}");
	}

	/**
	 * Method to send mail to Azure Service account owner
	 * @param azureServiceAccount
	 * @param azureSvcAccName
	 * @param subject
	 * @param templateFileName
	 * @param mailTemplateVariables
	 * @param cc
	 */
	private void sendMailToAzureSvcAccOwner(AzureServiceAccount azureServiceAccount, String azureSvcAccName, String subject,
											String templateFileName, Map<String, String> mailTemplateVariables, List<String> cc) {
		// send email notification to Azure service account owner
		DirectoryUser directoryUser = getUserDetails(azureServiceAccount.getOwnerNtid());
		if (directoryUser != null) {
			String from = supportEmail;
			List<String> to = new ArrayList<>();
			to.add(azureServiceAccount.getOwnerEmail());
			String mailSubject = String.format(subject, azureSvcAccName!=null?azureSvcAccName:"");

			if (StringUtils.isEmpty(directoryUser.getDisplayName().trim())) {
				mailTemplateVariables.put("name", directoryUser.getUserName());
			} else {
				mailTemplateVariables.put("name", directoryUser.getDisplayName());
			}

			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION,
							String.format(
									"sendEmail for Azure Service account [%s] -  User " + "email=[%s] - subject = [%s]",
									azureSvcAccName, azureServiceAccount.getOwnerEmail(), mailSubject))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

			emailUtils.sendAzureSvcAccHtmlEmalFromTemplate(from, to, cc, mailSubject, mailTemplateVariables, templateFileName);
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "sendMailToAzureSvcAccOwner")
					.put(LogMessage.MESSAGE, String.format("Unable to get the Directory User details   "
							+ "for an user name =  [%s] ,  Emails might not send to owner for an Azure service account = [%s]",
							azureServiceAccount.getOwnerEmail(), azureSvcAccName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		}
	}
	
	/**
	 * Method to get the Directory User details
	 *
	 * @param userName
	 * @return
	 */
	private DirectoryUser getUserDetails(String userName) {
		DirectoryUser directoryUser = directoryService.getUserDetailsByCorpId(userName);
		if (StringUtils.isEmpty(directoryUser.getUserEmail())) {
			// Get user details from Corp domain (For sprint users)
			directoryUser = directoryService.getUserDetailsFromCorp(userName);
		}
		if (directoryUser != null) {
			if(directoryUser.getDisplayName() != null) {
				String[] displayName = directoryUser.getDisplayName().split(",");
				if (displayName.length > 1) {
					directoryUser.setDisplayName(displayName[1] + "  " + displayName[0]);
				}
			}else {
				directoryUser.setDisplayName(userName);
			}
		}
		return directoryUser;
	}
	
	/**
	 * Method to rollback Azure service account onboarding process on failure.
	 * @param azureServiceAccount
	 * @param azureSvcAccName
	 * @param onAction
	 * @return
	 */
	private ResponseEntity<String> rollBackAzureOnboardOnFailure(AzureServiceAccount azureServiceAccount,
				String azureSvcAccName, String onAction) {
		//Delete the Azure Service account policies
		deleteAzureServiceAccountPolicies(tokenUtils.getSelfServiceToken(), azureSvcAccName);
		//Deleting the Azure service account metadata
		OnboardedAzureServiceAccount azureSvcAccToRevert = new OnboardedAzureServiceAccount(
				azureServiceAccount.getServicePrincipalName(), azureServiceAccount.getOwnerNtid());
		ResponseEntity<String> azureMetaDataDeletionResponse = deleteAzureSvcAccount(tokenUtils.getSelfServiceToken(), azureSvcAccToRevert);
		if (azureMetaDataDeletionResponse != null
				&& HttpStatus.OK.equals(azureMetaDataDeletionResponse.getStatusCode())) {
			if (onAction.equals("onPolicyFailure")) {
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
						"{\"errors\":[\"Failed to onboard Azure service account. Policy creation failed.\"]}");
			}
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
					"{\"errors\":[\"Failed to onboard Azure service account. Association of owner permission failed\"]}");
		} else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
					"{\"errors\":[\"Failed to create Azure Service Account policies. Reverting Azure service account creation also failed.\"]}");
		}
	}
	
	/**
	 * Deletes Azure Service Account policies
	 * @param token
	 * @param azureSvcAccName
	 * @return
	 */
	private boolean deleteAzureServiceAccountPolicies(String token, String azureSvcAccName) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "deleteAzureServiceAccountPolicies").
				put(LogMessage.MESSAGE, "Start deleting policies for Azure service account.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		int succssCount = 0;
		boolean allPoliciesDeleted = false;
		for (String policyPrefix : TVaultConstants.getSvcAccPolicies().keySet()) {
			String accessId = new StringBuffer().append(policyPrefix).append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccName).toString();
			ResponseEntity<String> policyDeleteStatus = accessService.deletePolicyInfo(token, accessId);
			if (HttpStatus.OK.equals(policyDeleteStatus.getStatusCode())) {
				succssCount++;
			}
		}
		if (succssCount == TVaultConstants.getSvcAccPolicies().size()) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "deleteAzureServiceAccountPolicies").
					put(LogMessage.MESSAGE, "Successfully removed policies for Azure service account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			allPoliciesDeleted = true;
		}
		else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "deleteAzureServiceAccountPolicies").
					put(LogMessage.MESSAGE, "Failed to delete some of the policies for Azure service account.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
		}
		return allPoliciesDeleted;
	}
	
	/**
	 * Deletes the AzureSvcAccount
	 *
	 * @param token
	 * @param azureServiceAccount
	 * @return
	 */
	private ResponseEntity<String> deleteAzureSvcAccount(String token, OnboardedAzureServiceAccount azureServiceAccount) {
		String azureSvcAccName = azureServiceAccount.getServicePrincipalName();
		String azureSvcAccPath = AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH + azureSvcAccName;
		Response onboardingResponse = reqProcessor.process(DELETEPATH, PATHSTR + azureSvcAccPath + "\"}", token);

		if (onboardingResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)
				|| onboardingResponse.getHttpstatus().equals(HttpStatus.OK)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "deleteAzureSvcAccount")
					.put(LogMessage.MESSAGE, "Successfully deleted Azure service account.")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.OK)
					.body("{\"messages\":[\"Successfully deleted Azure service account.\"]}");
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "deleteAzureSvcAccount")
					.put(LogMessage.MESSAGE, "Failed to delete Azure service account.")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("{\"errors\":[\"Failed to delete Azure service account.\"]}");
		}
	}
	
	/**
	 * Method to add Sudo permission to owner as part of Azure onboarding.
	 * @param token
	 * @param azureServiceAccount
	 * @param userDetails
	 * @param azureSvcAccName
	 * @return
	 */
	private boolean addSudoPermissionToOwner(String token, AzureServiceAccount azureServiceAccount, UserDetails userDetails,
											 String azureSvcAccName) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
				.put(LogMessage.MESSAGE, String.format("Start trying to add sudo permission for the service account [%s] to " +
						"the user [%s]", azureSvcAccName, azureServiceAccount.getOwnerNtid()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		AzureServiceAccountUser azureServiceAccountUser = new AzureServiceAccountUser(azureServiceAccount.getServicePrincipalName(),
				azureServiceAccount.getOwnerNtid(), TVaultConstants.SUDO_POLICY);
		//Add sudo permisson to the Azure service account owner
		ResponseEntity<String> addUserToAzureSvcAccResponse = addUserToAzureServiceAccount(token, userDetails,
				azureServiceAccountUser, true);
		if (HttpStatus.OK.equals(addUserToAzureSvcAccResponse.getStatusCode())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
					.put(LogMessage.MESSAGE,
							String.format(
									"Successfully added owner permission to [%s] for Azure service " + ACCOUNTSTR,
									azureServiceAccount.getOwnerNtid(), azureSvcAccName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return true;
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_CREATION_TITLE)
				.put(LogMessage.MESSAGE,
						String.format("Failed to add owner permission to [%s] for Azure service " + ACCOUNTSTR,
								azureServiceAccount.getOwnerNtid(), azureSvcAccName))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		return false;

	}
	
	/**
	 * Add user to Azure Service principal.
	 *
	 * @param token
	 * @param userDetails
	 * @param azureServiceAccountUser
	 * @param isPartOfOnboard
	 * @return
	 */
	public ResponseEntity<String> addUserToAzureServiceAccount(String token, UserDetails userDetails,
			AzureServiceAccountUser azureServiceAccountUser, boolean isPartOfOnboard) {

		azureServiceAccountUser.setAzureSvcAccName(azureServiceAccountUser.getAzureSvcAccName().toLowerCase());
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		if (!userDetails.isAdmin()) {
			token = tokenUtils.getSelfServiceToken();
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("Start trying to add user to Azure Service principal [%s]", azureServiceAccountUser.getAzureSvcAccName()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));

		if (!isAzureSvcaccPermissionInputValid(azureServiceAccountUser.getAccess())) {
			log.error(
					JSONUtil.getJSON(ImmutableMap.<String, String>builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
							.put(LogMessage.MESSAGE, "Invalid input values")
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(ERRORBODYSTR);
		}
		if (azureServiceAccountUser.getAccess().equalsIgnoreCase(AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING)) {
			azureServiceAccountUser.setAccess(TVaultConstants.WRITE_POLICY);
		}

		boolean isAuthorized = isAuthorizedToAddPermissionInAzureSvcAcc(userDetails, azureServiceAccountUser.getAzureSvcAccName(), isPartOfOnboard);
		String uniqueASPaccName= azureServiceAccountUser.getAzureSvcAccName();
		if (isAuthorized) {
			// Only Sudo policy can be added (as part of onbord) before activation.
			if (!isAzureSvcaccActivated(token, userDetails, azureServiceAccountUser.getAzureSvcAccName())
					&& !TVaultConstants.SUDO_POLICY.equals(azureServiceAccountUser.getAccess())) {
				log.error(
						JSONUtil.getJSON(ImmutableMap.<String, String>builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
								.put(LogMessage.MESSAGE, String.format("Failed to add user permission to Azure Service account. [%s] is not activated.", azureServiceAccountUser.getAzureSvcAccName()))
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
						"{\"errors\":[\"Failed to add user permission to Azure Service account. Service Account is not activated. Please activate this service account and try again.\"]}");
			}

			if (isOwnerPemissionGettingChanged(azureServiceAccountUser, getOwnerNTIdFromMetadata(token, uniqueASPaccName), isPartOfOnboard)) {
				log.error(
						JSONUtil.getJSON(ImmutableMap.<String, String>builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
								.put(LogMessage.MESSAGE, "Failed to add user permission to Azure Service account. Owner permission cannot be changed..")
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
						"{\"errors\":[\"Failed to add user permission to Azure Service account. Owner permission cannot be changed.\"]}");
			}
			return getUserPoliciesForAddUserToAzureSvcAcc(token, userDetails, azureServiceAccountUser, oidcEntityResponse,
					azureServiceAccountUser.getAzureSvcAccName());

		} else {
			return ResponseEntity.status(HttpStatus.FORBIDDEN)
					.body("{\"errors\":[\"Access denied: No permission to add users to this Azure service account\"]}");
		}
	}
	
	/**
	 * Validates Azure Service Account permission inputs
	 *
	 * @param access
	 * @return
	 */
	public static boolean isAzureSvcaccPermissionInputValid(String access) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, "Validate input parameters")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		boolean isValidAccess = true;
		if (!org.apache.commons.lang3.ArrayUtils.contains(ACCESS_PERMISSIONS, access)) {
			isValidAccess = false;
		}
		return isValidAccess;
	}
	
	/**
	 * Check if user has the permission to add user to the Azure Service Account.
	 *
	 * @param userDetails
	 * @param serviceAccount
	 * @param access
	 * @param token
	 * @return
	 */
	public boolean isAuthorizedToAddPermissionInAzureSvcAcc(UserDetails userDetails, String serviceAccount,
			boolean isPartOfOnboard) {
		// Admin users can add sudo policy for owner while onboarding the azure service principal
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "isAuthorizedToAddPermissionInAzureSvcAcc").
				put(LogMessage.MESSAGE,"Start checking is Authorized To Add Permission In AzureSvcAcc").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (userDetails.isAdmin() || isPartOfOnboard) {
			return true;
		}
		// Owner of the service account can add/remove users, groups, aws roles and approles to service account
		String ownerPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.
				getKey(TVaultConstants.SUDO_POLICY)).append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(serviceAccount).toString();
		String [] policies = policyUtils.getCurrentPolicies(tokenUtils.getSelfServiceToken(), userDetails.getUsername(), userDetails);

		return ArrayUtils.contains(policies, ownerPolicy);
	}

	
	/**
	 * To check if the Azure service principal is activated.
	 *
	 * @param token
	 * @param userDetails
	 * @param SvcAccName
	 * @return
	 */
	private boolean isAzureSvcaccActivated(String token, UserDetails userDetails, String azureSvcAccName) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, "isAzureSvcaccActivated").
                put(LogMessage.MESSAGE,"Start checking whether AzureSvcacc is activated or not ").
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
		String azureAccPath = AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + azureSvcAccName;
		boolean activationStatus = false;
		Response metaResponse = getMetadata(token, userDetails, azureAccPath);
		if (metaResponse != null && HttpStatus.OK.equals(metaResponse.getHttpstatus())) {
			try {
				JsonNode status = new ObjectMapper().readTree(metaResponse.getResponse()).get("data")
						.get("isActivated");
				if (status != null) {
					activationStatus = Boolean.parseBoolean(status.asText());
				}
			} catch (IOException e) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, "isAzureSvcaccActivated")
						.put(LogMessage.MESSAGE,
								String.format("Failed to get Activation status for the Azure Service account [%s]",
										azureSvcAccName))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "isAzureSvcaccActivated")
					.put(LogMessage.MESSAGE,
							String.format("Metadata not found for Azure Service account [%s]", azureSvcAccName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		}
		return activationStatus;
	}
	
	/**
	 * Get metadata for Azure service account.
	 *
	 * @param token
	 * @param userDetails
	 * @param path
	 * @return
	 */
	private Response getMetadata(String token, UserDetails userDetails, String path) {
		if (!userDetails.isAdmin()) {
			token = tokenUtils.getSelfServiceToken();
		}
		if (path != null && path.startsWith("/")) {
			path = path.substring(1, path.length());
		}
		if (path != null && path.endsWith("/")) {
			path = path.substring(0, path.length() - 1);
		}
		String azureMetaDataPath = "metadata/" + path;
		return reqProcessor.process("/sdb", PATHSTR + azureMetaDataPath + "\"}", token);
	}

	/**
	 * Method to verify the user for add user to Azure service account.
	 * @param token
	 * @param userDetails
	 * @param azureServiceAccountUser
	 * @param oidcEntityResponse
	 * @param azureSvcaccName
	 * @return
	 */
	private ResponseEntity<String> getUserPoliciesForAddUserToAzureSvcAcc(String token, UserDetails userDetails,
			AzureServiceAccountUser azureServiceAccountUser, OIDCEntityResponse oidcEntityResponse,
			String azureSvcaccName) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "getUserPoliciesForAddUserToAzureSvcAcc").
				put(LogMessage.MESSAGE,"Start verifying the user policies for add user to Azure service account.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		Response userResponse = new Response();
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			userResponse = reqProcessor.process(READPATH, AzureServiceAccountConstants.USERNAME_PARAM_STRING + azureServiceAccountUser.getUsername() + "\"}",
					token);
		} else if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			userResponse = reqProcessor.process(USERPATH, AzureServiceAccountConstants.USERNAME_PARAM_STRING + azureServiceAccountUser.getUsername() + "\"}", token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			// OIDC implementation changes
			ResponseEntity<OIDCEntityResponse> responseEntity = oidcUtil.oidcFetchEntityDetails(token, azureServiceAccountUser.getUsername(),
					userDetails, true);
			if (!responseEntity.getStatusCode().equals(HttpStatus.OK)) {
				if (responseEntity.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
							.put(LogMessage.MESSAGE, String.format("Failed to fetch OIDC user for [%s]", azureServiceAccountUser.getUsername()))
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
					return ResponseEntity.status(HttpStatus.FORBIDDEN)
							.body("{\"messages\":[\"User configuration failed. Please try again.\"]}");
				}
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(ERRORINVALIDSTR);
			}

			oidcEntityResponse.setEntityName(responseEntity.getBody().getEntityName());
			oidcEntityResponse.setPolicies(responseEntity.getBody().getPolicies());
			userResponse.setResponse(oidcEntityResponse.getPolicies().toString());
			userResponse.setHttpstatus(responseEntity.getStatusCode());
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "getUserPoliciesForAddUserToAzureSvcAcc").
				put(LogMessage.MESSAGE,"Completed user policy varification.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return addPolicyToAzureSvcAcc(token, userDetails, azureServiceAccountUser, oidcEntityResponse, azureSvcaccName,
				userResponse);
	}
	
	/**
	 * Method to create policies for add user to Azure service account and call the update process.
	 * @param token
	 * @param userDetails
	 * @param azureServiceAccountUser
	 * @param oidcEntityResponse
	 * @param azureSvcaccName
	 * @param userResponse
	 * @return
	 */
	private ResponseEntity<String> addPolicyToAzureSvcAcc(String token, UserDetails userDetails,
		AzureServiceAccountUser azureServiceAccountUser, OIDCEntityResponse oidcEntityResponse,
		String azureSvcaccName, Response userResponse) {

		String policy = new StringBuilder().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(azureServiceAccountUser.getAccess())).append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("Trying to [%s] policy to user [%s] for the Azure service principal [%s]", policy, azureServiceAccountUser.getUsername(), azureServiceAccountUser.getAzureSvcAccName()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		String readPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
		String writePolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
		String denyPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("User policies are, read - [%s], write - [%s], deny -[%s]", readPolicy, writePolicy, denyPolicy))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		String responseJson = "";
		String groups = "";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if (userResponse != null && HttpStatus.OK.equals(userResponse.getHttpstatus())) {
			responseJson = userResponse.getResponse();
			try {
				ObjectMapper objMapper = new ObjectMapper();
				// OIDC Changes
				if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
					currentpolicies.addAll(oidcEntityResponse.getPolicies());
				} else {
					currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
					if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
						groups = objMapper.readTree(responseJson).get("data").get(AzureServiceAccountConstants.AZURE_GROUP_MSG_STRING).asText();
					}
				}
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, String.format("Exception while creating currentpolicies or groups for [%s]", azureServiceAccountUser.getUsername()))
						.put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
						.build()));
			}

			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.add(policy);
		} else {
			// New user to be configured
			policies.add(policy);
		}
		return configureUserPoliciesForAddUserToAzureSvcAcc(token, userDetails, azureServiceAccountUser, oidcEntityResponse,
				groups, policies, currentpolicies);
	}

	/**
	 * Method to update policies for add user to Azure service principal.
	 * @param token
	 * @param userDetails
	 * @param azureServiceAccountUser
	 * @param oidcEntityResponse
	 * @param groups
	 * @param policies
	 * @param currentpolicies
	 * @return
	 */
	private ResponseEntity<String> configureUserPoliciesForAddUserToAzureSvcAcc(String token, UserDetails userDetails,
			AzureServiceAccountUser azureServiceAccountUser, OIDCEntityResponse oidcEntityResponse, String groups,
			List<String> policies, List<String> currentpolicies) {
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("Started configureUserPoliciesForAddUserToAzureSvcAcc and Policies [%s] before calling configure user", policies))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		Response userConfigresponse = new Response();
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			userConfigresponse = ControllerUtil.configureUserpassUser(azureServiceAccountUser.getUsername(), policiesString, token);
		} else if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			userConfigresponse = ControllerUtil.configureLDAPUser(azureServiceAccountUser.getUsername(), policiesString, groups, token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			// OIDC Implementation : Entity Update
			try {
				userConfigresponse = oidcUtil.updateOIDCEntity(policies, oidcEntityResponse.getEntityName());
				oidcUtil.renewUserToken(userDetails.getClientToken());
			} catch (Exception e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, String.format("Exception while adding or updating the identity for entity [%s]", oidcEntityResponse.getEntityName()))
						.put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
						.build()));
			}
		}

		if (userConfigresponse != null && (userConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)
				|| userConfigresponse.getHttpstatus().equals(HttpStatus.OK))) {
			return updateMetadataForAddUserToAzureSvcAcc(token, userDetails, azureServiceAccountUser, oidcEntityResponse,
					groups, currentpolicies, currentpoliciesString);
		} else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Failed to add user to the Azure Service Account\"]}");
		}
	}
	
	/**
	 * Method to update metadata for add user to Azure service account.
	 * @param token
	 * @param userDetails
	 * @param azureServiceAccountUser
	 * @param oidcEntityResponse
	 * @param groups
	 * @param currentpolicies
	 * @param currentpoliciesString
	 * @return
	 */
	private ResponseEntity<String> updateMetadataForAddUserToAzureSvcAcc(String token, UserDetails userDetails,
			AzureServiceAccountUser azureServiceAccountUser, OIDCEntityResponse oidcEntityResponse, String groups,
			List<String> currentpolicies, String currentpoliciesString) {
		// User has been associated with Azure Service Account. Now metadata has to be created
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "updateMetadataForAddUserToAzureSvcAcc")
				.put(LogMessage.MESSAGE,"Start updating the metadata for add user to AzureSvcAcc.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		String path = new StringBuffer(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureServiceAccountUser.getAzureSvcAccName())
				.toString();
		Map<String, String> params = new HashMap<>();
		params.put("type", USERS);
		params.put("name", azureServiceAccountUser.getUsername());
		params.put("path", path);
		params.put(AzureServiceAccountConstants.AZURE_ACCESS_MSG_STRING, azureServiceAccountUser.getAccess());
		Response metadataResponse = ControllerUtil.updateMetadata(params, token);
		if (metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus())
				|| HttpStatus.OK.equals(metadataResponse.getHttpstatus()))) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
							.put(LogMessage.MESSAGE, String.format("User [%s] is successfully associated to Azure Service Account [%s] with policy [%s].", azureServiceAccountUser.getUsername(), azureServiceAccountUser.getAzureSvcAccName(),azureServiceAccountUser.getAccess()))
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
			return ResponseEntity.status(HttpStatus.OK)
					.body("{\"messages\":[\"Successfully added the user to Azure Service Principal\"]}");
		} else {
			return revertUserPoliciesForAzureSvcAcc(token, userDetails, oidcEntityResponse, azureServiceAccountUser.getUsername(), groups,
					currentpolicies, currentpoliciesString);
		}
	}
	
	/**
	 * Method to revert user policies if add user to Azure service account failed.
	 * @param token
	 * @param userDetails
	 * @param oidcEntityResponse
	 * @param userName
	 * @param groups
	 * @param currentpolicies
	 * @param currentpoliciesString
	 * @return
	 */
	private ResponseEntity<String> revertUserPoliciesForAzureSvcAcc(String token, UserDetails userDetails,
			OIDCEntityResponse oidcEntityResponse, String userName, String groups, List<String> currentpolicies,
			String currentpoliciesString) {
		Response configUserResponse = new Response();
		// Revert the user association when metadata fails...
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, "Metadata creation for user association with service account failed. Reverting user association")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			configUserResponse = ControllerUtil.configureUserpassUser(userName, currentpoliciesString,
					token);
		} else if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			configUserResponse = ControllerUtil.configureLDAPUser(userName, currentpoliciesString, groups,
					token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			// OIDC changes
			try {
				configUserResponse = oidcUtil.updateOIDCEntity(currentpolicies,
						oidcEntityResponse.getEntityName());
				oidcUtil.renewUserToken(userDetails.getClientToken());
			} catch (Exception e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_USER_TO_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, String.format("Exception while adding or updating the identity for entity [%s]", oidcEntityResponse.getEntityName()))
						.put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
						.build()));
			}
		}
		if (configUserResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)
				|| configUserResponse.getHttpstatus().equals(HttpStatus.OK)) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
					"{\"messages\":[\"Failed to add user to the Service Account. Metadata update failed\"]}");
		} else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"messages\":[\"Failed to revert user association on Azure Service Account\"]}");
		}
	}
	
	/**
	 * Method to check if the owner permission is getting changed.
	 * @param azureServiceAccountUser
	 * @param currentUsername
	 * @param isPartOfOnboard
	 * @return
	 */
	private boolean isOwnerPemissionGettingChanged(AzureServiceAccountUser azureServiceAccountUser, String ownerNtId, boolean isPartOfOnboard) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "isOwnerPemissionGettingChanged")
				.put(LogMessage.MESSAGE,"Start checking if the owner permission is getting changed.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		if (isPartOfOnboard) {
			// sudo as part of onboard is allowed.
			return false;
		}
		boolean isPermissionChanged = false;
		// if owner is grating read/ deny to himself, not allowed. Write is allowed as part of activation.
		if (azureServiceAccountUser.getUsername().equalsIgnoreCase(ownerNtId) && !azureServiceAccountUser.getAccess().equals(TVaultConstants.WRITE_POLICY)) {
			isPermissionChanged = true;
		}
		return isPermissionChanged;
	}
	
	
	/*
	 * getAzureServicePrincipalList
	 * @param userDetails
	 * @param token
	 * @return
	 */
	public ResponseEntity<String> getAzureServicePrincipalList(UserDetails userDetails) {
		oidcUtil.renewUserToken(userDetails.getClientToken());
		String token = userDetails.getClientToken();
		if (!userDetails.isAdmin()) {
			token = userDetails.getSelfSupportToken();
		}
		String[] currentPolicies = policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails);

		currentPolicies = filterPoliciesBasedOnPrecedence(Arrays.asList(currentPolicies));

		List<Map<String, String>> azureListUsers = new ArrayList<>();
		Map<String, List<Map<String, String>>> azureList = new HashMap<>();
		if (userDetails.isAdmin()) {
			if (currentPolicies != null) {
				for (String policy : currentPolicies) {
					Map<String, String> azurePolicy = new HashMap<>();
					String[] policies = policy.split("_", -1);
					if (policies.length >= 3) {
						String[] policyName = Arrays.copyOfRange(policies, 2, policies.length);
						String azureName = String.join("_", policyName);
						String azureType = policies[1];
						if (azureType.equals(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH_PREFIX)) {
							azurePolicy.put(azureName, "write");
							azureListUsers.add(azurePolicy);
						}
					}
				}
			}
		} else if (currentPolicies != null) {
			for (String policy : currentPolicies) {
				Map<String, String> azurePolicy = new HashMap<>();
				String[] policies = policy.split("_", -1);
				if (policies.length >= 3) {
					String[] policyName = Arrays.copyOfRange(policies, 2, policies.length);
					String azureName = String.join("_", policyName);
					String azureType = policies[1];

					if (policy.startsWith("r_")) {
						azurePolicy.put(azureName, "read");
					} else if (policy.startsWith("w_")) {
						azurePolicy.put(azureName, "write");
					} else if (policy.startsWith("d_")) {
						azurePolicy.put(azureName, "deny");
					}
					if (!azurePolicy.isEmpty()) {
						if (azureType.equals(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH_PREFIX)) {
							azureListUsers.add(azurePolicy);
						}
					}
				}
			}
		}
		azureList.put(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH_PREFIX, azureListUsers);

		return ResponseEntity.status(HttpStatus.OK).body(JSONUtil.getJSON(azureList));
	}
	
	/**
	 * Filter azure service accounts policies based on policy precedence.
	 * 
	 * @param policies
	 * @return
	 */
	private String[] filterPoliciesBasedOnPrecedence(List<String> policies) {
		List<String> filteredList = new ArrayList<>();
		for (int i = 0; i < policies.size(); i++) {
			String policyName = policies.get(i);
			String[] Policy = policyName.split("_", -1);
			if (Policy.length >= 3) {
				String itemName = policyName.substring(1);
				List<String> matchingPolicies = filteredList.stream().filter(p -> p.substring(1).equals(itemName))
						.collect(Collectors.toList());
				if (!matchingPolicies.isEmpty()) {
					/*
					 * deny has highest priority. Read and write are additive in
					 * nature Removing all matching as there might be duplicate
					 * policies from user and groups
					 */
					filteredList = addPolicy(policyName,matchingPolicies,itemName,filteredList);
					
				} else {
					filteredList.add(policyName);
				}
			}
		}
		return filteredList.toArray(new String[0]);
	}
	
	private List<String> addPolicy(String policyName, List<String> matchingPolicies, String itemName,List<String> filteredList) {
		if (policyName.startsWith("d_") || (policyName.startsWith("w_")
				&& !matchingPolicies.stream().anyMatch(p -> p.equals("d" + itemName)))) {
			filteredList.removeAll(matchingPolicies);
			filteredList.add(policyName);
		} else if (matchingPolicies.stream().anyMatch(p -> p.equals("d" + itemName))) {
			// policy is read and deny already in the list. Then
			// deny has precedence.
			filteredList.removeAll(matchingPolicies);
			filteredList.add("d" + itemName);
		} else if (matchingPolicies.stream().anyMatch(p -> p.equals("w" + itemName))) {
			// policy is read and write already in the list. Then
			// write has precedence.
			filteredList.removeAll(matchingPolicies);
			filteredList.add("w" + itemName);
		} else if (matchingPolicies.stream().anyMatch(p -> p.equals("r" + itemName))
				|| matchingPolicies.stream().anyMatch(p -> p.equals("o" + itemName))) {
			// policy is read and read already in the list. Then
			// remove all duplicates read and add single read
			// permission for that azure service account.
			filteredList.removeAll(matchingPolicies);
			filteredList.add("r" + itemName);
		}
		return filteredList;
	}
	
	/**
	 * Read Folder details for a given Azure service principal
	 *
	 * @param token
	 * @param path
	 * @return
	 * @throws IOException 
	 */
	public ResponseEntity<String> readFolders(String token, String path) throws IOException {
		Response response = new Response();
		ObjectMapper objMapper = new ObjectMapper();
		Response lisresp = reqProcessor.process("/azure/list", PATHSTR + path + "\"}", token);
		if(lisresp.getHttpstatus().equals(HttpStatus.OK)){
			List<String> foldersList = new ArrayList<>();
			AzureServiceAccountNode azureServiceAccountNode = new AzureServiceAccountNode();
			JsonNode folders = objMapper.readTree(lisresp.getResponse()).get("keys");
			for (JsonNode node : folders) {
				foldersList.add(node.textValue());
			}
			azureServiceAccountNode.setFolders(foldersList);
			azureServiceAccountNode.setPath(path);
			String separator = "/";
			int sepPos = path.indexOf(separator);
			azureServiceAccountNode.setServicePrincipalName(path.substring(sepPos + separator.length()));
			response.setSuccess(true);
			response.setHttpstatus(HttpStatus.OK);
			String res = objMapper.writeValueAsString(azureServiceAccountNode);
			return ResponseEntity.status(response.getHttpstatus()).body(res);
		}else if (lisresp.getHttpstatus().equals(HttpStatus.FORBIDDEN)){
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "readFolders")
					.put(LogMessage.MESSAGE, "No permission to access the folder")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			response.setSuccess(false);
			response.setHttpstatus(HttpStatus.FORBIDDEN);
			response.setResponse("{\"errors\":[\"Access Denied: No permission to read or rotate secret for Azure service principal\"]}");
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		}else{
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "readFolders")
					.put(LogMessage.MESSAGE, "Unable to readFolders")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			response.setSuccess(false);
			response.setHttpstatus(HttpStatus.INTERNAL_SERVER_ERROR);
			response.setResponse("{\"errors\":[\"Unexpected error :" + path + "\"]}");
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
		} 
	}

	/**
	 * Find Azure service account from metadata.
	 * 
	 * @param token
	 * @param azureSvcaccName
	 * @return
	 */
	public ResponseEntity<String> getAzureServiceAccountSecretKey(String token, String azureSvcaccName, String folderName) throws IOException {
		String path = AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + azureSvcaccName + "/" + folderName;

		Response response = reqProcessor.process("/azuresvcacct", PATHSTR + path + "\"}", token);
		if (response.getHttpstatus().equals(HttpStatus.OK)) {
			JsonParser jsonParser = new JsonParser();
			JsonObject data = ((JsonObject) jsonParser.parse(response.getResponse())).getAsJsonObject("data");
			Long expiryDate = Long.valueOf(String.valueOf(data.get("expiryDateEpoch")));
			String formattedExpiryDt = dateConversion(expiryDate);
			data.addProperty("expiryDate", formattedExpiryDt);
			return ResponseEntity.status(HttpStatus.OK).body(data.toString());
		}
		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"No Azure Service Principal with " + azureSvcaccName + ".\"]}");

	}
	
	
	/**
	 * Date conversion from milliseconds to yyyy-MM-dd HH:mm:ss
	 * 
	 * @param createdEpoch
	 */
	private String dateConversion(Long createdEpoch) {
		DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Calendar calendar = Calendar.getInstance();
		calendar.setTimeInMillis(createdEpoch);
		return formatter.format(calendar.getTime());
	}
	
	/**
	 * Read Secret.
	 * @param userDetails
	 * @param token
	 * @param azureSvcName
	 * @param secretKey
	 * @return
	 * @throws IOException
	 */
	public ResponseEntity<String> readSecret(UserDetails userDetails, String token, String azureSvcName, String secretKey)
			throws IOException {

		List<String> currentpolicies = commonUtils.getTokePoliciesAsList(token);
		if (!userDetails.isAdmin() && !CollectionUtils.isEmpty(currentpolicies) && !Collections.disjoint(Arrays.asList(TVaultConstants.IAM_AZURE_ADMIN_POLICY_LIST), currentpolicies)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "readSecrets")
					.put(LogMessage.MESSAGE, String.format("Access denied: No permission to read secret for Azure service account [%s]", azureSvcName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ERRORSTR
					+ JSONUtil.getJSON("Access denied: No permission to read secret for Azure service account") + "}");
		}
		if (userDetails.isAdmin()) {
			token = userDetails.getSelfSupportToken();
		}

		azureSvcName = azureSvcName.toLowerCase();
		String azureSvcNamePath = AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + azureSvcName;
		ResponseEntity<String> response = readFolders(token, azureSvcNamePath);
		ObjectMapper mapper = new ObjectMapper();
		String secret = "";
		if (HttpStatus.OK.equals(response.getStatusCode())) {
			AzureServiceAccountNode azureServiceAccountNode = mapper.readValue(response.getBody(),
					AzureServiceAccountNode.class);
			if (azureServiceAccountNode.getFolders() != null) {
				for (String folderName : azureServiceAccountNode.getFolders()) {
					ResponseEntity<String> responseEntity = getAzureServiceAccountSecretKey(token, azureSvcName,
							folderName);
					if (HttpStatus.OK.equals(responseEntity.getStatusCode())) {
						AzureServiceAccountSecret azureServiceAccountSecret = mapper.readValue(responseEntity.getBody(),
								AzureServiceAccountSecret.class);
						if (secretKey.equals(azureServiceAccountSecret.getSecretKeyId())) {
							secret = azureServiceAccountSecret.getSecretText();
							break;
						}
					} else {
						return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"error\":"
								+ JSONUtil.getJSON("No secret found for the secretKey :" + secretKey + "") + "}");
					}
				}
				if (StringUtils.isEmpty(secret)) {
					return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ERRORSTR
							+ JSONUtil.getJSON(SECRETNOTFOUND + secretKey + "") + "}");
				}
				return ResponseEntity.status(HttpStatus.OK)
						.body("{\"accessKeySecret\":" + JSONUtil.getJSON(secret) + "}");
			} else {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
						ERRORSTR + JSONUtil.getJSON(SECRETNOTFOUND + secretKey + "") + "}");
			}
		} else if (HttpStatus.FORBIDDEN.equals(response.getStatusCode())) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ERRORSTR
					+ JSONUtil.getJSON("Access denied: No permission to read secret for Azure service account") + "}");
		} else {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
					ERRORSTR + JSONUtil.getJSON("azure_svc_name not found") + "}");
		}
	}
	
		
	/**
	 * Method to offboard  service account.
	 * @param token
	 * @param azureOffboardRequest
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> offboardAzureServiceAccount(String token, AzureServiceAccountOffboardRequest azureOffboardRequest,
															UserDetails userDetails) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION,AzureServiceAccountConstants.AZURE_SVCACC_OFFBOARD_CREATION_TITLE)
				.put(LogMessage.MESSAGE, String.format("Start trying to offboard Azure service account[%s].",azureOffboardRequest.getAzureSvcAccName()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		String managedBy = "";
		String azureSvcName = azureOffboardRequest.getAzureSvcAccName().toLowerCase();
		String selfSupportToken = tokenUtils.getSelfServiceToken();
		if (!isAuthorizedForAzureOnboardAndOffboard(token)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_OFFBOARD_CREATION_TITLE)
					.put(LogMessage.MESSAGE,
							"Access denied. Not authorized to perform offboarding of Azure service accounts.")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
					"{\"errors\":[\"Access denied. Not authorized to perform offboarding of Azure service accounts.\"]}");
		}

		boolean policyDeleteStatus = deleteAzureServiceAccountPolicies(selfSupportToken, azureSvcName);
		if (!policyDeleteStatus) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_OFFBOARD_CREATION_TITLE)
					.put(LogMessage.MESSAGE,
							String.format("Failed to delete some of the policies for azure service " + ACCOUNTSTR,
									azureSvcName))
					.put(LogMessage.APIURL,	ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
					"{\"errors\":[\"Failed to Offboard Azure service account. Policy deletion failed.\"]}");
		}

		// delete users,groups,aws-roles,app-roles from azure service account
		String path = AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH + azureSvcName;
		Response metaResponse = reqProcessor.process("/sdb", PATHSTR + path + "\"}", token);
		Map<String, Object> responseMap = null;
		try {
			responseMap = new ObjectMapper().readValue(metaResponse.getResponse(),
					new TypeReference<Map<String, Object>>() {
					});
		} catch (IOException e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_OFFBOARD_CREATION_TITLE)
					.put(LogMessage.MESSAGE, String.format("Error Fetching metadata for azure service account " +
							" [%s]", azureSvcName))
					.put(LogMessage.APIURL,	ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Failed to Offboard Azure service account. Error Fetching metadata for azure service account\"]}");
		}
		if (responseMap != null && responseMap.get("data") != null) {
			Map<String, Object> metadataMap = (Map<String, Object>) responseMap.get("data");
			Map<String, String> approles = (Map<String, String>) metadataMap.get("app-roles");
			Map<String, String> groups = (Map<String, String>) metadataMap.get(GROUPSTR);
			Map<String, String> users = (Map<String, String>) metadataMap.get(USERS);
			Map<String,String> awsroles = (Map<String, String>)metadataMap.get(AWSROLES);
			// always add owner to the users list whose policy should be updated
			managedBy = (String) metadataMap.get(AzureServiceAccountConstants.OWNER_NT_ID);
			if (!org.apache.commons.lang3.StringUtils.isEmpty(managedBy)) {
				if (null == users) {
					users = new HashMap<>();
				}
				users.put(managedBy, "sudo");
			}

			updateUserPolicyAssociationOnAzureSvcaccDelete(azureSvcName, users, selfSupportToken, userDetails);
			updateGroupPolicyAssociationOnAzureSvcaccDelete(azureSvcName, groups, selfSupportToken, userDetails);
			updateApprolePolicyAssociationOnAzureSvcaccDelete(azureSvcName, approles, selfSupportToken);
			deleteAwsRoleonOnAzureSvcaccDelete(azureSvcName, awsroles, selfSupportToken);
		}

		OnboardedAzureServiceAccount azureSvcAccToOffboard = new OnboardedAzureServiceAccount(azureSvcName, managedBy);
		//delete azure service account secrets and mount details
		ResponseEntity<String> secretDeletionResponse = deleteAzureSvcAccountSecrets(token, azureSvcAccToOffboard);
		if (HttpStatus.OK.equals(secretDeletionResponse.getStatusCode())) {
			// Remove metadata...
			ResponseEntity<String> metadataResponse = deleteAzureSvcAccount(token, azureSvcAccToOffboard);
			if(HttpStatus.OK.equals(metadataResponse.getStatusCode())){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, "offboarding Azure service account")
						.put(LogMessage.MESSAGE, String.format("Successfully offboarded Azure service account [%s] from T-Vault", azureSvcName))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
						.build()));
				return ResponseEntity.status(HttpStatus.OK).body(
						"{\"messages\":[\"Successfully offboarded Azure service account (if existed) from T-Vault\"]}");
			}else{
				return ResponseEntity.status(HttpStatus.MULTI_STATUS).body(
						"{\"errors\":[\"Failed to offboard Azure service account from TVault\"]}");
			}
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_OFFBOARD_CREATION_TITLE)
					.put(LogMessage.MESSAGE, String.format("Failed to offboard Azure service account [%s] from TVault",
							azureSvcName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.MULTI_STATUS).body(
					"{\"errors\":[\"Failed to offboard Azure service account from TVault\"]}");
		}
	}


	/**
	 * Update User policy on Azure Service account offboarding
	 * @param azureSvcAccName
	 * @param acessInfo
	 * @param token
	 * @param userDetails
	 */
	private void updateUserPolicyAssociationOnAzureSvcaccDelete(String azureSvcAccName, Map<String, String> acessInfo,
															  String token, UserDetails userDetails) {
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, UPDATEPOLICYSTR)
				.put(LogMessage.MESSAGE, String.format("Trying to delete user policies on Azure service account delete " +
						"of [%s]", azureSvcAccName))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		if (acessInfo != null) {
			String readPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccName).toString();
			String writePolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccName).toString();
			String denyPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccName).toString();
			String ownerPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccName).toString();

			Set<String> users = acessInfo.keySet();
			ObjectMapper objMapper = new ObjectMapper();
			for (String userName : users) {

				Response userResponse = new Response();
				if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
					userResponse = reqProcessor.process(READPATH, USERNAMESTR + userName + "\"}",
							token);
				} else if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
					userResponse = reqProcessor.process(USERPATH, USERNAMESTR + userName + "\"}",
							token);
				} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
					// OIDC implementation changes
					ResponseEntity<OIDCEntityResponse> responseEntity = oidcUtil.oidcFetchEntityDetails(token, userName,
							null, true);
					if (!responseEntity.getStatusCode().equals(HttpStatus.OK)) {
						if (responseEntity.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
							log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
									.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
									.put(LogMessage.ACTION, UPDATEPOLICYSTR)
									.put(LogMessage.MESSAGE, String.format("Failed to fetch OIDC user policies for [%s]"
											, userName))
									.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
									.build()));
							ResponseEntity.status(HttpStatus.FORBIDDEN)
									.body("{\"messages\":[\"User configuration failed. Please try again.\"]}");
						}
						ResponseEntity.status(HttpStatus.NOT_FOUND)
								.body(ERRORINVALIDSTR);
					}
					oidcEntityResponse.setEntityName(responseEntity.getBody().getEntityName());
					oidcEntityResponse.setPolicies(responseEntity.getBody().getPolicies());
					userResponse.setResponse(oidcEntityResponse.getPolicies().toString());
					userResponse.setHttpstatus(responseEntity.getStatusCode());
				}
				String responseJson = "";
				String groups = "";
				List<String> policies = new ArrayList<>();
				List<String> currentpolicies = new ArrayList<>();

				if (HttpStatus.OK.equals(userResponse.getHttpstatus())) {
					responseJson = userResponse.getResponse();
					try {
						// OIDC implementation changes
						if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
							currentpolicies.addAll(oidcEntityResponse.getPolicies());
						} else {
							currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
							if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
								groups = objMapper.readTree(responseJson).get("data").get(GROUPSTR).asText();
							}
						}
					} catch (IOException e) {
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, UPDATEPOLICYSTR)
								.put(LogMessage.MESSAGE, String.format("updateUserPolicyAssociationOnAzureSvcaccDelete " +
												"failed [%s]", e.getMessage()))
								.put(LogMessage.APIURL,	ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
					}
					policies.addAll(currentpolicies);
					policies.remove(readPolicy);
					policies.remove(writePolicy);
					policies.remove(denyPolicy);
					policies.remove(ownerPolicy);

					String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");

					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, UPDATEPOLICYSTR)
							.put(LogMessage.MESSAGE, String.format("Current policies [%s]", policies))
							.put(LogMessage.APIURL,	ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
					if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
						log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, UPDATEPOLICYSTR)
								.put(LogMessage.MESSAGE, String.format("Current policies userpass [%s]", policies))
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
						ControllerUtil.configureUserpassUser(userName, policiesString, token);
					} else if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
						log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, UPDATEPOLICYSTR)
								.put(LogMessage.MESSAGE, String.format("Current policies ldap [%s]", policies))
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
						ControllerUtil.configureLDAPUser(userName, policiesString, groups, token);
					} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
						// OIDC Implementation : Entity Update
						try {
							oidcUtil.updateOIDCEntity(policies, oidcEntityResponse.getEntityName());
							oidcUtil.renewUserToken(userDetails.getClientToken());
						} catch (Exception e) {
							log.error(e);
							log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
									.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
									.put(LogMessage.ACTION, UPDATEPOLICYSTR)
									.put(LogMessage.MESSAGE, "Exception while adding or updating the identity ")
									.put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace()))
									.put(LogMessage.APIURL,	ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
									.build()));
						}
					}
				}
			}
		}
	}

	/**
	 * Update Group policy on Azure Service account offboarding
	 *
	 * @param azureSvcAccountName
	 * @param acessInfo
	 * @param token
	 * @param userDetails
	 */
	private void updateGroupPolicyAssociationOnAzureSvcaccDelete(String azureSvcAccountName, Map<String, String> acessInfo,
															   String token, UserDetails userDetails) {
		OIDCGroup oidcGroup = new OIDCGroup();
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, UPDATEGROUPPOLICYSTR)
				.put(LogMessage.MESSAGE, String.format("Trying to delete group policies on Azure service account delete " +
						"for [%s]", azureSvcAccountName))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, UPDATEGROUPPOLICYSTR)
					.put(LogMessage.MESSAGE, "Inside userpass of updateGroupPolicyAssociationOnAzureSvcaccDelete...Just Returning...")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return;
		}
		if (acessInfo != null) {
			String readPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
			String writePolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
			String denyPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
			String sudoPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();

			Set<String> groups = acessInfo.keySet();
			ObjectMapper objMapper = new ObjectMapper();
			for (String groupName : groups) {
				Response response = new Response();
				if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
					response = reqProcessor.process(GROUPPATH, GROUPNAMESTR + groupName + "\"}",
							token);
				} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
					// call read api with groupname
					oidcGroup = oidcUtil.getIdentityGroupDetails(groupName, token);
					if (oidcGroup != null) {
						response.setHttpstatus(HttpStatus.OK);
						response.setResponse(oidcGroup.getPolicies().toString());
					} else {
						response.setHttpstatus(HttpStatus.BAD_REQUEST);
					}
				}

				String responseJson = "";
				List<String> policies = new ArrayList<>();
				List<String> currentpolicies = new ArrayList<>();
				if (HttpStatus.OK.equals(response.getHttpstatus())) {
					responseJson = response.getResponse();
					try {
						// OIDC Changes
						if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
							currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
						} else if (TVaultConstants.OIDC.equals(vaultAuthMethod) && oidcGroup != null) {
							currentpolicies.addAll(oidcGroup.getPolicies());
						}
					} catch (IOException e) {
						log.error(e);
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, UPDATEGROUPPOLICYSTR)
								.put(LogMessage.MESSAGE, String.format("updateGroupPolicyAssociationOnAzureSvcaccDelete " +
												"failed [%s]", e.getMessage()))
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
					}
					policies.addAll(currentpolicies);
					policies.remove(readPolicy);
					policies.remove(writePolicy);
					policies.remove(denyPolicy);
					policies.remove(sudoPolicy);
					String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, UPDATEGROUPPOLICYSTR)
							.put(LogMessage.MESSAGE, String.format("Current policies [%s]", policies))
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
					if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
						ControllerUtil.configureLDAPGroup(groupName, policiesString, token);
					} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
						oidcUtil.updateGroupPolicies(token, groupName, policies, currentpolicies, oidcGroup != null ? oidcGroup.getId() : null);
						oidcUtil.renewUserToken(userDetails.getClientToken());
					}
				}
			}
		}
	}

	/**
	 * Approle policy update as part of offboarding
	 *
	 * @param azureSvcAccountName
	 * @param acessInfo
	 * @param token
	 */
	private void updateApprolePolicyAssociationOnAzureSvcaccDelete(String azureSvcAccountName,
																 Map<String, String> acessInfo, String token) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "updateApprolePolicyAssociationOn AzureSvcaccDelete")
				.put(LogMessage.MESSAGE, String.format("trying to update approle policies on Azure service account " +
						"delete for [%s]", azureSvcAccountName))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		if (acessInfo != null) {
			String readPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
			String writePolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
			String denyPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
			String sudoPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
			Set<String> approles = acessInfo.keySet();
			ObjectMapper objMapper = new ObjectMapper();
			for (String approleName : approles) {
				Response roleResponse = reqProcessor.process(READROLEPATH,
						ROLENAME + approleName + "\"}", token);
				String responseJson = "";
				List<String> policies = new ArrayList<>();
				List<String> currentpolicies = new ArrayList<>();
				if (HttpStatus.OK.equals(roleResponse.getHttpstatus())) {
					responseJson = roleResponse.getResponse();
					try {
						JsonNode policiesArry = objMapper.readTree(responseJson).get("data").get(POLICIESSTR);
						if (null != policiesArry) {
							for (JsonNode policyNode : policiesArry) {
								currentpolicies.add(policyNode.asText());
							}
						}
					} catch (IOException e) {
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, "updateApprolePolicyAssociationOnAzureSvcaccDelete")
								.put(LogMessage.MESSAGE, String.format("%s, Approle removal as part of offboarding " +
												"Service account failed.", approleName))
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
					}
					policies.addAll(currentpolicies);
					policies.remove(readPolicy);
					policies.remove(writePolicy);
					policies.remove(denyPolicy);
					policies.remove(sudoPolicy);

					String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
					log.info( JSONUtil.getJSON(ImmutableMap.<String, String> builder()
									.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
									.put(LogMessage.ACTION, "updateApprolePolicyAssociationOnAzureSvcaccDelete")
									.put(LogMessage.MESSAGE, "Current policies :" + policiesString + " is being configured")
									.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
									.build()));
					appRoleService.configureApprole(approleName, policiesString, token);
				}
			}
		}
	}

	/**
	 * Deletes the Azure SvcAccount secret
	 * @param token
	 * @param azureServiceAccount
	 * @return
	 */
	private ResponseEntity<String> deleteAzureSvcAccountSecrets(String token, OnboardedAzureServiceAccount azureServiceAccount) {
		String azureSvcAccName = azureServiceAccount.getServicePrincipalName();
		String azureSvcAccPath = AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + azureSvcAccName;

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, DELETEAZURE)
				.put(LogMessage.MESSAGE, String.format("Trying to delete secret folder for Azure service " +
						ACCOUNTSTR, azureSvcAccName))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		boolean secretDeleteStatus = deleteAzureSvcAccountSecretFolders(token, azureServiceAccount.getServicePrincipalName());
		if (secretDeleteStatus) {
			Response onboardingResponse = reqProcessor.process(DELETEPATH, PATHSTR + azureSvcAccPath + "\"}", token);

			if (onboardingResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)
					|| onboardingResponse.getHttpstatus().equals(HttpStatus.OK)) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, DELETEAZURE)
						.put(LogMessage.MESSAGE, "Successfully deleted Azure service account Secrets.")
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
				return ResponseEntity.status(HttpStatus.OK)
						.body("{\"messages\":[\"Successfully deleted Azure service account Secrets.\"]}");
			}
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, DELETEAZURE)
					.put(LogMessage.MESSAGE, "Failed to delete Azure service account Secrets.")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("{\"errors\":[\"Failed to delete Azure service account Secrets.\"]}");
		}

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, DELETEAZURE)
				.put(LogMessage.MESSAGE, "Failed to delete one or more Azure service account Secret folders.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"Failed to delete Azure service account Secrets.\"]}");
	}
	
	/**
	 * To delete Azure secret folders as part of Offboarding.
	 * @param token
	 * @param azureSvcAccName
	 * @return
	 */
	private boolean deleteAzureSvcAccountSecretFolders(String token, String azureSvcAccName) {

		JsonObject azureMetadataJson = getAzureMetadata(token, azureSvcAccName);

		if ((null!= azureMetadataJson && azureMetadataJson.has(TVaultConstants.SECRET)) && (!azureMetadataJson.get(SECRETSTR).isJsonNull())) {
			
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "DeleteAzureSvcAccountSecretFolders").
						put(LogMessage.MESSAGE, String.format("Trying to delete secret folders for the Azure Service " +
								ACCOUNTSTR, azureSvcAccName)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));

				JsonArray svcSecretArray = null;
				try {
					svcSecretArray = azureMetadataJson.get(TVaultConstants.SECRET).getAsJsonArray();
				} catch (IllegalStateException e) {
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, "deleteAzureSvcAccountSecretFolders").
							put(LogMessage.MESSAGE, String.format("Failed to get secret folders. Invalid metadata " +
									"for [%s].", azureSvcAccName)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return false;
				}

				if (null != svcSecretArray) {
					int deleteCount = 0;
					for (int i = 0; i < svcSecretArray.size(); i++) {
						String folderPath = AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + azureSvcAccName + "/secret_" + (i+1);
						Response deleteFolderResponse = reqProcessor.process(DELETEPATH,
								PATHSTR + folderPath + "\"}", token);
						if (deleteFolderResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)
								|| deleteFolderResponse.getHttpstatus().equals(HttpStatus.OK)) {
							log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
									put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
									put(LogMessage.ACTION, "deleteAzureSvcAccountSecretFolders").
									put(LogMessage.MESSAGE, String.format("Deleted secret folder [%d] for the Azure Service " +
											ACCOUNTSTR, (i+1), azureSvcAccName)).
									put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
									build()));
							deleteCount++;
						}
					}
					if (deleteCount == svcSecretArray.size()) {
						return true;
					}
					else {
						return false;
					}
				}
			
		}
		return true;
	}
	
	/**
	 * To get Azure Service Account metadata as JsonObject.
	 * @param token
	 * @param azureSvcaccName
	 * @return
	 */
	private JsonObject getAzureMetadata(String token, String azureSvcaccName) {
		String path = AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH + azureSvcaccName;
		Response response = reqProcessor.process("/read", PATHSTR + path + "\"}", token);
		if (response.getHttpstatus().equals(HttpStatus.OK)) {
			return populateMetaData(response);
		}
		return null;
	}
	
	/**
	 * populate metadata
	 * 
	 * @param response
	 * @return
	 */
	private JsonObject populateMetaData(Response response) {
		JsonParser jsonParser = new JsonParser();
		JsonObject data = ((JsonObject) jsonParser.parse(response.getResponse())).getAsJsonObject("data");
		Long createdAtEpoch = Long.valueOf(String.valueOf(data.get("createdAtEpoch")));

		String createdDate = dateConversion(createdAtEpoch);
		data.addProperty("createdDate", createdDate);
		JsonArray dataSecret = ((JsonObject) jsonParser.parse(data.toString())).getAsJsonArray(SECRETSTR);

		for (int i = 0; i < dataSecret.size(); i++) {
			JsonElement jsonElement = dataSecret.get(i);
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			jsonObject.addProperty("expiryDurationMs", jsonObject.get("expiryDuration").toString());
			String expiryDate = dateConversion(jsonObject.get("expiryDuration").getAsLong());
			jsonObject.addProperty("expiryDuration", expiryDate);
		}
		JsonElement jsonElement = dataSecret.getAsJsonArray();
		data.add(SECRETSTR, jsonElement);
		return data;
	}
	
	 /**
     * Aws role deletion as part of Offboarding
     * @param acessInfo
     * @param token
     */
    private void deleteAwsRoleonOnAzureSvcaccDelete(String azureSvcName, Map<String,String> acessInfo, String token) {
        log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, AzureServiceAccountConstants.DELETE_AWSROLE_ASSOCIATION).
                put(LogMessage.MESSAGE, String.format ("Trying to delete AwsRole association on offboarding of Azure Service Principal [%s] ", azureSvcName)).
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
        if(acessInfo!=null){
            Set<String> roles = acessInfo.keySet();
			for (String role : roles) {
				removeAWSRoleAssociationFromAzureSvcAccForOffboard(azureSvcName, token, role);
			}
        }
    }

	/**
	 * Method to remove the AWS role association from Azure Service account for Off board.
	 * @param azureSvcName
	 * @param token
	 * @param role
	 */
	private void removeAWSRoleAssociationFromAzureSvcAccForOffboard(String azureSvcName, String token, String role) {
		String readPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
		String writePolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
		String denyPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
		String ownerPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, AzureServiceAccountConstants.DELETE_AWSROLE_ASSOCIATION).
				put(LogMessage.MESSAGE, String.format ("Azure service principal policies are, read - [%s], write - [%s], deny -[%s], owner - [%s]", readPolicy, writePolicy, denyPolicy, ownerPolicy)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		Response roleResponse = reqProcessor.process("/auth/aws/roles","{\"role\":\""+role+"\"}",token);
		String responseJson="";
		String authType = TVaultConstants.EC2;
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();
		String policiesString = "";
		if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
			responseJson = roleResponse.getResponse();
			ObjectMapper objMapper = new ObjectMapper();
			try {
				JsonNode policiesArry =objMapper.readTree(responseJson).get(POLICIESSTR);
				for(JsonNode policyNode : policiesArry){
					currentpolicies.add(policyNode.asText());
				}
				authType = objMapper.readTree(responseJson).get("auth_type").asText();
			} catch (IOException e) {
		        log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		                put(LogMessage.ACTION, AzureServiceAccountConstants.DELETE_AWSROLE_ASSOCIATION).
		                put(LogMessage.MESSAGE, e.getMessage()).
		                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		                build()));
			}

			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);

			policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");

			log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.DELETE_AWSROLE_ASSOCIATION).
					put(LogMessage.MESSAGE, "Remove AWS Role from Azure Service Principal -  policy :" + policiesString + " is being configured" ).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));

			if (TVaultConstants.IAM.equals(authType)) {
				awsiamAuthService.configureAWSIAMRole(role,policiesString,token);
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		                put(LogMessage.ACTION, AzureServiceAccountConstants.DELETE_AWSROLE_ASSOCIATION).
		                put(LogMessage.MESSAGE, String.format ("%s, AWS IAM Role association is removed as part of offboarding Azure Service principal [%s].", role, azureSvcName)).
		                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		                build()));
			}
			else {
				awsAuthService.configureAWSRole(role,policiesString,token);
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		                put(LogMessage.ACTION, AzureServiceAccountConstants.DELETE_AWSROLE_ASSOCIATION).
		                put(LogMessage.MESSAGE, String.format ("%s, AWS EC2 Role association is removed as part of offboarding Azure Service principal [%s].", role, azureSvcName)).
		                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		                build()));
			}
		}
	}

	/**
	 * Removes user from Azure service account
	 *
	 * @param token
	 * @param safeUser
	 * @return
	 */
	public ResponseEntity<String> removeUserFromAzureServiceAccount(String token,
			AzureServiceAccountUser azureServiceAccountUser, UserDetails userDetails) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG).
                put(LogMessage.MESSAGE, String.format ("Start trying to remove user [%s] from Azure Service account [%s].", azureServiceAccountUser.getUsername(),azureServiceAccountUser.getAzureSvcAccName())).
                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                build()));
		azureServiceAccountUser.setAzureSvcAccName(azureServiceAccountUser.getAzureSvcAccName().toLowerCase());
		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		if (!userDetails.isAdmin()) {
			token = tokenUtils.getSelfServiceToken();
		}
		if (!isAzureSvcaccPermissionInputValid(azureServiceAccountUser.getAccess())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE,"Invalid input values")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(ERRORBODYSTR);
		}
		if (azureServiceAccountUser.getAccess()
				.equalsIgnoreCase(AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING)) {
			azureServiceAccountUser.setAccess(TVaultConstants.WRITE_POLICY);
		}

		String azureSvcaccName = azureServiceAccountUser.getAzureSvcAccName();

		boolean isAuthorized = isAuthorizedToAddPermissionInAzureSvcAcc(userDetails, azureSvcaccName, false);
		String uniqueASPaccName= azureServiceAccountUser.getAzureSvcAccName();
		if (isAuthorized) {
			// Only Sudo policy can be added (as part of onbord) before
			// activation.
			if (!isAzureSvcaccActivated(token, userDetails, azureSvcaccName)
					&& !TVaultConstants.SUDO_POLICY.equals(azureServiceAccountUser.getAccess())) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE,
								String.format(
										"Failed to remove user permission from Azure Service account. [%s] is not activated.",
										azureServiceAccountUser.getAzureSvcAccName()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
						"{\"errors\":[\"Failed to remove user permission from Azure Service account. Azure Service Account is not activated. Please activate this Azure service account and try again.\"]}");
			}
			// Deleting owner permission is not allowed
			if (azureServiceAccountUser.getUsername().equalsIgnoreCase((getOwnerNTIdFromMetadata(token, uniqueASPaccName )))) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE,
								"Failed to remove user permission to Azure Service account. Owner permission cannot be changed..")
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
						"{\"errors\":[\"Failed to remove user permission to Azure Service account. Owner permission cannot be changed.\"]}");
			}
			return processAndRemoveUserPermissionFromAzureSvcAcc(token, azureServiceAccountUser, userDetails,
					oidcEntityResponse, azureSvcaccName);
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Access denied: No permission to remove user from this Azure service account\"]}");
		}
	}
	/**
	 * To get list of azure service principal onboarded
	 * 
	 * @param token
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> getOnboardedAzureServiceAccounts(String token, UserDetails userDetails) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "listOnboardedIAzureerviceAccounts")
				.put(LogMessage.MESSAGE, "Trying to get list of onboaded Azure service accounts")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		Response response = null;
		List<String> onboardedlist = new ArrayList<>();
		if(userDetails.isAdmin()) {
			onboardedlist=getOnboardedAzureServiceAccountList(userDetails.getSelfSupportToken());
		}
		
		else {
			String[] latestPolicies = policyUtils.getCurrentPolicies(userDetails.getSelfSupportToken(),
					userDetails.getUsername(), userDetails);
			for (String policy : latestPolicies) {

				if (policy.startsWith("o_azuresvcacc")) {
					onboardedlist.add(policy.substring(14));
				}
			}
		}	
		response = new Response();
		response.setHttpstatus(HttpStatus.OK);
		response.setSuccess(true);
		response.setResponse("{\"keys\":" + JSONUtil.getJSON(onboardedlist) + "}");
		
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "listOnboardedAzureServiceAccounts")
					.put(LogMessage.MESSAGE, "Successfully retrieved the list of Azure Service Accounts")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(response.getHttpstatus()).body(response.getResponse());
	}

	/**
	 * Find Azure service principal from metadata.
	 *
	 * @param token
	 * @param azureSvcName
	 * @return
	 */
	public ResponseEntity<String> getAzureServicePrincipalDetail(String token, String azureSvcName) {
		String path = AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH + azureSvcName;
		Response response = reqProcessor.process("/azuresvcacct", PATHSTR + path + "\"}", token);
		if (response.getHttpstatus().equals(HttpStatus.OK)) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.FETCH_AZURE_DETAILS).
					put(LogMessage.MESSAGE,  String.format ("Azure Service account [%s] details fetched successfully.",azureSvcName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			JsonObject data = populateMetaData(response);
			return ResponseEntity.status(HttpStatus.OK).body(data.toString());
		}
		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body("{\"errors\":[\"No Azure Service Principal with " + azureSvcName + ".\"]}");
	}
	/*
	 * Method to verify the user for removing from Azure service account.
	 *
	 * @param token
	 * @param azureServiceAccountUser
	 * @param userDetails
	 * @param oidcEntityResponse
	 * @param azureSvcaccName
	 * @return
	 */
	private ResponseEntity<String> processAndRemoveUserPermissionFromAzureSvcAcc(String token,
			AzureServiceAccountUser azureServiceAccountUser, UserDetails userDetails,
			OIDCEntityResponse oidcEntityResponse, String azureSvcaccName) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE,"Start verifying  verify the user for removing from Azure service account.")
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
						.build()));

		Response userResponse = new Response();
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			userResponse = reqProcessor.process(READPATH,
					USERNAMESTR + azureServiceAccountUser.getUsername() + "\"}", token);
		} else if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			userResponse = reqProcessor.process(USERPATH,
					USERNAMESTR + azureServiceAccountUser.getUsername() + "\"}", token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			// OIDC implementation changes
			ResponseEntity<OIDCEntityResponse> responseEntity = oidcUtil.oidcFetchEntityDetails(token,
					azureServiceAccountUser.getUsername(), userDetails, true);
			if (!responseEntity.getStatusCode().equals(HttpStatus.OK)) {
				if (responseEntity.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
					log.error(
							JSONUtil.getJSON(ImmutableMap.<String, String> builder()
									.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
									.put(LogMessage.ACTION,
											AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
									.put(LogMessage.MESSAGE, "Trying to fetch OIDC user policies, failed")
									.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
									.build()));
				}
				return ResponseEntity.status(HttpStatus.NOT_FOUND)
						.body(ERRORINVALIDSTR);
			}
			oidcEntityResponse.setEntityName(responseEntity.getBody().getEntityName());
			oidcEntityResponse.setPolicies(responseEntity.getBody().getPolicies());
			userResponse.setResponse(oidcEntityResponse.getPolicies().toString());
			userResponse.setHttpstatus(responseEntity.getStatusCode());
		}

		log.debug(
				JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE,
								String.format("userResponse status is [%s]", userResponse.getHttpstatus()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		return createPoliciesAndRemoveUserFromAzureSvcAcc(token, azureServiceAccountUser, userDetails,
				oidcEntityResponse, azureSvcaccName, userResponse);
	}

	/**
	 * Method to create policies for removing user from Azure service account
	 * and call the metadata update.
	 *
	 * @param token
	 * @param azureServiceAccountUser
	 * @param userDetails
	 * @param oidcEntityResponse
	 * @param azureSvcaccName
	 * @param userResponse
	 * @return
	 */
	private ResponseEntity<String> createPoliciesAndRemoveUserFromAzureSvcAcc(String token,
			AzureServiceAccountUser azureServiceAccountUser, UserDetails userDetails,
			OIDCEntityResponse oidcEntityResponse, String azureSvcaccName, Response userResponse) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,"Start create policies for removing user from Azure service account.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		String readPolicy = new StringBuffer()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
		String writePolicy = new StringBuffer()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
		String denyPolicy = new StringBuffer()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
		String ownerPolicy = new StringBuffer()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,
						String.format("Policies are read - [%s], write - [%s], deny -[%s], owner - [%s]", readPolicy,
								writePolicy, denyPolicy, ownerPolicy))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		String responseJson = "";
		String groups = "";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();
		if (HttpStatus.OK.equals(userResponse.getHttpstatus())) {
			responseJson = userResponse.getResponse();
			try {
				ObjectMapper objMapper = new ObjectMapper();
				if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
					currentpolicies.addAll(oidcEntityResponse.getPolicies());
				} else {
					currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
					if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
						groups = objMapper.readTree(responseJson).get("data").get(GROUPSTR).asText();
					}
				}
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, "Exception while creating currentpolicies or groups")
						.put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}
			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.remove(ownerPolicy);
		}
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");

		Response ldapConfigresponse = configureRemovedUserPermissions(token, azureServiceAccountUser, userDetails,
				oidcEntityResponse, groups, policies, policiesString);

		if (ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)
				|| ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)) {

			return updateMetadataAfterRemovePermissionFromAzureSvcAcc(token, azureServiceAccountUser, userDetails,
					oidcEntityResponse, groups, currentpolicies, currentpoliciesString);
		} else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Failed to remvoe the user from the Azure Service Account\"]}");
		}
	}

	/**
	 * Method to configure the user permission after removed from Azure service
	 * account.
	 *
	 * @param token
	 * @param azureServiceAccountUser
	 * @param userDetails
	 * @param oidcEntityResponse
	 * @param groups
	 * @param policies
	 * @param policiesString
	 * @return
	 */
	private Response configureRemovedUserPermissions(String token, AzureServiceAccountUser azureServiceAccountUser,
			UserDetails userDetails, OIDCEntityResponse oidcEntityResponse, String groups, List<String> policies,
			String policiesString) {
		Response ldapConfigresponse = new Response();
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			ldapConfigresponse = ControllerUtil.configureUserpassUser(azureServiceAccountUser.getUsername(),
					policiesString, token);
		} else if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			ldapConfigresponse = ControllerUtil.configureLDAPUser(azureServiceAccountUser.getUsername(), policiesString,
					groups, token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			// OIDC Implementation : Entity Update
			try {
				ldapConfigresponse = oidcUtil.updateOIDCEntity(policies, oidcEntityResponse.getEntityName());
				oidcUtil.renewUserToken(userDetails.getClientToken());
			} catch (Exception e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, "Exception while updating the identity")
						.put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}
		}
		return ldapConfigresponse;
	}

	/**
	 * Method to update the metadata after removed user from Azure service
	 * account
	 *
	 * @param token
	 * @param azureServiceAccountUser
	 * @param userDetails
	 * @param oidcEntityResponse
	 * @param groups
	 * @param currentpolicies
	 * @param currentpoliciesString
	 * @return
	 */
	private ResponseEntity<String> updateMetadataAfterRemovePermissionFromAzureSvcAcc(String token,
			AzureServiceAccountUser azureServiceAccountUser, UserDetails userDetails,
			OIDCEntityResponse oidcEntityResponse, String groups, List<String> currentpolicies,
			String currentpoliciesString) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,"Start updating metadata after remove permission from AzureSvcAcc.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		String azureSvcaccName = azureServiceAccountUser.getAzureSvcAccName();
		// User has been removed from this Azure Service Account. Now metadata
		// has to be deleted
		String path = new StringBuffer(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureSvcaccName)
				.toString();
		Map<String, String> params = new HashMap<>();
		params.put("type", USERS);
		params.put("name", azureServiceAccountUser.getUsername());
		params.put("path", path);
		params.put(ACCESS, DELETE);
		Response metadataResponse = ControllerUtil.updateMetadata(params, token);
		if (metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus())
				|| HttpStatus.OK.equals(metadataResponse.getHttpstatus()))) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, String.format("User [%s] is successfully Removed from Azure Service Account [%s].",azureServiceAccountUser.getUsername(), azureServiceAccountUser.getAzureSvcAccName()))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));
			return ResponseEntity.status(HttpStatus.OK)
					.body("{\"messages\":[\"Successfully removed user from the Azure Service Account\"]}");
		} else {
			return revertUserPermission(token, azureServiceAccountUser, userDetails, oidcEntityResponse, groups,
					currentpolicies, currentpoliciesString);
		}
	}

	/**
	 * Method to revert user permission for remove user from Azure service
	 * account if update failed.
	 *
	 * @param token
	 * @param azureServiceAccountUser
	 * @param userDetails
	 * @param oidcEntityResponse
	 * @param groups
	 * @param currentpolicies
	 * @param currentpoliciesString
	 * @return
	 */
	private ResponseEntity<String> revertUserPermission(String token, AzureServiceAccountUser azureServiceAccountUser,
			UserDetails userDetails, OIDCEntityResponse oidcEntityResponse, String groups, List<String> currentpolicies,
			String currentpoliciesString) {
		Response configUserResponse = new Response();
		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			configUserResponse = ControllerUtil.configureUserpassUser(azureServiceAccountUser.getUsername(),
					currentpoliciesString, token);
		} else if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			configUserResponse = ControllerUtil.configureLDAPUser(azureServiceAccountUser.getUsername(),
					currentpoliciesString, groups, token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			// OIDC changes
			try {
				configUserResponse = oidcUtil.updateOIDCEntity(currentpolicies, oidcEntityResponse.getEntityName());
				oidcUtil.renewUserToken(userDetails.getClientToken());
			} catch (Exception e2) {
				log.error(e2);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_USER_FROM_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, "Exception while updating the identity")
						.put(LogMessage.STACKTRACE, Arrays.toString(e2.getStackTrace()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}
		}
		if (configUserResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)
				|| configUserResponse.getHttpstatus().equals(HttpStatus.OK)) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
					"{\"errors\":[\"Failed to remove the user from the Azure Service Account. Metadata update failed\"]}");
		} else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Failed to revert user association on Azure Service Account\"]}");
		}
	}

	/**
	 * To create aws ec2 role
	 * @param userDetails
	 * @param token
	 * @param awsLoginRole
	 * @return
	 * @throws TVaultValidationException
	 */
	public ResponseEntity<String> createAWSRole(UserDetails userDetails, String token, AWSLoginRole awsLoginRole) throws TVaultValidationException {
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		return awsAuthService.createRole(token, awsLoginRole, userDetails);
	}

	/**
	 * Create aws iam role
	 * @param userDetails
	 * @param token
	 * @param awsiamRole
	 * @return
	 * @throws TVaultValidationException
	 */
	public ResponseEntity<String> createIAMRole(UserDetails userDetails, String token, AWSIAMRole awsiamRole) throws TVaultValidationException {
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		return awsiamAuthService.createIAMRole(awsiamRole, token, userDetails);
	}

	/**
	 * Add AWS role to Azure Service Account
	 * @param userDetails
	 * @param token
	 * @param azureServiceAccountAWSRole
	 * @return
	 */
	public ResponseEntity<String> addAwsRoleToAzureSvcacc(UserDetails userDetails, String token, AzureServiceAccountAWSRole azureServiceAccountAWSRole) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_AWS_ROLE_MSG).
				put(LogMessage.MESSAGE,String.format("Start trying to add AWS Role[%s] to Azure Service Account [%s].",azureServiceAccountAWSRole.getRolename(),azureServiceAccountAWSRole.getAzureSvcAccName())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
        if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }
		if(!isAzureSvcaccPermissionInputValid(azureServiceAccountAWSRole.getAccess())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERRORBODYSTR);
		}
		if (azureServiceAccountAWSRole.getAccess().equalsIgnoreCase(AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING)) {
			azureServiceAccountAWSRole.setAccess(TVaultConstants.WRITE_POLICY);
		}
		String roleName = azureServiceAccountAWSRole.getRolename();
		String azureSvcName = azureServiceAccountAWSRole.getAzureSvcAccName().toLowerCase();
		String access = azureServiceAccountAWSRole.getAccess();

		roleName = (roleName !=null) ? roleName.toLowerCase() : roleName;
		access = (access != null) ? access.toLowerCase(): access;

		boolean isAuthorized = hasAddOrRemovePermission(userDetails, azureSvcName, token);
		if(isAuthorized){
			String policy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(access))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();


			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_AWS_ROLE_MSG).
					put(LogMessage.MESSAGE, String.format (POLICYSTR, policy)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));

			String readPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
			String writePolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
			String denyPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
			String ownerPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();

			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_AWS_ROLE_MSG).
					put(LogMessage.MESSAGE, String.format ("Policies are read - [%s], write - [%s], deny -[%s], owner - [%s]", readPolicy, writePolicy, denyPolicy, ownerPolicy)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));

			Response roleResponse = reqProcessor.process("/auth/aws/roles","{\"role\":\""+roleName+"\"}",token);
			String responseJson="";
			String authType = TVaultConstants.EC2;
			List<String> policies = new ArrayList<>();
			List<String> currentpolicies = new ArrayList<>();
			String policiesString = "";
			String currentpoliciesString = "";

			if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
				responseJson = roleResponse.getResponse();
				ObjectMapper objMapper = new ObjectMapper();
				try {
					JsonNode policiesArry =objMapper.readTree(responseJson).get(POLICIESSTR);
					for(JsonNode policyNode : policiesArry){
						currentpolicies.add(policyNode.asText());
					}
					authType = objMapper.readTree(responseJson).get("auth_type").asText();
				} catch (IOException e) {
                    log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                            put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                            put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_AWS_ROLE_MSG).
                            put(LogMessage.MESSAGE, e.getMessage()).
                            put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                            build()));
				}
				policies.addAll(currentpolicies);
				policies.remove(readPolicy);
				policies.remove(writePolicy);
				policies.remove(denyPolicy);
				policies.add(policy);
				policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
				currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
			} else{
				return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"Either AWS role doesn't exists or you don't have enough permission to add this AWS role to Azure Service Principal\"]}");
			}
			Response awsRoleConfigresponse = null;
			if (TVaultConstants.IAM.equals(authType)) {
				awsRoleConfigresponse = awsiamAuthService.configureAWSIAMRole(roleName,policiesString,token);
			}
			else {
				awsRoleConfigresponse = awsAuthService.configureAWSRole(roleName,policiesString,token);
			}
			if(awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
				String path = new StringBuffer(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureSvcName).toString();
				Map<String,String> params = new HashMap<>();
				params.put("type", AWSROLES);
				params.put("name",roleName);
				params.put("path",path);
				params.put(ACCESS,access);
				Response metadataResponse = ControllerUtil.updateMetadata(params,token);
				if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_AWS_ROLE_MSG).
							put(LogMessage.MESSAGE, String.format("AWS Role [%s] successfully associated to Azure Service Account [%s] with policy [%s].",azureServiceAccountAWSRole.getRolename(),azureServiceAccountAWSRole.getAzureSvcAccName(),azureServiceAccountAWSRole.getAccess())).
							put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role successfully associated with Azure Service Account\"]}");
				}
				if (TVaultConstants.IAM.equals(authType)) {
					awsRoleConfigresponse = awsiamAuthService.configureAWSIAMRole(roleName,currentpoliciesString,token);
				}
				else {
					awsRoleConfigresponse = awsAuthService.configureAWSRole(roleName,currentpoliciesString,token);
				}
				if(awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_AWS_ROLE_MSG).
							put(LogMessage.MESSAGE, "Reverting, AWS Role policy update success").
							put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
							put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Please try again\"]}");
				} else{
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_AWS_ROLE_MSG).
							put(LogMessage.MESSAGE, "Reverting AWS Role policy update failed").
							put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
							put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Contact Admin \"]}");
				}
			} else{
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Role configuration failed. Try Again\"]}");
			}
		} else{
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to add AWS Role to this Azure service account\"]}");
		}
	}

	/**
	 * Check if user has the permission to add user/group/awsrole/approles to
	 * the Azure Service Account
	 *
	 * @param userDetails
	 * @param action
	 * @param token
	 * @return
	 */
	public boolean hasAddOrRemovePermission(UserDetails userDetails, String serviceAccount, String token) {
		// Owner of the service account can add/remove users, groups, aws roles
		// and approles to service account
		if (userDetails.isAdmin()) {
			return true;
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "hasAddOrRemovePermission").
				put(LogMessage.MESSAGE,"Start checking if user has the permission to add user/group/awsrole/approles to the Azure Service Account.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		String ownerPolicy = new StringBuffer()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(serviceAccount).toString();
		String[] policies = policyUtils.getCurrentPolicies(token, userDetails.getUsername(), userDetails);
		return ArrayUtils.contains(policies, ownerPolicy);
	}

	/**
	 * Add Group to Azure service principal
	 *
	 * @param token
	 * @param azureServiceAccountGroup
	 * @param userDetails
	 * @return
	 */
	public ResponseEntity<String> addGroupToAzureServiceAccount(String token,
			AzureServiceAccountGroup azureServiceAccountGroup, UserDetails userDetails) {
		OIDCGroup oidcGroup = new OIDCGroup();
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("Start trying to add Group [%s] to Azure Service Principal [%s].",azureServiceAccountGroup.getGroupname(),azureServiceAccountGroup.getAzureSvcAccName()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		azureServiceAccountGroup.setAzureSvcAccName(azureServiceAccountGroup.getAzureSvcAccName().toLowerCase());
		if (!userDetails.isAdmin()) {
			token = tokenUtils.getSelfServiceToken();
		}
		if (!isAzureSvcaccPermissionInputValid(azureServiceAccountGroup.getAccess())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(ERRORBODYSTR);
		}
		if (azureServiceAccountGroup.getAccess().equalsIgnoreCase(AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING)) {
			azureServiceAccountGroup.setAccess(TVaultConstants.WRITE_POLICY);
		}

		if (TVaultConstants.USERPASS.equals(vaultAuthMethod)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("{\"errors\":[\"This operation is not supported for Userpass authentication. \"]}");
		}

		boolean canAddGroup = isAuthorizedToAddPermissionInAzureSvcAcc(userDetails, azureServiceAccountGroup.getAzureSvcAccName(), false);
		if (canAddGroup) {
			// Only Sudo policy can be added (as part of onbord) before activation.
			if (!isAzureSvcaccActivated(token, userDetails, azureServiceAccountGroup.getAzureSvcAccName())
					&& !TVaultConstants.SUDO_POLICY.equals(azureServiceAccountGroup.getAccess())) {
				log.error(
						JSONUtil.getJSON(ImmutableMap.<String, String>builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
								.put(LogMessage.MESSAGE, String.format(
										"Failed to add group permission to Azure service principal. [%s] is not activated.",
										azureServiceAccountGroup.getAzureSvcAccName()))
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
						"{\"errors\":[\"Failed to add group permission to Azure service principal. Azure service principal is not activated. Please activate this account and try again.\"]}");
			}

			return processRequestAndCallMetadataUpdateToAzureSvcAcc(token, userDetails, oidcGroup, azureServiceAccountGroup);
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("{\"errors\":[\"Access denied: No permission to add groups to this Azure service principal\"]}");
		}
	}

	/**
	 * Method to process AzureServiceAccountGroup request and call the update metadata and policy creations.
	 * @param token
	 * @param userDetails
	 * @param oidcGroup
	 * @param azureServiceAccountGroup
	 * @return
	 */
	private ResponseEntity<String> processRequestAndCallMetadataUpdateToAzureSvcAcc(String token, UserDetails userDetails,
			OIDCGroup oidcGroup, AzureServiceAccountGroup azureServiceAccountGroup) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,"Start process AzureServiceAccountGroup request and call the update metadata and policy creations.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		String policy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(azureServiceAccountGroup.getAccess()))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountGroup.getAzureSvcAccName()).toString();

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format(POLICYSTR, policy))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		String readPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountGroup.getAzureSvcAccName()).toString();
		String writePolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountGroup.getAzureSvcAccName()).toString();
		String denyPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountGroup.getAzureSvcAccName()).toString();
		String sudoPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountGroup.getAzureSvcAccName()).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,
						String.format("Group policies are, read - [%s], write - [%s], deny -[%s], owner - [%s]", readPolicy,
								writePolicy, denyPolicy, sudoPolicy))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		Response groupResp = new Response();

		if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			groupResp = reqProcessor.process(GROUPPATH,
					GROUPNAMESTR + azureServiceAccountGroup.getGroupname() + "\"}", token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			// call read api with groupname
			oidcGroup = oidcUtil.getIdentityGroupDetails(azureServiceAccountGroup.getGroupname(), token);
			if (oidcGroup != null) {
				groupResp.setHttpstatus(HttpStatus.OK);
				groupResp.setResponse(oidcGroup.getPolicies().toString());
			} else {
				groupResp.setHttpstatus(HttpStatus.BAD_REQUEST);
			}
		}

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("Group Response status is [%s]", groupResp.getHttpstatus()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		String responseJson = "";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if (HttpStatus.OK.equals(groupResp.getHttpstatus())) {
			responseJson = groupResp.getResponse();
			try {
				ObjectMapper objMapper = new ObjectMapper();
				// OIDC Changes
				if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
					currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
				} else if (TVaultConstants.OIDC.equals(vaultAuthMethod) && oidcGroup != null) {
					currentpolicies.addAll(oidcGroup.getPolicies());
				}
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, "Exception while creating currentpolicies")
						.put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}

			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.add(policy);
		} else {
			// New group to be configured
			policies.add(policy);
		}
		return configureGroupAndUpdateMetadataForAzureSvcAcc(token, userDetails, oidcGroup, azureServiceAccountGroup,
				policies, currentpolicies);
	}

	/**
	 * Method to update policies and metadata for add group to Azure service principal.
	 * @param token
	 * @param userDetails
	 * @param oidcGroup
	 * @param azureServiceAccountGroup
	 * @param policies
	 * @param currentpolicies
	 * @return
	 */
	private ResponseEntity<String> configureGroupAndUpdateMetadataForAzureSvcAcc(String token, UserDetails userDetails,
			OIDCGroup oidcGroup, AzureServiceAccountGroup azureServiceAccountGroup, List<String> policies,
			List<String> currentpolicies) {

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,"Start configuring Group and update metadata for AzureSvcAcc")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("policies [%s] before calling configureLDAPGroup", policies))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		Response ldapConfigresponse = new Response();
		// OIDC Changes
		if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			ldapConfigresponse = ControllerUtil.configureLDAPGroup(azureServiceAccountGroup.getGroupname(),
					policiesString, token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			ldapConfigresponse = oidcUtil.updateGroupPolicies(token, azureServiceAccountGroup.getGroupname(), policies,
					currentpolicies, oidcGroup != null ? oidcGroup.getId() : null);
			oidcUtil.renewUserToken(userDetails.getClientToken());
		}

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("After configured the group [%s] and status [%s] ", azureServiceAccountGroup.getGroupname(), ldapConfigresponse.getHttpstatus()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		if (ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)
				|| ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)) {
			String path = new StringBuffer(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureServiceAccountGroup.getAzureSvcAccName())
					.toString();
			Map<String, String> params = new HashMap<>();
			params.put("type", AzureServiceAccountConstants.AZURE_GROUP_MSG_STRING);
			params.put("name", azureServiceAccountGroup.getGroupname());
			params.put("path", path);
			params.put(AzureServiceAccountConstants.AZURE_ACCESS_MSG_STRING, azureServiceAccountGroup.getAccess());

			Response metadataResponse = ControllerUtil.updateMetadata(params, token);
			if (metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus())
					|| HttpStatus.OK.equals(metadataResponse.getHttpstatus()))) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, String.format("Group [%s] is successfully configured to Azure Service Account [%s] with policy [%s].",azureServiceAccountGroup.getGroupname(),azureServiceAccountGroup.getAzureSvcAccName(),azureServiceAccountGroup.getAccess()))
						.put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString())
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
						.build()));
				return ResponseEntity.status(HttpStatus.OK)
						.body("{\"messages\":[\"Group is successfully associated with Azure Service Principal\"]}");
			} else {
				return revertGroupPermissionForAzureSvcAcc(token, userDetails, oidcGroup,
						azureServiceAccountGroup.getGroupname(), currentpolicies, currentpoliciesString,
						metadataResponse);
			}
		} else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Group configuration failed.Try Again\"]}");
		}
	}

	/**
	 * Method to revert group permission if add group to Azure service principal failed.
	 * @param token
	 * @param userDetails
	 * @param oidcGroup
	 * @param groupName
	 * @param currentpolicies
	 * @param currentpoliciesString
	 * @param metadataResponse
	 * @return
	 */
	private ResponseEntity<String> revertGroupPermissionForAzureSvcAcc(String token, UserDetails userDetails,
			OIDCGroup oidcGroup, String groupName, List<String> currentpolicies, String currentpoliciesString,
			Response metadataResponse) {
		Response ldapRevertConfigresponse = new Response();
		// OIDC Changes
		if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			ldapRevertConfigresponse = ControllerUtil.configureLDAPGroup(groupName, currentpoliciesString, token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			ldapRevertConfigresponse = oidcUtil.updateGroupPolicies(token, groupName, currentpolicies, currentpolicies,
					oidcGroup != null ? oidcGroup.getId() : null);
			oidcUtil.renewUserToken(userDetails.getClientToken());
		}
		if (ldapRevertConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Reverting, group policy update success")
					.put(LogMessage.RESPONSE,
							(null != metadataResponse) ? metadataResponse.getResponse() : TVaultConstants.EMPTY)
					.put(LogMessage.STATUS,
							(null != metadataResponse) ? metadataResponse.getHttpstatus().toString()
									: TVaultConstants.EMPTY)
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Group configuration failed. Please try again\"]}");
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_GROUP_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Reverting group policy update failed")
					.put(LogMessage.RESPONSE,
							(null != metadataResponse) ? metadataResponse.getResponse() : TVaultConstants.EMPTY)
					.put(LogMessage.STATUS,
							(null != metadataResponse) ? metadataResponse.getHttpstatus().toString()
									: TVaultConstants.EMPTY)
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Group configuration failed. Contact Admin \"]}");
		}
	}

	/**
	 * Activate Azure Service Principal.
	 * @param token
	 * @param userDetails
	 * @param servicePrincipalName
	 * @return
	 */
	public ResponseEntity<String> activateAzureServicePrincipal(String token, UserDetails userDetails, String servicePrincipalName) {

		servicePrincipalName = servicePrincipalName.toLowerCase();
		String servicePrincipalId;
		String tenantId;
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
				put(LogMessage.MESSAGE, String.format ("Start trying to activate Azure Service Principal [%s]", servicePrincipalName)).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		boolean isAuthorized = true;
		if (userDetails != null) {
			isAuthorized = isAuthorizedToAddPermissionInAzureSvcAcc(userDetails, servicePrincipalName, false);
		}
		if (isAuthorized) {
			if (isAzureSvcaccActivated(token, userDetails, servicePrincipalName)) {
				log.error(
						JSONUtil.getJSON(ImmutableMap.<String, String>builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION)
								.put(LogMessage.MESSAGE, String.format("Failed to activate Azure Service Principal. [%s] is already activated", servicePrincipalName))
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
						"{\"errors\":[\"Azure Service Principal is already activated. You can now grant permissions from Permissions menu\"]}");
			}

			JsonObject azureMetadataJson = getAzureMetadata(token, servicePrincipalName);

			if (null!= azureMetadataJson && azureMetadataJson.has(SECRETSTR)) {
				if (!azureMetadataJson.get(SECRETSTR).isJsonNull()) {
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
							put(LogMessage.MESSAGE, String.format ("Trying to rotate secret for the Azure Service Principal [%s]", servicePrincipalName)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));

					JsonArray svcSecretArray = null;
					try {
						svcSecretArray = azureMetadataJson.get(SECRETSTR).getAsJsonArray();
						servicePrincipalId = azureMetadataJson.get("servicePrincipalId").getAsString();
						tenantId = azureMetadataJson.get("tenantId").getAsString();
					} catch (IllegalStateException e) {
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
								put(LogMessage.MESSAGE, String.format ("Failed to activate Azure Service Principal. Invalid metadata for [%s].", servicePrincipalName)).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
						return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to activate Azure Service Principal. Invalid metadata.\"]}");
					}

					if (null != svcSecretArray) {
						int secretSaveCount = 0;
						for (int i=0;i<svcSecretArray.size();i++) {

							JsonObject azureSecret = (JsonObject) svcSecretArray.get(i);

							if (azureSecret.has(AzureServiceAccountConstants.SECRET_KEY_ID)) {
								String secretKeyId = azureSecret.get(AzureServiceAccountConstants.SECRET_KEY_ID).getAsString();
								Long expiryDurationMs = Long.valueOf(azureSecret.get(AzureServiceAccountConstants.EXPIRY_DURATION).getAsString());
								log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
										put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
										put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
										put(LogMessage.MESSAGE, String.format ("Trying to rotate secret for the Azure Service Principal [%s] secret key id: [%s]", servicePrincipalName, secretKeyId)).
										put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
										build()));
								// Rotate Azure service account secret for each secret key id in metadata
								if (rotateAzureServicePrincipalSecret(token, servicePrincipalName, secretKeyId, servicePrincipalId, tenantId,expiryDurationMs, i+1)) {
									secretSaveCount++;
								}
							}
						}
					
						if (secretSaveCount == svcSecretArray.size()) {
							// Update status to activated.
							Response metadataUpdateResponse = azureServiceAccountUtils.updateActivatedStatusInMetadata(token, servicePrincipalName);
							if(metadataUpdateResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataUpdateResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataUpdateResponse.getHttpstatus()))){
								log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
										put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
										put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
										put(LogMessage.MESSAGE, String.format("Metadata updated Successfully for Azure Service Principal [%s].", servicePrincipalName)).
										put(LogMessage.STATUS, metadataUpdateResponse.getHttpstatus().toString()).
										put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
										build()));
								// Add rotate permission for owner
								String ownerNTId = getOwnerNTIdFromMetadata(token, servicePrincipalName );
								if (StringUtils.isEmpty(ownerNTId)) {
									log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
											put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
											put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
											put(LogMessage.MESSAGE, String.format("Failed to add rotate permission for owner for Azure Service Principal [%s]. Owner NT id not found in metadata", servicePrincipalName)).
											put(LogMessage.STATUS, HttpStatus.BAD_REQUEST.toString()).
											put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
											build()));
									return ResponseEntity.status(HttpStatus.OK).body("{\"errors\":[\"Failed to activate Azure Service Principal. Azure secrets are rotated and saved in T-Vault. However failed to add permission to owner. Owner info not found in Metadata.\"]}");
								}

								AzureServiceAccountUser azureServiceAccountUser = new AzureServiceAccountUser(servicePrincipalName,
										ownerNTId, AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING);

								ResponseEntity<String> addUserToAzureSvcAccResponse = addUserToAzureServiceAccount(token, userDetails, azureServiceAccountUser, false);
								if (HttpStatus.OK.equals(addUserToAzureSvcAccResponse.getStatusCode())) {
									log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
											put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
											put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
											put(LogMessage.MESSAGE, String.format ("Azure Service Principal [%s] activated successfully.", servicePrincipalName)).
											put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
											build()));
									return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Azure Service Principal activated successfully\"]}");

								}
								log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
										put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
										put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
										put(LogMessage.MESSAGE, String.format("Failed to add rotate permission to owner as part of Azure Service Principal activation for [%s].", servicePrincipalName)).
										put(LogMessage.STATUS, addUserToAzureSvcAccResponse!=null?addUserToAzureSvcAccResponse.getStatusCode().toString():HttpStatus.BAD_REQUEST.toString()).
										put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
										build()));
								return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to activate Azure Service Principal. Azure secrets are rotated and saved in T-Vault. However owner permission update failed.\"]}");

							}
							return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to activate Azure Service Principal. Azure secrets are rotated and saved in T-Vault. However metadata update failed.\"]}");
						}
						log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
								put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
								put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
								put(LogMessage.MESSAGE, String.format ("Azure Service account [%s] activated successfully", servicePrincipalName)).
								put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
								build()));
						return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to activate Azure Service Principal. Failed to rotate secrets for one or more SecretKeyIds.\"]}");
					}
				}
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
						put(LogMessage.MESSAGE, String.format ("Failed to activate activate Azure Service Principal. Invalid metadata for [%s].", servicePrincipalName)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to activate Azure Service Principal. Invalid metadata.\"]}");
			}
			else {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.ACTIVATE_ACTION).
						put(LogMessage.MESSAGE, String.format ("SecretKey information not found in metadata for Azure Service Principal [%s]", servicePrincipalName)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"SecretKey information not found in metadata for this Azure Service Principal\"]}");
			}

		}
		else{
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied: No permission to activate this Azure Service Principal\"]}");
		}
	}


	/**
	 * Rotate Azure Service Principal secret by secretKeyId.
	 * @param userDetails
	 * @param token
	 * @param azureServicePrincipalRotateRequest
	 * @return ResponseEntity
	 */
	public ResponseEntity<String> rotateSecret(UserDetails userDetails, String token,
											   AzureServicePrincipalRotateRequest azureServicePrincipalRotateRequest) {
		boolean rotationStatus = false;
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_ACTION).
				put(LogMessage.MESSAGE, String.format ("Trying to rotate secret for the Azure Service Principal [%s] " +
								"secret key id: [%s]", azureServicePrincipalRotateRequest.getAzureSvcAccName(),
						azureServicePrincipalRotateRequest.getSecretKeyId())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));

		String secretKeyId = azureServicePrincipalRotateRequest.getSecretKeyId();
		String servicePrincipalName = azureServicePrincipalRotateRequest.getAzureSvcAccName().toLowerCase();

		if (!hasResetPermissionForAzureServicePrincipal(userDetails, token, servicePrincipalName)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_ACTION).
					put(LogMessage.MESSAGE, String.format("Access denited. No permisison to rotate Azure Service Principal secret for [%s].", servicePrincipalName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body("{\"errors\":[\"Access denied: No permission to rotate secret for this Azure Service Principal.\"]}");
		}

		// Get metadata to check the secretkeyid
		JsonObject azureMetadataJson = getAzureMetadata(token, servicePrincipalName);

		if (null!= azureMetadataJson && azureMetadataJson.has(SECRETSTR)) {
			if (!azureMetadataJson.get(SECRETSTR).isJsonNull()) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_ACTION).
						put(LogMessage.MESSAGE, String.format("Trying to rotate secret for the Azure Service Principal [%s]", servicePrincipalName)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));

				JsonArray azureSecretArray = null;
				try {
					azureSecretArray = azureMetadataJson.get(SECRETSTR).getAsJsonArray();
				} catch (IllegalStateException e) {
					log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_ACTION).
							put(LogMessage.MESSAGE, String.format("Failed to rotate Azure Service Principal. Invalid metadata for [%s].", servicePrincipalName)).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to rotate secret for Azure Service Principal. Invalid metadata.\"]}");
				}

				if (null != azureSecretArray) {
					for (int i = 0; i < azureSecretArray.size(); i++) {

						JsonObject azureSecret = (JsonObject) azureSecretArray.get(i);
						if (azureSecret.has(AzureServiceAccountConstants.SECRET_KEY_ID) && secretKeyId
								.equals(azureSecret.get(AzureServiceAccountConstants.SECRET_KEY_ID).getAsString())) {
							log.debug(
									JSONUtil.getJSON(ImmutableMap.<String, String> builder()
											.put(LogMessage.USER,
													ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
											.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_ACTION)
											.put(LogMessage.MESSAGE,
													String.format(
															"Trying to rotate secret for the Azure Service Principal [%s] secret key id: [%s]",
															servicePrincipalName, secretKeyId))
											.put(LogMessage.APIURL,
													ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
											.build()));
							Long expiryDurationMs = Long.valueOf(azureSecret.get(AzureServiceAccountConstants.EXPIRY_DURATION).getAsString());
							// Rotate Azure Service Principal secret for each secret key id in metadata
							rotationStatus = rotateAzureServicePrincipalSecret(token, servicePrincipalName,
									secretKeyId, azureServicePrincipalRotateRequest.getServicePrincipalId(),
									azureServicePrincipalRotateRequest.getTenantId(), expiryDurationMs, i+1);
							break;
						}
					}
				}
			}
		}
		else {
			log.error(
					JSONUtil.getJSON(ImmutableMap.<String, String> builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_ACTION)
							.put(LogMessage.MESSAGE,
									String.format(
											"Failed to rotate secret for SecretkeyId [%s] for Azure Service Principal "
													+ "[%s]",
											azureServicePrincipalRotateRequest.getSecretKeyId(),
											azureServicePrincipalRotateRequest.getAzureSvcAccName()))
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Secret Key information not found in metadata for this Azure Service Principal\"]}");
		}

		if (rotationStatus) {
			log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_ACTION).
					put(LogMessage.MESSAGE, String.format ("Azure Service Principal [%s] rotated successfully for " +
									"SecretKeyId Completed [%s]",
							azureServicePrincipalRotateRequest.getAzureSvcAccName(),
							azureServicePrincipalRotateRequest.getSecretKeyId())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Azure Service Principal secret rotated successfully\"]}");
		}
		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_ACTION).
				put(LogMessage.MESSAGE, String.format ("Failed to rotate secret for SecretkeyId [%s] for Azure Service Principal " +
								"[%s]", azureServicePrincipalRotateRequest.getSecretKeyId(),
						azureServicePrincipalRotateRequest.getAzureSvcAccName())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Failed to rotate secret for Azure Service Principal\"]}");
	}

	/**
	 * Method to check if the user/approle has reset permission.
	 * @param userDetails
	 * @param token
	 * @param servicePrincipalName
	 * @return
	 */
	private boolean hasResetPermissionForAzureServicePrincipal(UserDetails userDetails, String token, String servicePrincipalName) {
		if (userDetails.isAdmin()) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, "HasResetPermissionForAzureServicePrincipal")
					.put(LogMessage.MESSAGE, "User is admin and therefore has reset permission on this Azure Service principal.")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return true;
		}
		String resetPermission = "w_"+ AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX + servicePrincipalName;
		ObjectMapper objectMapper = new ObjectMapper();
		List<String> currentPolicies = new ArrayList<>();
		List<String> identityPolicies = new ArrayList<>();
		Response response = reqProcessor.process("/auth/tvault/lookup","{}", token);
		if(HttpStatus.OK.equals(response.getHttpstatus())) {
			String responseJson = response.getResponse();
			try {
				currentPolicies = azureServiceAccountUtils.getTokenPoliciesAsListFromTokenLookupJson(objectMapper, responseJson);
				identityPolicies = policyUtils.getIdentityPoliciesAsListFromTokenLookupJson(objectMapper, responseJson);
				if (currentPolicies.contains(resetPermission) || identityPolicies.contains(resetPermission)) {
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, "HasResetPermissionForAzureServicePrincipal")
							.put(LogMessage.MESSAGE, "User has reset permission on this Azure Service principal.")
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
					return true;
				}
			} catch (IOException e) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, "hasResetPermissionForAzureServicePrincipal")
						.put(LogMessage.MESSAGE,
								"Failed to parse policies from token")
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, "hasResetPermissionForAzureServicePrincipal")
				.put(LogMessage.MESSAGE, "Access denied. User is not permitted to rotate secret for Azure Service principal")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		return false;
	}

	/**
	 * To get owner NT id from metadata for Azure Service Principal.
	 * @param token
	 * @param servicePrincipalName
	 * @return
	 */
	private String getOwnerNTIdFromMetadata(String token, String servicePrincipalName) {
		JsonObject getAzureMetadata = getAzureMetadata(token, servicePrincipalName);
		if (null != getAzureMetadata && getAzureMetadata.has(AzureServiceAccountConstants.OWNER_NT_ID)) {
			return getAzureMetadata.get(AzureServiceAccountConstants.OWNER_NT_ID).getAsString();
		}
		return null;
	}

	/**
	 * Rotate secret for a secretKeyID in an Azure Service Principal.
	 * @param token
	 * @param servicePrincipalName
	 * @param secretKeyId
	 * @param servicePrincipalId
	 * @param tenantId
	 * @param secretKeyIndex
	 * @return
	 */
	private boolean rotateAzureServicePrincipalSecret(String token, String servicePrincipalName, String secretKeyId, String servicePrincipalId, String tenantId, Long expiryDurationMs, int secretKeyIndex) {
		AzureServicePrincipalRotateRequest azureServicePrincipalRotateRequest = new AzureServicePrincipalRotateRequest(servicePrincipalName, secretKeyId, servicePrincipalId, tenantId, expiryDurationMs);

		AzureServiceAccountSecret azureServiceAccountSecret = azureServiceAccountUtils.rotateAzureServicePrincipalSecret(azureServicePrincipalRotateRequest);
		
		if (null != azureServiceAccountSecret) {
			log.info(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_SECRET_ACTION).
					put(LogMessage.MESSAGE, String.format ("Azure Service Principal [%s] rotated successfully for " +
									"Secret key id [%s]", servicePrincipalName,
							secretKeyId)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			// Save secret in azuresvcacc mount
			String path = AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + servicePrincipalName + "/" + AzureServiceAccountConstants.AZURE_SP_SECRET_FOLDER_PREFIX + (secretKeyIndex);
			if (azureServiceAccountUtils.writeAzureSPSecret(token, path, servicePrincipalName, azureServiceAccountSecret)) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_SECRET_ACTION).
						put(LogMessage.MESSAGE, "Secret saved to Azure Service Principal mount").
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				Response metadataUdpateResponse = azureServiceAccountUtils.updateAzureSPSecretKeyInfoInMetadata(token, servicePrincipalName, secretKeyId, azureServiceAccountSecret);
				if (null != metadataUdpateResponse && HttpStatus.NO_CONTENT.equals(metadataUdpateResponse.getHttpstatus())) {
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SP_ROTATE_SECRET_ACTION).
							put(LogMessage.MESSAGE, "Updated Azure Service Principal metadata with secretKeyId and expiry").
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return true;
				}
			}
		}
		return false;
	}

	public ResponseEntity<String> removeAwsRoleFromAzureSvcacc(UserDetails userDetails, String token,
			AzureServiceAccountAWSRole azureServiceAccountAWSRole) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_AWS_ROLE_AZURE_MSG).
				put(LogMessage.MESSAGE, String.format ("Start trying to remove AWS Role[%s] from Azure service principal [%s]", azureServiceAccountAWSRole.getRolename(),azureServiceAccountAWSRole.getAzureSvcAccName())).
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		if (!userDetails.isAdmin()) {
			token = tokenUtils.getSelfServiceToken();
		}
		if(!isAzureSvcaccPermissionInputValid(azureServiceAccountAWSRole.getAccess())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ERRORBODYSTR);
		}
		if (azureServiceAccountAWSRole.getAccess().equalsIgnoreCase(AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING)) {
			azureServiceAccountAWSRole.setAccess(TVaultConstants.WRITE_POLICY);
		}
		String roleName = azureServiceAccountAWSRole.getRolename();
		String azureSvcName = azureServiceAccountAWSRole.getAzureSvcAccName().toLowerCase();
		String access = azureServiceAccountAWSRole.getAccess();

		roleName = (roleName !=null) ? roleName.toLowerCase() : roleName;
		access = (access != null) ? access.toLowerCase(): access;

		boolean isAuthorized = hasAddOrRemovePermission(userDetails, azureSvcName, token);
		if(isAuthorized){
			String policy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(access))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();


			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_AWS_ROLE_AZURE_MSG).
					put(LogMessage.MESSAGE, String.format (POLICYSTR, policy)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			
			String readPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
			String writePolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
			String denyPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
			String ownerPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcName).toString();
			
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_AWS_ROLE_AZURE_MSG).
					put(LogMessage.MESSAGE, String.format ("Policies are, read - [%s], write - [%s], deny -[%s], owner - [%s]", readPolicy, writePolicy, denyPolicy, ownerPolicy)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			
			Response roleResponse = reqProcessor.process("/auth/aws/roles","{\"role\":\""+roleName+"\"}",token);
			String responseJson="";
			String authType = TVaultConstants.EC2;
			List<String> policies = new ArrayList<>();
			List<String> currentpolicies = new ArrayList<>();
			String policiesString = "";
			String currentpoliciesString = "";

			if(HttpStatus.OK.equals(roleResponse.getHttpstatus())){
				responseJson = roleResponse.getResponse();
				ObjectMapper objMapper = new ObjectMapper();
				try {
					JsonNode policiesArry =objMapper.readTree(responseJson).get(POLICIESSTR);
					for(JsonNode policyNode : policiesArry){
						currentpolicies.add(policyNode.asText());
					}
					authType = objMapper.readTree(responseJson).get("auth_type").asText();
				} catch (IOException e) {
                    log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
                            put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
                            put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_AWS_ROLE_AZURE_MSG).
                            put(LogMessage.MESSAGE, e.getMessage()).
                            put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
                            build()));
                    policies.addAll(currentpolicies);
    				policies.remove(readPolicy);
    				policies.remove(writePolicy);
    				policies.remove(denyPolicy);
    				policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
    				currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
				}
			} else{
				return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"errors\":[\"Either AWS role doesn't exists or you don't have enough permission to remove this AWS role from Azure Service Principal\"]}");
			}
			Response awsRoleConfigresponse = null;
			if (TVaultConstants.IAM.equals(authType)) {
				awsRoleConfigresponse = awsiamAuthService.configureAWSIAMRole(roleName,policiesString,token);
			}
			else {
				awsRoleConfigresponse = awsAuthService.configureAWSRole(roleName,policiesString,token);
			}
			if(awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
				String path = new StringBuffer(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureSvcName).toString();
				Map<String,String> params = new HashMap<>();
				params.put("type", AWSROLES);
				params.put("name",roleName);
				params.put("path",path);
				params.put(ACCESS,DELETE);
				Response metadataResponse = ControllerUtil.updateMetadata(params,token);
				if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
					log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
							put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
							put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_AWS_ROLE_AZURE_MSG).
							put(LogMessage.MESSAGE, String.format("AWS Role [%s] successfully removed from Azure Service Account [%s].",azureServiceAccountAWSRole.getRolename(),azureServiceAccountAWSRole.getAzureSvcAccName())).
							put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
							put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
							build()));
					return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"AWS Role successfully removed from Azure Service Account\"]}");
				}
				if (TVaultConstants.IAM.equals(authType)) {
					awsRoleConfigresponse = awsiamAuthService.configureAWSIAMRole(roleName,currentpoliciesString,token);
				}
				else {
					awsRoleConfigresponse = awsAuthService.configureAWSRole(roleName,currentpoliciesString,token);
				}
			if(awsRoleConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_AWS_ROLE_AZURE_MSG).
						put(LogMessage.MESSAGE, "Reverting, AWS Role policy update success").
						put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
						put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Please try again\"]}");
			}
			else{
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_AWS_ROLE_MSG).
						put(LogMessage.MESSAGE, "Reverting AWS Role policy update failed").
						put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
						put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"AWS Role configuration failed. Contact Admin \"]}");
			}
		} 
			else{
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Role configuration failed. Try Again\"]}");
			}
		}else{
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to remove AWS Role from this Azure service account\"]}");
		}
	}

	/**
     * Remove Group from Azure Service Account
     *
     * @param token
     * @param azureServiceAccountGroup
     * @param userDetails
     * @return
     */
    public ResponseEntity<String> removeGroupFromAzureServiceAccount(String token, AzureServiceAccountGroup azureServiceAccountGroup, UserDetails userDetails) {
		OIDCGroup oidcGroup = new OIDCGroup();
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,String.format("Trying to remove Group [%s] from Azure Service Account [%s].",azureServiceAccountGroup.getGroupname(),azureServiceAccountGroup.getAzureSvcAccName()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		azureServiceAccountGroup.setAzureSvcAccName(azureServiceAccountGroup.getAzureSvcAccName().toLowerCase());
		if (!userDetails.isAdmin()) {
            token = tokenUtils.getSelfServiceToken();
        }

        if (!isAzureSvcaccPermissionInputValid(azureServiceAccountGroup.getAccess())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(ERRORBODYSTR);
		}
		if (azureServiceAccountGroup.getAccess().equalsIgnoreCase(AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING)) {
			azureServiceAccountGroup.setAccess(TVaultConstants.WRITE_POLICY);
		}

        String azureSvcAccountName =  azureServiceAccountGroup.getAzureSvcAccName();

		boolean isAuthorized = isAuthorizedToAddPermissionInAzureSvcAcc(userDetails, azureSvcAccountName, false);
		if (isAuthorized) {
			return getGroupDetailsAndAzureSvcAccActivatedCheck(token, azureServiceAccountGroup, userDetails, oidcGroup,
					azureSvcAccountName);
        }
        else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to remove groups from this Azure service principal\"]}");
        }

    }

	/**
	 * Method to check the azure service principal activation and get the group details
	 * @param token
	 * @param azureServiceAccountGroup
	 * @param userDetails
	 * @param oidcGroup
	 * @param azureSvcAccountName
	 * @return
	 */
	private ResponseEntity<String> getGroupDetailsAndAzureSvcAccActivatedCheck(String token,
			AzureServiceAccountGroup azureServiceAccountGroup, UserDetails userDetails, OIDCGroup oidcGroup,
			String azureSvcAccountName) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION,"getGroupDetailsAndAzureSvcAccActivatedCheck")
				.put(LogMessage.MESSAGE,"Checking the azure service principal activation and get the group details")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		// Only Sudo policy can be added (as part of onbord) before activation.
		if (!isAzureSvcaccActivated(token, userDetails, azureSvcAccountName)
				&& !TVaultConstants.SUDO_POLICY.equals(azureServiceAccountGroup.getAccess())) {
			log.error(
					JSONUtil.getJSON(ImmutableMap.<String, String>builder()
							.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
							.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG)
							.put(LogMessage.MESSAGE, String.format("Failed to remove group permission to Azure Service principal. [%s] is not activated.", azureSvcAccountName))
							.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
							.build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Failed to remove group permission. Azure Service Principal is not activated. Please activate this service principal and try again.\"]}");
		}

		// check for this group is associated to this Azure Service account
		String azureMetadataPath = new StringBuilder().append(AzureServiceAccountConstants.AZURE_SVCC_ACC_META_PATH).append(azureSvcAccountName).toString();
		Response metadataReadResponse = reqProcessor.process("/azuresvcacct", PATHSTR + azureMetadataPath + "\"}", token);
		Map<String, Object> responseMap = null;
		boolean metaDataResponseStatus = true;
		if(metadataReadResponse != null && HttpStatus.OK.equals(metadataReadResponse.getHttpstatus())) {
			responseMap = ControllerUtil.parseJson(metadataReadResponse.getResponse());
			if(responseMap.isEmpty()) {
				metaDataResponseStatus = false;
			}
		}
		else {
			metaDataResponseStatus = false;
		}

		if(metaDataResponseStatus) {
			@SuppressWarnings("unchecked")
			Map<String,Object> metadataMap = (Map<String,Object>)responseMap.get("data");
			Map<String,Object> groupsData = (Map<String,Object>)metadataMap.get(TVaultConstants.GROUPS);

			if (groupsData == null || !groupsData.containsKey(azureServiceAccountGroup.getGroupname())) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
						put(LogMessage.MESSAGE, String.format ("Group [%s] is not associated to Azure service principal [%s]", azureServiceAccountGroup.getGroupname(), azureSvcAccountName)).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to remove group from Azure service principal. Group association to Azure service principal not found\"]}");
			}
		}else {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
					put(LogMessage.MESSAGE, String.format ("Error Fetching existing Azure service principal info [%s]", azureSvcAccountName)).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Error Fetching existing Azure service principal info. please check the path specified\"]}");
		}

		return getGroupDetailsAndCallRemovalProcess(token, azureServiceAccountGroup, userDetails, oidcGroup,
				azureSvcAccountName);
	}

	/**
	 * Method to call the group removal based on the auth method
	 * @param token
	 * @param azureServiceAccountGroup
	 * @param userDetails
	 * @param oidcGroup
	 * @param azureSvcAccountName
	 * @return
	 */
	private ResponseEntity<String> getGroupDetailsAndCallRemovalProcess(String token,
			AzureServiceAccountGroup azureServiceAccountGroup, UserDetails userDetails, OIDCGroup oidcGroup,
			String azureSvcAccountName) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
				put(LogMessage.MESSAGE,"Method to call the group removal based on the auth method").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		Response groupResp = new Response();
		if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			groupResp = reqProcessor.process(GROUPPATH, GROUPNAMESTR + azureServiceAccountGroup.getGroupname() + "\"}", token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			// call read api with groupname
			oidcGroup = oidcUtil.getIdentityGroupDetails(azureServiceAccountGroup.getGroupname(), token);
			if (oidcGroup != null) {
				groupResp.setHttpstatus(HttpStatus.OK);
				groupResp.setResponse(oidcGroup.getPolicies().toString());
			} else {
				groupResp.setHttpstatus(HttpStatus.BAD_REQUEST);
			}
		}
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		        put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
		        put(LogMessage.MESSAGE, String.format ("userResponse status is [%s]", groupResp.getHttpstatus())).
		        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		        build()));

		return removePoliciesAndUpdateMetadataForAzurevcAcc(token, azureServiceAccountGroup, userDetails, oidcGroup,
				azureSvcAccountName, groupResp);
	}

	 /**
	 * Method to update policies for remove group from Azure service account.
	 * @param token
	 * @param azureServiceAccountGroup
	 * @param userDetails
	 * @param oidcGroup
	 * @param azureSvcAccountName
	 * @param groupResp
	 * @return
	 */
	private ResponseEntity<String> removePoliciesAndUpdateMetadataForAzurevcAcc(String token,
			AzureServiceAccountGroup azureServiceAccountGroup, UserDetails userDetails, OIDCGroup oidcGroup,
			String azureSvcAccountName, Response groupResp) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "removePoliciesAndUpdateMetadataForAzurevcAcc").
				put(LogMessage.MESSAGE,"Start updating policies for remove group from Azure service account.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		String readPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY)).append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
		String writePolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY)).append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
		String denyPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY)).append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();
		String sudoPolicy = new StringBuffer().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY)).append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcAccountName).toString();

		log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		        put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		        put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
		        put(LogMessage.MESSAGE, String.format ("Policies are, read - [%s], write - [%s], deny -[%s], owner - [%s]", readPolicy, writePolicy, denyPolicy, sudoPolicy)).
		        put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		        build()));

		String responseJson="";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if(groupResp != null && HttpStatus.OK.equals(groupResp.getHttpstatus())){
		    responseJson = groupResp.getResponse();
		    try {
				ObjectMapper objMapper = new ObjectMapper();
				// OIDC Changes
				if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
					currentpolicies = ControllerUtil.getPoliciesAsListFromJson(objMapper, responseJson);
				} else if (TVaultConstants.OIDC.equals(vaultAuthMethod) && oidcGroup != null) {
					currentpolicies.addAll(oidcGroup.getPolicies());
				}
		    } catch (IOException e) {
		        log.error(e);
		        log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
		                put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
		                put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
		                put(LogMessage.MESSAGE, "Exception while creating currentpolicies or groups").
		                put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace())).
		                put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
		                build()));
		    }

		    policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
		}else {
			return deleteOrphanGroupEntriesForAzureSvcAcc(token, azureServiceAccountGroup);
		}

		return configureGroupPoliciesByAuthMethod(token, azureServiceAccountGroup, userDetails, oidcGroup, policies,
				currentpolicies);
	}

	/**
	 * Method to configure group policies based on the auth method and call the metadata update
	 * @param token
	 * @param azureServiceAccountGroup
	 * @param userDetails
	 * @param oidcGroup
	 * @param policies
	 * @param currentpolicies
	 * @return
	 */
	private ResponseEntity<String> configureGroupPoliciesByAuthMethod(String token,
			AzureServiceAccountGroup azureServiceAccountGroup, UserDetails userDetails, OIDCGroup oidcGroup,
			List<String> policies, List<String> currentpolicies) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
				put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
				put(LogMessage.ACTION, "configureGroupPoliciesByAuthMethod").
				put(LogMessage.MESSAGE,"Start configuring group policies based on the auth method and call the metadata update.").
				put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
				build()));
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
		Response ldapConfigresponse = new Response();
		// OIDC Changes
		if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
			ldapConfigresponse = ControllerUtil.configureLDAPGroup(azureServiceAccountGroup.getGroupname(), policiesString, token);
		} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
			ldapConfigresponse = oidcUtil.updateGroupPolicies(token, azureServiceAccountGroup.getGroupname(), policies, currentpolicies,
					oidcGroup != null ? oidcGroup.getId() : null);
			oidcUtil.renewUserToken(userDetails.getClientToken());
		}
		if(ldapConfigresponse.getHttpstatus().equals(HttpStatus.NO_CONTENT) || ldapConfigresponse.getHttpstatus().equals(HttpStatus.OK)){
			return updateMetadataForRemoveGroupFromAzureSvcAcc(token, azureServiceAccountGroup, userDetails, oidcGroup,
					currentpolicies, currentpoliciesString);
		}
		else {
			String ssoToken = oidcUtil.getSSOToken();
			if (!StringUtils.isEmpty(ssoToken)) {
				String objectId = oidcUtil.getGroupObjectResponse(ssoToken, azureServiceAccountGroup.getGroupname());
				if (objectId == null || StringUtils.isEmpty(objectId)) {
					return deleteOrphanGroupEntriesForAzureSvcAcc(token, azureServiceAccountGroup);
				}
			}
		    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Group configuration failed.Try Again\"]}");
		}
	}

	/**
	 * Method to delete orphan group entries if exists for Azure service account
	 * @param token
	 * @param azureServiceAccountGroup
	 * @return
	 */
	private ResponseEntity<String> deleteOrphanGroupEntriesForAzureSvcAcc(String token, AzureServiceAccountGroup azureServiceAccountGroup) {
		// Trying to remove the orphan entries if exists
		String path = new StringBuilder(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureServiceAccountGroup.getAzureSvcAccName()).toString();
		Map<String,String> params = new HashMap<>();
		params.put("type", GROUPSTR);
		params.put("name",azureServiceAccountGroup.getGroupname());
		params.put("path",path);
		params.put(ACCESS,DELETE);
		Response metadataResponse = ControllerUtil.updateMetadata(params,token);
		if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, "Remove Group from Azure service principal").
					put(LogMessage.MESSAGE, String.format ("Group [%s] is successfully removed from Azure service principal [%s]", azureServiceAccountGroup.getGroupname(), azureServiceAccountGroup.getAzureSvcAccName())).
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("{\"Message\":\"Group not available or deleted from AD, removed the group assignment and permissions \"}");
		}else{
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"messages\":[\"Group configuration failed.Try again \"]}");
		}
	}

		/**
		 * Method to update metadata and revert group permission if metadata update failed.
		 *
		 * @param token
		 * @param azureServiceAccountGroup
		 * @param userDetails
		 * @param oidcGroup
		 * @param currentpolicies
		 * @param currentpoliciesString
		 * @return
		 */
		private ResponseEntity<String> updateMetadataForRemoveGroupFromAzureSvcAcc(String token,
				AzureServiceAccountGroup azureServiceAccountGroup, UserDetails userDetails, OIDCGroup oidcGroup,
				List<String> currentpolicies, String currentpoliciesString) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
					put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
					put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
					put(LogMessage.MESSAGE,"Start updating metadata and revert group permission if metadata update failed.").
					put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
					build()));
			String path = new StringBuilder(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureServiceAccountGroup.getAzureSvcAccName()).toString();
			Map<String,String> params = new HashMap<>();
			params.put("type", GROUPSTR);
			params.put("name",azureServiceAccountGroup.getGroupname());
			params.put("path",path);
			params.put(ACCESS,DELETE);
			Response metadataResponse = ControllerUtil.updateMetadata(params,token);
			if(metadataResponse !=null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus()) || HttpStatus.OK.equals(metadataResponse.getHttpstatus()))){
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
						put(LogMessage.MESSAGE,  String.format("Group [%s] is successfully removed from Azure Service Principal [%s].",azureServiceAccountGroup.getGroupname(),azureServiceAccountGroup.getAzureSvcAccName())).
						put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString()).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.OK).body("{\"messages\":[\"Group is successfully removed from Azure Service Principal\"]}");
			}else {
				return revertGroupPermissionForAzureSvcAcc(token, azureServiceAccountGroup, userDetails, oidcGroup,
						currentpolicies, currentpoliciesString, metadataResponse);
			}
		}
		
		/**
		 * Method to revert group permission for Azure service account
		 *
		 * @param token
		 * @param azureServiceAccountGroup
		 * @param userDetails
		 * @param oidcGroup
		 * @param currentpolicies
		 * @param currentpoliciesString
		 * @param metadataResponse
		 * @return
		 */
		private ResponseEntity<String> revertGroupPermissionForAzureSvcAcc(String token,
				AzureServiceAccountGroup azureServiceAccountGroup, UserDetails userDetails, OIDCGroup oidcGroup,
				List<String> currentpolicies, String currentpoliciesString, Response metadataResponse) {
			Response configGroupResponse = new Response();
			// OIDC Changes
			if (TVaultConstants.LDAP.equals(vaultAuthMethod)) {
				configGroupResponse = ControllerUtil.configureLDAPGroup(azureServiceAccountGroup.getGroupname(), currentpoliciesString, token);
			} else if (TVaultConstants.OIDC.equals(vaultAuthMethod)) {
				configGroupResponse = oidcUtil.updateGroupPolicies(token, azureServiceAccountGroup.getGroupname(), currentpolicies,
						currentpolicies, oidcGroup != null ? oidcGroup.getId() : null);
				oidcUtil.renewUserToken(userDetails.getClientToken());
			}
			if(configGroupResponse.getHttpstatus().equals(HttpStatus.NO_CONTENT)){
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
						put(LogMessage.MESSAGE, "Reverting, group policy update success").
						put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
						put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Group configuration failed. Please try again\"]}");
			}else{
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_GROUP_FROM_AZURESVCACC_MSG).
						put(LogMessage.MESSAGE, "Reverting group policy update failed").
						put(LogMessage.RESPONSE, (null!=metadataResponse)?metadataResponse.getResponse():TVaultConstants.EMPTY).
						put(LogMessage.STATUS, (null!=metadataResponse)?metadataResponse.getHttpstatus().toString():TVaultConstants.EMPTY).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"errors\":[\"Group configuration failed. Contact Admin \"]}");
			}
		}

	/**
	 * Associate Approle to Azure Service Principal
	 *
	 * @param userDetails
	 * @param token
	 * @param azureServiceAccountApprole
	 * @return
	 */
	public ResponseEntity<String> associateApproletoAzureServiceAccount(UserDetails userDetails, String token,
			AzureServiceAccountApprole azureServiceAccountApprole) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,String.format("Start trying to add Approle[%s] to Azure Service Principal[%s].",azureServiceAccountApprole.getApprolename(),azureServiceAccountApprole.getAzureSvcAccName()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		azureServiceAccountApprole.setAzureSvcAccName(azureServiceAccountApprole.getAzureSvcAccName().toLowerCase());
		if (!userDetails.isAdmin()) {
			token = tokenUtils.getSelfServiceToken();
		}
		if (!isAzureSvcaccPermissionInputValid(azureServiceAccountApprole.getAccess())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Invalid value specified for access. Valid values are read, rotate, deny")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(ERRORBODYSTR);
		}
		if (azureServiceAccountApprole.getAccess().equalsIgnoreCase(AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING)) {
			azureServiceAccountApprole.setAccess(TVaultConstants.WRITE_POLICY);
		}
		
		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(azureServiceAccountApprole.getApprolename())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Access denied: no permission to associate this AppRole to any Azure Service Principal")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Access denied: no permission to associate this AppRole to any Azure Service Principal\"]}");
		}

		boolean isAuthorized = hasAddOrRemovePermission(userDetails, azureServiceAccountApprole.getAzureSvcAccName(), token);
		if (isAuthorized) {
			return processAndConstructPoliciesForAddApproleToAzureSvcAcc(token, azureServiceAccountApprole);
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Access denied: No permission to add Approle to this azure service principal")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("{\"errors\":[\"Access denied: No permission to add Approle to this azure service principal\"]}");
		}
	}

	/**
	 * Method to process the request and construct the policies for add approle to azure service principal.
	 * @param token
	 * @param azureServiceAccountApprole
	 * @return
	 */
	private ResponseEntity<String> processAndConstructPoliciesForAddApproleToAzureSvcAcc(String token,
			AzureServiceAccountApprole azureServiceAccountApprole) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,"Start process the request and construct the policies for add approle to azure service principal.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		String policy = new StringBuilder().append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(azureServiceAccountApprole.getAccess()))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountApprole.getAzureSvcAccName()).toString();

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format(POLICYSTR, policy))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		String readPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountApprole.getAzureSvcAccName()).toString();
		String writePolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountApprole.getAzureSvcAccName()).toString();
		String denyPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountApprole.getAzureSvcAccName()).toString();
		String ownerPolicy = new StringBuilder()
				.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
				.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureServiceAccountApprole.getAzureSvcAccName()).toString();
		
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,
						String.format("Approle Policies are, read - [%s], write - [%s], deny -[%s], owner - [%s]",
								readPolicy, writePolicy, denyPolicy, ownerPolicy))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

		Response roleResponse = reqProcessor.process(READROLEPATH,
				ROLENAME + azureServiceAccountApprole.getApprolename() + "\"}", token);

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("Approle Response status is [%s]", roleResponse.getHttpstatus()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));

		String responseJson = "";
		List<String> policies = new ArrayList<>();
		List<String> currentpolicies = new ArrayList<>();

		if (HttpStatus.OK.equals(roleResponse.getHttpstatus())) {
			responseJson = roleResponse.getResponse();
			ObjectMapper objMapper = new ObjectMapper();
			try {
				JsonNode policiesArry = objMapper.readTree(responseJson).get("data").get(TVaultConstants.POLICIES);
				if (null != policiesArry) {
					for (JsonNode policyNode : policiesArry) {
						currentpolicies.add(policyNode.asText());
					}
				}
			} catch (IOException e) {
				log.error(e);
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE, "Exception while creating currentpolicies")
						.put(LogMessage.STACKTRACE, Arrays.toString(e.getStackTrace()))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			}
			policies.addAll(currentpolicies);
			policies.remove(readPolicy);
			policies.remove(writePolicy);
			policies.remove(denyPolicy);
			policies.add(policy);
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Non existing role name. Please configure approle as first step")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
					.body("{\"errors\":[\"Either Approle doesn't exists or you don't have enough permission to add this approle to Azure Service Principal\"]}");
		}
		String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
		String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");

		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE, String.format("Policies [%s] before calling configureApprole", policies))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		//Configure the approle with policies for Azure service principal.
		Response approleControllerResp = appRoleService.configureApprole(azureServiceAccountApprole.getApprolename(), policiesString, token);

		if (approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT)
				|| approleControllerResp.getHttpstatus().equals(HttpStatus.OK)) {
			return updateMetadataForAddApproleToAzureSvcAcc(token, azureServiceAccountApprole, currentpoliciesString);
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Failed to add Approle to the Azure Service Principal")
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body("{\"errors\":[\"Failed to add Approle to the Azure Service Principal\"]}");
		}
	}

	/**
	 * Method to call the update metadata for adding the approle to azure service principal.
	 * @param token
	 * @param azureServiceAccountApprole
	 * @param currentpoliciesString
	 * @return
	 */
	private ResponseEntity<String> updateMetadataForAddApproleToAzureSvcAcc(String token,
			AzureServiceAccountApprole azureServiceAccountApprole, String currentpoliciesString) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,"Start updating metadata for adding the approle to azure service principal.")
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
				.build()));
		Response approleControllerResp;
		String path = new StringBuilder(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH).append(azureServiceAccountApprole.getAzureSvcAccName())
				.toString();
		Map<String, String> params = new HashMap<>();
		params.put("type", TVaultConstants.APP_ROLES);
		params.put("name", azureServiceAccountApprole.getApprolename());
		params.put("path", path);
		params.put(ACCESS, azureServiceAccountApprole.getAccess());
		Response metadataResponse = ControllerUtil.updateMetadata(params, token);
		if (metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus())
				|| HttpStatus.OK.equals(metadataResponse.getHttpstatus()))) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, String.format("Approle [%s] successfully associated to Azure Service Principal [%s] with policy [%s].",azureServiceAccountApprole.getApprolename(),azureServiceAccountApprole.getAzureSvcAccName(),azureServiceAccountApprole.getAccess()))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));

			return ResponseEntity.status(HttpStatus.OK)
					.body("{\"messages\":[\"Approle successfully associated with Azure Service Principal\"]}");
		}
		//Revert the approle policy configuration if update metadata failed.
		approleControllerResp = appRoleService.configureApprole(azureServiceAccountApprole.getApprolename(), currentpoliciesString, token);
		if (approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {

			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Reverting, Approle policy update success")
					.put(LogMessage.RESPONSE, (null != metadataResponse) ? metadataResponse.getResponse() : TVaultConstants.EMPTY)
					.put(LogMessage.STATUS, (null != metadataResponse) ? metadataResponse.getHttpstatus().toString() : TVaultConstants.EMPTY)
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Approle configuration failed. Please try again\"]}");
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.ADD_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE, "Reverting Approle policy update failed")
					.put(LogMessage.RESPONSE, (null != metadataResponse) ? metadataResponse.getResponse() : TVaultConstants.EMPTY)
					.put(LogMessage.STATUS, (null != metadataResponse) ? metadataResponse.getHttpstatus().toString() : TVaultConstants.EMPTY)
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("{\"errors\":[\"Approle configuration failed. Contact Admin \"]}");
	}
}
	
	/**
	 * Remove approle from Azure service account
	 *
	 * @param userDetails
	 * @param token
	 * @param azureServiceAccountApprole
	 * @return
	 */
	public ResponseEntity<String> removeApproleFromAzureSvcAcc(UserDetails userDetails, String token,
			AzureServiceAccountApprole azureServiceAccountApprole) {
		log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
				.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
				.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_APPROLE_TO_AZURESVCACC_MSG)
				.put(LogMessage.MESSAGE,
						String.format("Start trying to remove approle[%s] from Azure Service Account [%s]",
								azureServiceAccountApprole.getApprolename(),azureServiceAccountApprole.getAzureSvcAccName()))
				.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		azureServiceAccountApprole.setAzureSvcAccName(azureServiceAccountApprole.getAzureSvcAccName().toLowerCase());
		if (!userDetails.isAdmin()) {
			token = tokenUtils.getSelfServiceToken();
		}
		String approleName = azureServiceAccountApprole.getApprolename();
		String azureSvcaccName = azureServiceAccountApprole.getAzureSvcAccName();
		String access = azureServiceAccountApprole.getAccess();
		approleName = (approleName != null) ? approleName.toLowerCase() : approleName;
		access = (access != null) ? access.toLowerCase() : access;

		if (Arrays.asList(TVaultConstants.SELF_SUPPORT_ADMIN_APPROLES).contains(azureServiceAccountApprole.getApprolename())) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Access denied: no permission to remove this AppRole to any Service Account\"]}");
		}
		if (!isAzureSvcaccPermissionInputValid(access)) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(ERRORBODYSTR);
		}

		boolean isAuthorized = hasAddOrRemovePermission(userDetails, azureSvcaccName, token);

		if (isAuthorized) {
			String readPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.READ_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
			String writePolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.WRITE_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
			String denyPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.DENY_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();
			String ownerPolicy = new StringBuffer()
					.append(TVaultConstants.SVC_ACC_POLICIES_PREFIXES.getKey(TVaultConstants.SUDO_POLICY))
					.append(AzureServiceAccountConstants.AZURE_SVCACC_POLICY_PREFIX).append(azureSvcaccName).toString();

			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_APPROLE_TO_AZURESVCACC_MSG)
					.put(LogMessage.MESSAGE,
							String.format("Policies are, read - [%s], write - [%s], deny -[%s], owner - [%s]",
									readPolicy, writePolicy, denyPolicy, ownerPolicy))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			Response roleResponse = reqProcessor.process(READROLEPATH,
					ROLENAME + approleName + "\"}", token);
			String responseJson = "";
			List<String> policies = new ArrayList<>();
			List<String> currentpolicies = new ArrayList<>();
			if (HttpStatus.OK.equals(roleResponse.getHttpstatus())) {
				responseJson = roleResponse.getResponse();
				ObjectMapper objMapper = new ObjectMapper();
				try {
					JsonNode policiesArry = objMapper.readTree(responseJson).get("data").get(POLICIESSTR);
					if (null != policiesArry) {
						for (JsonNode policyNode : policiesArry) {
							currentpolicies.add(policyNode.asText());
						}
					}
				} catch (IOException e) {
					log.error(e);
				}
				policies.addAll(currentpolicies);
				policies.remove(readPolicy);
				policies.remove(writePolicy);
				policies.remove(denyPolicy);
			}
			else {
				return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
						.body("{\"errors\":[\"Either Approle doesn't exists or you don't have enough permission to remove this approle from Azure Service Principal\"]}");
			}
				String policiesString = org.apache.commons.lang3.StringUtils.join(policies, ",");
				String currentpoliciesString = org.apache.commons.lang3.StringUtils.join(currentpolicies, ",");
				log.info(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_APPROLE_TO_AZURESVCACC_MSG)
						.put(LogMessage.MESSAGE,
								"Remove approle from Azure Service account -  policy :" + policiesString
										+ " is being configured")
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
				// Update the policy for approle
				Response approleControllerResp = appRoleService.configureApprole(approleName, policiesString, token);
				if (approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT)
						|| approleControllerResp.getHttpstatus().equals(HttpStatus.OK)) {
					String path = new StringBuffer(AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH)
							.append(azureSvcaccName).toString();
					Map<String, String> params = new HashMap<String, String>();
					params.put("type", "app-roles");
					params.put("name", approleName);
					params.put("path", path);
					params.put(ACCESS, DELETE);
					Response metadataResponse = ControllerUtil.updateMetadata(params, token);
					if (metadataResponse != null && (HttpStatus.NO_CONTENT.equals(metadataResponse.getHttpstatus())
							|| HttpStatus.OK.equals(metadataResponse.getHttpstatus()))) {
						log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
								.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
								.put(LogMessage.ACTION, AzureServiceAccountConstants.REMOVE_APPROLE_TO_AZURESVCACC_MSG)
								.put(LogMessage.MESSAGE, String.format("Approle [%s] is successfully removed from Azure Service Account [%s].",azureServiceAccountApprole.getApprolename(),azureServiceAccountApprole.getAzureSvcAccName()))
								.put(LogMessage.STATUS, metadataResponse.getHttpstatus().toString())
								.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
								.build()));
						return ResponseEntity.status(HttpStatus.OK).body(
								"{\"messages\":[\"Approle is successfully removed(if existed) from Azure Service Account\"]}");
					}
					approleControllerResp = appRoleService.configureApprole(approleName, currentpoliciesString, token);
					if (approleControllerResp.getHttpstatus().equals(HttpStatus.NO_CONTENT)) {
						log.error(
								JSONUtil.getJSON(ImmutableMap.<String, String> builder()
										.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
										.put(LogMessage.ACTION,
												AzureServiceAccountConstants.REMOVE_APPROLE_TO_AZURESVCACC_MSG)
										.put(LogMessage.MESSAGE, "Reverting, approle policy update success")
										.put(LogMessage.RESPONSE,
												(null != metadataResponse) ? metadataResponse.getResponse()
														: TVaultConstants.EMPTY)
										.put(LogMessage.STATUS,
												(null != metadataResponse) ? metadataResponse.getHttpstatus().toString()
														: TVaultConstants.EMPTY)
										.put(LogMessage.APIURL,
												ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
										.build()));
						return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
								.body("{\"errors\":[\"Approle configuration failed. Please try again\"]}");
					} else {
						log.error(
								JSONUtil.getJSON(ImmutableMap.<String, String> builder()
										.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
										.put(LogMessage.ACTION,
												AzureServiceAccountConstants.REMOVE_APPROLE_TO_AZURESVCACC_MSG)
										.put(LogMessage.MESSAGE, "Reverting approle policy update failed")
										.put(LogMessage.RESPONSE,
												(null != metadataResponse) ? metadataResponse.getResponse()
														: TVaultConstants.EMPTY)
										.put(LogMessage.STATUS,
												(null != metadataResponse) ? metadataResponse.getHttpstatus().toString()
														: TVaultConstants.EMPTY)
										.put(LogMessage.APIURL,
												ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
										.build()));
						return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
								.body("{\"errors\":[\"Approle configuration failed. Contact Admin \"]}");
					}
				} else {
					return ResponseEntity.status(HttpStatus.BAD_REQUEST)
							.body("{\"errors\":[\"Failed to remove approle from the Service Account\"]}");
				}
			} else {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST)
						.body("{\"errors\":[\"Access denied: No permission to remove approle from Service Account\"]}");
			}
		}

	/**
	 * ransfers an Azure service principal from one owner to another.
	 * @param token
	 * @param userDetails
	 * @param aspTransferRequest
	 * @return
	 */
	public ResponseEntity<String> transferAzureServicePrincipal(String token, UserDetails userDetails, ASPTransferRequest aspTransferRequest) throws JsonProcessingException {
		List<String> onboardedList = getOnboardedAzureServiceAccountList(token);
		String servicePrincipalName = aspTransferRequest.getServicePrincipalName();
		if (!onboardedList.contains(servicePrincipalName)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Failed to transfer Azure Service Principal. Could not find Azure Service Principal [%s]", servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Unable to transfer Azure Service Principal. "+ servicePrincipalName + " not found. \"]}");
		}
		if (!isAuthorizedForAzureOnboardAndOffboard(token)) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Access denied: No permission to transfer this Azure Service Principal [%s]", servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Access denied: No permission to transfer this Azure Service Principal\"]}");
		}

		String azureAccPath = AzureServiceAccountConstants.AZURE_SVCC_ACC_PATH + servicePrincipalName;
		Response metaResponse = getMetadata(token, userDetails, azureAccPath);
		AzureServiceAccountMetadataDetails currentAzureServiceAccountMetadata = constructAzureServiceAccountFromMetadata(metaResponse);
		if (!HttpStatus.OK.equals(metaResponse.getHttpstatus()) || currentAzureServiceAccountMetadata == null) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Failed to read metadata for this Azure Service Principal [%s]", servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Failed to read metadata for this Azure Service Principal\"]}");
		}
		AzureServiceAccount currentAzureServiceAccount = constructAzureServiceAccount(currentAzureServiceAccountMetadata);
		AzureServiceAccount newAzureServiceAccount = (AzureServiceAccount) SerializationUtils.clone(currentAzureServiceAccount);

		if (aspTransferRequest.getOwnerNtid().equalsIgnoreCase(currentAzureServiceAccount.getOwnerNtid())) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Failed to transfer the owner. " +
							"The owner given is already the current owner on account [%s]", servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
					"{\"errors\":[\"Failed to transfer Azure Service Principal owner. The owner given is already the current owner.\"]}");
		}

		newAzureServiceAccount.setOwnerEmail(aspTransferRequest.getOwnerEmail());
		newAzureServiceAccount.setOwnerNtid(aspTransferRequest.getOwnerNtid());

		if (!StringUtils.isEmpty(aspTransferRequest.getApplicationId())) {
			newAzureServiceAccount.setApplicationId(aspTransferRequest.getApplicationId());
		}
		if (!StringUtils.isEmpty(aspTransferRequest.getApplicationName())) {
			newAzureServiceAccount.setApplicationName(aspTransferRequest.getApplicationName());
		}
		if (!StringUtils.isEmpty(aspTransferRequest.getApplicationTag())) {
			newAzureServiceAccount.setApplicationTag(aspTransferRequest.getApplicationTag());
		}

		boolean removedUsersSuccess = removeRedundantUserPermissionsAfterTransfer(userDetails, currentAzureServiceAccount,
				newAzureServiceAccount, servicePrincipalName, metaResponse);

		if (removedUsersSuccess) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Successfully removed user permissions from Azure Service Principal [%s] on transfer",
							servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Removing user permissions for Azure Service Principal [%s] on transfer failed.", servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.MULTI_STATUS)
					.body("{\"errors\":[\"Failed to remove user permissions for Azure Service Principal.\"]}");
		}

		boolean addSudoPermissionToOwnerResponse = addSudoPermissionToOwner(token, newAzureServiceAccount,
				userDetails, servicePrincipalName);
		if (addSudoPermissionToOwnerResponse) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Successfully added sudo permission for new owner [%s] on " +
									"account [%s]",
							currentAzureServiceAccount.getOwnerNtid(), servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));

			//Add rotate permisson to the Azure service account owner
			AzureServiceAccountUser azureServiceAccountUser = new AzureServiceAccountUser(newAzureServiceAccount.getServicePrincipalName(),
					newAzureServiceAccount.getOwnerNtid(), AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING);
			ResponseEntity<String> addUserToAzureSvcAccResponse = addUserToAzureServiceAccount(token, userDetails,
					azureServiceAccountUser, true);
			if (addUserToAzureSvcAccResponse.getStatusCode().equals(HttpStatus.OK)) {
				log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
						.put(LogMessage.MESSAGE, String.format("Successfully added write permission for new owner [%s] on account [%s]",
								currentAzureServiceAccount.getOwnerNtid(), servicePrincipalName))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			} else {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
						.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
						.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
						.put(LogMessage.MESSAGE, String.format("Failed to add write permission to owner [%s] on account [%s]",
										currentAzureServiceAccount.getOwnerNtid(), servicePrincipalName))
						.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
				revertTransferOnFailure(newAzureServiceAccount, servicePrincipalName, userDetails, tokenUtils.getSelfServiceToken());
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Transfer Azure Service " +
						"Principal failed. Failed to associate write permission with owner.\"]}");
			}
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE,
							String.format("Failed to add sudo permission to owner [%s] on account [%s]",
									currentAzureServiceAccount.getOwnerNtid(), servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Transfer Azure Service " +
					"Principal failed. New owner association failed.\"]}");
		}

		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();

		AzureServiceAccountUser oldOwner = new AzureServiceAccountUser(servicePrincipalName,
				currentAzureServiceAccountMetadata.getOwnerNtid(), TVaultConstants.SUDO_POLICY);
		ResponseEntity<String> removeOldOwnerSudoPermissionResponse =
				processAndRemoveUserPermissionFromAzureSvcAcc(tokenUtils.getSelfServiceToken(), oldOwner, userDetails,
				oidcEntityResponse, servicePrincipalName);

		oldOwner = new AzureServiceAccountUser(servicePrincipalName,
				currentAzureServiceAccountMetadata.getOwnerNtid(), TVaultConstants.WRITE_POLICY);
		ResponseEntity<String> removeOldOwnerWritePermissionResponse =
				processAndRemoveUserPermissionFromAzureSvcAcc(tokenUtils.getSelfServiceToken(), oldOwner, userDetails,
				oidcEntityResponse, servicePrincipalName);

		if (HttpStatus.OK.equals(removeOldOwnerSudoPermissionResponse.getStatusCode()) &&
				HttpStatus.OK.equals(removeOldOwnerWritePermissionResponse.getStatusCode())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Successfully removed old owner [%s] from " +
									"Azure Service Principal [%s]",
							currentAzureServiceAccount.getOwnerNtid(), servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE,
							String.format("Failed to remove old owner [%s] from Azure Service Principal [%s]",
									currentAzureServiceAccount.getOwnerNtid(), servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			revertTransferOnFailure(newAzureServiceAccount, servicePrincipalName, userDetails, tokenUtils.getSelfServiceToken());
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"errors\":[\"Transfer Azure Service " +
					"Principal failed. Failed to remove current owner permission.\"]}");
		}

		// Update Metadata
		Response metadataUpdateResponse = ControllerUtil.updateMetadataOnASPUpdate(azureAccPath, newAzureServiceAccount, token);
		if (metadataUpdateResponse !=null && HttpStatus.NO_CONTENT.equals(metadataUpdateResponse.getHttpstatus())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE,
							String.format("Successfully updated Metadata for the Azure Service Principal [%s] on transfer",
									servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Updating metadata for Azure Service Principal on transfer [%s] failed.", servicePrincipalName))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.MULTI_STATUS)
					.body("{\"errors\":[\"Metadata updating failed for Azure Service Account.\"]}");
		}

		DirectoryUser oldOwnerObj = getUserDetails(currentAzureServiceAccount.getOwnerNtid());
		Map<String, String> mailTemplateVariables = new HashMap<>();
		mailTemplateVariables.put("azureSvcAccName", servicePrincipalName);
		String oldOwnerName = "";
		if (oldOwnerObj != null) {
			oldOwnerName = StringUtils.isEmpty(oldOwnerObj.getDisplayName().trim()) ? oldOwnerObj.getUserName() :
					oldOwnerObj.getDisplayName();
		}
		mailTemplateVariables.put("oldOwnerName", oldOwnerName);
		mailTemplateVariables.put("contactLink", supportEmail);
		List<String> cc = new ArrayList<>();
		cc.add(currentAzureServiceAccount.getOwnerEmail());

		sendMailToAzureSvcAccOwner(newAzureServiceAccount, servicePrincipalName, AzureServiceAccountConstants.ASP_TRANSFER_EMAIL_SUBJECT,
				AzureServiceAccountConstants.AZURE_TRANSFER_EMAIL_TEMPLATE_NAME, mailTemplateVariables, cc);

		return ResponseEntity.status(HttpStatus.OK)
				.body("{\"messages\":[\"Owner has been successfully transferred for Azure Service Principal\"]}");
	}

	@SuppressWarnings("unchecked")
	private boolean removeRedundantUserPermissionsAfterTransfer(UserDetails userDetails, AzureServiceAccount currentAzureSvcAcc,
											   AzureServiceAccount newAzureSvcAcc, String servicePrincipalName, Response metaResponse) {
		boolean isSuccess = true;
		Map<String, Object> responseMap;
		try {
			responseMap = new ObjectMapper().readValue(metaResponse.getResponse(), new TypeReference<Map<String, Object>>() {});
		} catch (IOException e) {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String> builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.AZURE_SVCACC_OFFBOARD_CREATION_TITLE)
					.put(LogMessage.MESSAGE, String.format("Error Fetching metadata for azure service account " +
							" [%s]", servicePrincipalName))
					.put(LogMessage.APIURL,	ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL))
					.build()));
			return false;
		}
		Map<String, Object> userMap = null;
		if (responseMap != null && responseMap.get("data") != null) {
			Map<String, Object> metadataMap = (Map<String, Object>) responseMap.get("data");
			userMap = (Map<String, Object>) metadataMap.get(USERS);
		}

		if (userMap != null && !userMap.isEmpty()) {
			for (Map.Entry<String, Object> entry : userMap.entrySet()) {
				if (entry.getKey().equals(newAzureSvcAcc.getOwnerNtid()) && !entry.getValue().equals(TVaultConstants.WRITE_POLICY)) {
					String access = (entry.getValue().toString().equals(TVaultConstants.WRITE_POLICY)) ?
							AzureServiceAccountConstants.AZURE_ROTATE_MSG_STRING : entry.getValue().toString();
					AzureServiceAccountUser azureServiceAccountUser = new AzureServiceAccountUser(currentAzureSvcAcc.getServicePrincipalName(),
							entry.getKey(), access);
					OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
					ResponseEntity<String> removeResponse = processAndRemoveUserPermissionFromAzureSvcAcc(tokenUtils.getSelfServiceToken(),
							azureServiceAccountUser, userDetails, oidcEntityResponse, servicePrincipalName);
					if (!removeResponse.getStatusCode().equals(HttpStatus.OK)) {
						isSuccess = false;
						break;
					}
				}
			}
		}
		return isSuccess;
	}

	/**
	 * Revert new owner association on ASP transfer failure.
	 * @param azureServiceAccount
	 * @param servicePrincipalName
	 * @param userDetails
	 * @param token
	 * @return
	 */
	private ResponseEntity<String> revertTransferOnFailure(AzureServiceAccount azureServiceAccount, String servicePrincipalName,
														   UserDetails userDetails, String token) {

		OIDCEntityResponse oidcEntityResponse = new OIDCEntityResponse();
		AzureServiceAccountUser oldOwner = new AzureServiceAccountUser(servicePrincipalName,
				azureServiceAccount.getOwnerNtid(), TVaultConstants.SUDO_POLICY);
		ResponseEntity<String> removeOldOwnerSudoPermissionResponse =
				processAndRemoveUserPermissionFromAzureSvcAcc(token, oldOwner, userDetails,
						oidcEntityResponse, servicePrincipalName);

		oldOwner = new AzureServiceAccountUser(servicePrincipalName,
				azureServiceAccount.getOwnerNtid(), TVaultConstants.WRITE_POLICY);
		ResponseEntity<String> removeOldOwnerWritePermissionResponse =
				processAndRemoveUserPermissionFromAzureSvcAcc(token, oldOwner, userDetails,
						oidcEntityResponse, servicePrincipalName);

		if (HttpStatus.OK.equals(removeOldOwnerSudoPermissionResponse.getStatusCode()) && HttpStatus.OK.equals(removeOldOwnerWritePermissionResponse.getStatusCode())) {
			log.debug(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Reverted permission from new owner [%s] back to the old owner.",
							azureServiceAccount.getOwnerNtid()))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
		} else {
			log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder()
					.put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER))
					.put(LogMessage.ACTION, AzureServiceAccountConstants.TRANSFER_ASP_METHOD_NAME)
					.put(LogMessage.MESSAGE, String.format("Failed to revert permission from new owner [%s] back to the old owner.",
							azureServiceAccount.getOwnerNtid()))
					.put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).build()));
			return ResponseEntity.status(HttpStatus.MULTI_STATUS).body(
					"{\"errors\":[\"Failed to revert permissions from the new owner back to the old owner on Azure Service Principal transfer failure.\"]}");
		}
		return ResponseEntity.status(HttpStatus.OK).body(
				"{\"errors\":[\"Successfully reverted transfer of Azure Service Principal.\"]}");
	}

	private AzureServiceAccount constructAzureServiceAccount(AzureServiceAccountMetadataDetails currentAzureServiceAccountMetadata) {
		AzureServiceAccount azureServiceAccount = new AzureServiceAccount();
		azureServiceAccount.setServicePrincipalName(currentAzureServiceAccountMetadata.getServicePrincipalName());
		azureServiceAccount.setServicePrincipalId(currentAzureServiceAccountMetadata.getServicePrincipalId());
		azureServiceAccount.setServicePrincipalClientId(currentAzureServiceAccountMetadata.getServicePrincipalClientId());
		azureServiceAccount.setApplicationId(currentAzureServiceAccountMetadata.getApplicationId());
		azureServiceAccount.setApplicationName(currentAzureServiceAccountMetadata.getApplicationName());
		azureServiceAccount.setApplicationTag(currentAzureServiceAccountMetadata.getApplicationTag());
		azureServiceAccount.setCreatedAtEpoch(currentAzureServiceAccountMetadata.getCreatedAtEpoch());
		azureServiceAccount.setOwnerEmail(currentAzureServiceAccountMetadata.getOwnerEmail());
		azureServiceAccount.setOwnerNtid(currentAzureServiceAccountMetadata.getOwnerNtid());
		azureServiceAccount.setTenantId(currentAzureServiceAccountMetadata.getTenantId());
		return azureServiceAccount;
	}

	/**
	 * To construct Azure Service Principal metadata object.
	 * @param metaResponse
	 * @return
	 */
	private AzureServiceAccountMetadataDetails constructAzureServiceAccountFromMetadata(Response metaResponse) {
		AzureServiceAccountMetadataDetails azureServiceAccount = new AzureServiceAccountMetadataDetails();

		if (metaResponse !=null && HttpStatus.OK.equals(metaResponse.getHttpstatus())) {
			try {
				JsonNode jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("servicePrincipalName");
				if (jsonNode != null) {
					azureServiceAccount.setServicePrincipalName(jsonNode.asText());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("createdAtEpoch");
				if (jsonNode != null) {
					azureServiceAccount.setCreatedAtEpoch(jsonNode.asLong());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("owner_ntid");
				if (jsonNode != null) {
					azureServiceAccount.setOwnerNtid(jsonNode.asText());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("owner_email");
				if (jsonNode != null) {
					azureServiceAccount.setOwnerEmail(jsonNode.asText());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("application_id");
				if (jsonNode != null) {
					azureServiceAccount.setApplicationId(jsonNode.asText());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("application_name");
				if (jsonNode != null) {
					azureServiceAccount.setApplicationName(jsonNode.asText());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("application_tag");
				if (jsonNode != null) {
					azureServiceAccount.setApplicationTag(jsonNode.asText());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("isActivated");
				if (jsonNode != null) {
					azureServiceAccount.setAccountActivated(jsonNode.asBoolean());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("servicePrincipalClientId");
				if (jsonNode != null) {
					azureServiceAccount.setServicePrincipalClientId(jsonNode.asText());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("servicePrincipalId");
				if (jsonNode != null) {
					azureServiceAccount.setServicePrincipalId(jsonNode.asText());
				}
				jsonNode = new ObjectMapper().readTree(metaResponse.getResponse()).get("data").get("tenantId");
				if (jsonNode != null) {
					azureServiceAccount.setTenantId(jsonNode.asText());
				}
				JsonParser jsonParser = new JsonParser();
				JsonArray dataSecret = ((JsonObject) jsonParser.parse(new ObjectMapper().readTree(metaResponse.getResponse()).get("data").toString()))
						.getAsJsonArray("secret");

				List<AzureSecretsMetadata> secrets = new ArrayList<>();
				for (int i = 0; i < dataSecret.size(); i++) {
					AzureSecretsMetadata secret = new AzureSecretsMetadata();
					JsonElement jsonElement = dataSecret.get(i);
					JsonObject jsonObject = jsonElement.getAsJsonObject();
					if (jsonObject.get("expiryDateEpoch") != null) {
						secret.setExpiryDuration(jsonObject.get("expiryDuration").getAsLong());
					}
					if (jsonObject.get("accessKeyId") != null) {
						secret.setSecretKeyId(jsonObject.get("accessKeyId").getAsString());
					}
					secrets.add(secret);
				}
				azureServiceAccount.setSecret(secrets);
			} catch (IOException e) {
				log.error(JSONUtil.getJSON(ImmutableMap.<String, String>builder().
						put(LogMessage.USER, ThreadLocalContext.getCurrentMap().get(LogMessage.USER)).
						put(LogMessage.ACTION, "constructAzureServiceAccountFromMetadata").
						put(LogMessage.MESSAGE, String.format("Failed to parse Azure Service Principal metadata for [%s]", azureServiceAccount.getServicePrincipalName())).
						put(LogMessage.APIURL, ThreadLocalContext.getCurrentMap().get(LogMessage.APIURL)).
						build()));
				return null;
			}
		}
		return azureServiceAccount;
	}
}
