package com.tmobile.cso.vault.api.v2.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tmobile.cso.vault.api.common.SSLCertificateConstants;
import com.tmobile.cso.vault.api.common.TVaultConstants;
import com.tmobile.cso.vault.api.model.*;
import com.tmobile.cso.vault.api.process.RequestProcessor;
import com.tmobile.cso.vault.api.process.Response;
import com.tmobile.cso.vault.api.service.SSLCertificateAWSRoleService;
import com.tmobile.cso.vault.api.service.SSLCertificateService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
public class SSLCertificateControllerTest {
    @Mock
    public SSLCertificateService sslCertificateService;

    @Mock
    public SSLCertificateAWSRoleService sslCertificateAWSRoleService;

    private MockMvc mockMvc;

    @Mock
    RequestProcessor reqProcessor;

    @InjectMocks
    public SSLCertificateController SslCertificateController;

    @Mock
    private SSLCertificateRequest sSLCertificateRequest;

	@Mock
	private SSLCertificateOnboardRequest sslCertOnboardRequest;
    
    @Mock
    private SSLCertificateMetadataDetails sSLCertificateMetadataRequest;
    
    @Mock
    private RevocationRequest revocationRequest;
    @Mock
    UserDetails userDetails;

    @Mock
    HttpServletRequest httpServletRequest;
    String token;
    
    @Mock
    private CertificateUpdateRequest certificateUpdateRequest;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        this.mockMvc = MockMvcBuilders.standaloneSetup(SslCertificateController).build();
        token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        userDetails.setUsername("normaluser");
        userDetails.setAdmin(true);
        userDetails.setClientToken(token);
        userDetails.setSelfSupportToken(token);
    }

    @Test
    public void test_authenticate_successful() throws Exception {
        CertManagerLoginRequest certManagerLoginRequest = new CertManagerLoginRequest("testusername", "testpassword");
        when(sslCertificateService.authenticate(certManagerLoginRequest)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        assertEquals(HttpStatus.OK, SslCertificateController.authenticate(certManagerLoginRequest).getStatusCode());
    }

    @Test
    public void test_authenticate_Unauthorized() throws Exception {
        CertManagerLoginRequest certManagerLoginRequest = new CertManagerLoginRequest("testusername1", "testpassword1");
        when(sslCertificateService.authenticate(certManagerLoginRequest)).thenReturn(new ResponseEntity<>(HttpStatus.UNAUTHORIZED));
        assertEquals(HttpStatus.UNAUTHORIZED, SslCertificateController.authenticate(certManagerLoginRequest).getStatusCode());
    }

    @Test
    public void test_generateSSLCertificate_success() {
        TargetSystem targetSystem = new TargetSystem();
        targetSystem.setAddress("Target System address");
        targetSystem.setDescription("Target System Description");
        targetSystem.setName("Target Name");

        TargetSystemServiceRequest targetSystemServiceRequest = new TargetSystemServiceRequest();
        targetSystemServiceRequest.setHostname("Target System Service Host name");
        targetSystemServiceRequest.setName("Target System Service Name");
        targetSystemServiceRequest.setPort(443);
        targetSystemServiceRequest.setMultiIpMonitoringEnabled(false);
        targetSystemServiceRequest.setMonitoringEnabled(false);
        targetSystemServiceRequest.setDescription("Target Service Description");

        sSLCertificateRequest.setCertificateName("CertificateName");
        sSLCertificateRequest.setTargetSystem(targetSystem);
        sSLCertificateRequest.setTargetSystemServiceRequest(targetSystemServiceRequest);


       when(sslCertificateService.generateSSLCertificate(sSLCertificateRequest,userDetails,token,SSLCertificateConstants.UI)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
       assertEquals(HttpStatus.OK, sslCertificateService.generateSSLCertificate(sSLCertificateRequest,userDetails,token,SSLCertificateConstants.UI).getStatusCode());
    }

    @Test
    public void test_generateSSLCertificate_success_Test() {
        TargetSystem targetSystem = new TargetSystem();
        targetSystem.setAddress("Target System address");
        targetSystem.setDescription("Target System Description");
        targetSystem.setName("Target Name");

        TargetSystemServiceRequest targetSystemServiceRequest = new TargetSystemServiceRequest();
        targetSystemServiceRequest.setHostname("Target System Service Host name");
        targetSystemServiceRequest.setName("Target System Service Name");
        targetSystemServiceRequest.setPort(443);
        targetSystemServiceRequest.setMultiIpMonitoringEnabled(false);
        targetSystemServiceRequest.setMonitoringEnabled(false);
        targetSystemServiceRequest.setDescription("Target Service Description");

        sSLCertificateRequest.setCertificateName("CertificateName");
        sSLCertificateRequest.setTargetSystem(targetSystem);
        sSLCertificateRequest.setTargetSystemServiceRequest(targetSystemServiceRequest);


        when(sslCertificateService.generateSSLCertificate(sSLCertificateRequest, userDetails, token,SSLCertificateConstants.UI)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        when(httpServletRequest.getAttribute("UserDetails")).thenReturn(userDetails);
        assertEquals(HttpStatus.OK, SslCertificateController.generateSSLCertificate(httpServletRequest, token, sSLCertificateRequest).getStatusCode());
    }

    @Test
    public void test_generateSSLCertificate_Error() {
        TargetSystem targetSystem = new TargetSystem();
        targetSystem.setAddress("Target System address");
        targetSystem.setDescription("Target System Description");
        targetSystem.setName("Target Name");

        TargetSystemServiceRequest targetSystemServiceRequest = new TargetSystemServiceRequest();
        targetSystemServiceRequest.setHostname("Target System Service Host name");
        targetSystemServiceRequest.setName("Target System Service Name");
        targetSystemServiceRequest.setPort(443);
        targetSystemServiceRequest.setMultiIpMonitoringEnabled(false);
        targetSystemServiceRequest.setMonitoringEnabled(false);
        targetSystemServiceRequest.setDescription("Target Service Description");

        sSLCertificateRequest.setCertificateName("CertificateName");
        sSLCertificateRequest.setTargetSystem(targetSystem);
        sSLCertificateRequest.setTargetSystemServiceRequest(targetSystemServiceRequest);

        when(sslCertificateService.generateSSLCertificate(sSLCertificateRequest,userDetails,token,SSLCertificateConstants.UI)).thenReturn(new ResponseEntity<>
             (HttpStatus.INTERNAL_SERVER_ERROR));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR,
                sslCertificateService.generateSSLCertificate(sSLCertificateRequest,userDetails,token,SSLCertificateConstants.UI).getStatusCode());

    }
    
    @Test
    public void test_getCertificates() throws Exception {
        // Mock response        
        when(sslCertificateService.getAllSSLCertificatesToManage("5PDrOhsy4ig8L3EpsJZSLAMg", userDetails, "",1,0,"internal")).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        assertEquals(HttpStatus.OK, sslCertificateService.getAllSSLCertificatesToManage("5PDrOhsy4ig8L3EpsJZSLAMg",userDetails,"",1,0,"internal").getStatusCode());
    }
    
    @Test
    public void test_getCertificates_external() throws Exception {
        // Mock response        
        when(sslCertificateService.getAllSSLCertificatesToManage("5PDrOhsy4ig8L3EpsJZSLAMg", userDetails, "",1,0,"external")).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        assertEquals(HttpStatus.OK, sslCertificateService.getAllSSLCertificatesToManage("5PDrOhsy4ig8L3EpsJZSLAMg",userDetails,"",1,0,"external").getStatusCode());
    }
	
	@Test
	public void test_issueRevocationRequest_Success() {
		String certName = "test@t-mobile.com";
		String certficateType = "internal";
		revocationRequest.setReason("unspecified");
		when(sslCertificateService.issueRevocationRequest(certficateType, certName, userDetails, token, revocationRequest))
				.thenReturn(new ResponseEntity<>(HttpStatus.OK));
		when(httpServletRequest.getAttribute("UserDetails")).thenReturn(userDetails);
		assertEquals(HttpStatus.OK,
				SslCertificateController.issueRevocationRequest(httpServletRequest, token, certficateType,certName, revocationRequest).getStatusCode());

	}
       
	@Test
    public void testAddUsertoCertificate() throws Exception {
        String responseJson = "{\"messages\":[\"User is successfully associated \"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);       
        CertificateUser certUser = new CertificateUser("testuser1","read", "certificatename.t-mobile.com", "internal");

        String inputJson =new ObjectMapper().writeValueAsString(certUser);
        when(sslCertificateService.addUserToCertificate(Mockito.any(CertificateUser.class), Mockito.eq(userDetails), Mockito.anyBoolean())).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.post("/v2/sslcert/user").requestAttr("UserDetails", userDetails)
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseJson)));
    }

    @Test
    public void testAssociateApproletoCertificate() throws Exception {
    	CertificateApprole certificateApprole = new CertificateApprole("certificatename.t-mobile.com", "role1", "read", "internal");

        String inputJson =new ObjectMapper().writeValueAsString(certificateApprole);
        String responseJson = "{\"messages\":[\"Approle successfully associated with Certificate\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);

        when(sslCertificateService.associateApproletoCertificate(Mockito.any(CertificateApprole.class), Mockito.eq(userDetails))).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.post("/v2/sslcert/approle").requestAttr("UserDetails", userDetails)
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseJson)));
    }
    
    @Test
    public void testDeleteApproletoCertificate() throws Exception {
    	CertificateApprole certificateApprole = new CertificateApprole("certificatename.t-mobile.com", "role1", "read", "internal");

        String inputJson =new ObjectMapper().writeValueAsString(certificateApprole);
        String responseJson = "{\"messages\":[\"Approle successfully deleted from Certificate\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);

        when(sslCertificateService.deleteApproleFromCertificate(Mockito.any(CertificateApprole.class), Mockito.eq(userDetails))).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.delete("/v2/sslcert/approle").requestAttr("UserDetails", userDetails)
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseJson)));
    }
    UserDetails getMockUser(boolean isAdmin) {
        String token = "5PDrOhsy4ig8L3EpsJZSLAMg";
        UserDetails userDetails = new UserDetails();
        userDetails.setUsername("normaluser");
        userDetails.setAdmin(isAdmin);
        userDetails.setClientToken(token);
        userDetails.setSelfSupportToken(token);
        return userDetails;
    }

    @Test
    public void test_downloadCertificateWithPrivateKey() throws Exception {
        CertificateDownloadRequest certificateDownloadRequest = new CertificateDownloadRequest(
                "abc.com", "password", "pembundle", false,"internal");

        String inputJson =new ObjectMapper().writeValueAsString(certificateDownloadRequest);
        InputStreamResource resource = null;
        ResponseEntity<InputStreamResource> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(resource);

        UserDetails userDetails = getMockUser(true);
        when(sslCertificateService.downloadCertificateWithPrivateKey(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any(), Mockito.eq(userDetails))).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.post("/v2/sslcert/certificates/download").requestAttr("UserDetails", userDetails)
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk());
    }

    @Test
    public void test_downloadCertificate() throws Exception {

        InputStreamResource resource = null;
        ResponseEntity<InputStreamResource> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(resource);

        when(sslCertificateService.downloadCertificate(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any(), Mockito.eq("12345"),
                Mockito.eq("pem"),Mockito.eq("external"))).thenReturn(responseEntityExpected);

        mockMvc.perform(MockMvcRequestBuilders.get("/v2/sslcert/certificates/12345/pem/external")
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk());
    }
    
    @Test
    public void testRemoveUserFromCertificate() throws Exception {
        CertificateUser certUser = new CertificateUser("testuser1","read", "certificatename.t-mobile.com", "internal");   	
        String expected = "{\"message\":[\"Successfully removed user from the certificate\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expected);
        when(sslCertificateService.removeUserFromCertificate(Mockito.any(), Mockito.any())).thenReturn(responseEntityExpected);
        String inputJson = getJSON(certUser);
        MvcResult result = mockMvc.perform(MockMvcRequestBuilders.delete("/v2/sslcert/user")
                .header("vault-token", token)
                .header("Content-Type", "application/json;charset=UTF-8")
                .requestAttr("UserDetails", userDetails)
                .content(inputJson))
        		.andExpect(status().isOk()).andReturn();

        String actual = result.getResponse().getContentAsString();
        assertEquals(expected, actual);
    }
    
    @Test
    public void testRemoveGroupFromCertificate() throws Exception {
    	CertificateGroup certGroup = new CertificateGroup("certificatename.t-mobile.com", "testgroup","read", "internal");   	
        String expected = "{\"message\":[\"Group is successfully removed from certificate\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expected);
        when(sslCertificateService.removeGroupFromCertificate(Mockito.any(), Mockito.any())).thenReturn(responseEntityExpected);
        String inputJson = getJSON(certGroup);
        MvcResult result = mockMvc.perform(MockMvcRequestBuilders.delete("/v2/sslcert/group")
                .header("vault-token", token)
                .header("Content-Type", "application/json;charset=UTF-8")
                .requestAttr("UserDetails", userDetails)
                .content(inputJson))
        		.andExpect(status().isOk()).andReturn();

        String actual = result.getResponse().getContentAsString();
        assertEquals(expected, actual);
    }
    
    private String getJSON(Object obj)  {
		ObjectMapper mapper = new ObjectMapper();
		try {
			return mapper.writeValueAsString(obj);
		} catch (JsonProcessingException e) {
			return TVaultConstants.EMPTY_JSON;
		}
	}


	@Test
    public void testAddGrouptoCertificate() throws Exception {
		String responseJson = "{\"messages\":[\"Group is successfully associated with Certificate\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
		CertificateGroup certGroup = new CertificateGroup("certificatename.t-mobile.com","testgroup","read", "internal");
		String inputJson =new ObjectMapper().writeValueAsString(certGroup);
		when(sslCertificateService.addingGroupToCertificate(Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any(CertificateGroup.class), Mockito.any(UserDetails.class))).thenReturn(responseEntityExpected);
		 mockMvc.perform(MockMvcRequestBuilders.post("/v2/ss/certificate/group").requestAttr("UserDetails", userDetails)
	                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
	                .header("Content-Type", "application/json;charset=UTF-8")
	                .content(inputJson));
	}
	
	@Test
    public void test_getListOfCertificates() throws Exception {
        // Mock response        
        when(sslCertificateService.getListOfCertificates("5PDrOhsy4ig8L3EpsJZSLAMg","internal",1,0)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        assertEquals(HttpStatus.OK, sslCertificateService.getListOfCertificates("5PDrOhsy4ig8L3EpsJZSLAMg","internal",1,0).getStatusCode());
    }
	
	@Test
    public void updateCertOwner() throws Exception {
        // Mock response     
		TargetSystem targetSystem = new TargetSystem();
        targetSystem.setAddress("Target System address");
        targetSystem.setDescription("Target System Description");
        targetSystem.setName("Target Name");

        TargetSystemServiceRequest targetSystemServiceRequest = new TargetSystemServiceRequest();
        targetSystemServiceRequest.setHostname("Target System Service Host name");
        targetSystemServiceRequest.setName("Target System Service Name");
        targetSystemServiceRequest.setPort(443);
        targetSystemServiceRequest.setMultiIpMonitoringEnabled(false);
        targetSystemServiceRequest.setMonitoringEnabled(false);
        targetSystemServiceRequest.setDescription("Target Service Description");

        sSLCertificateMetadataRequest.setCertificateName("CertificateName");
        when(sslCertificateService.updateCertOwner("internal","certificatename.t-mobile.com","owneremail@test.com",userDetails)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        assertEquals(HttpStatus.OK, sslCertificateService.updateCertOwner("internal","certificatename.t-mobile.com","owneremail@test.com",userDetails).getStatusCode());
    }

	@Test
	public void testValidateApprovalStatusAndGetCertificateDetails() throws Exception {
		String expected = "{\"message\":[\"Certificate approved and metadata successfully updated\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(expected);
		when(sslCertificateService.validateApprovalStatusAndGetCertificateDetails(Mockito.anyString(),
				Mockito.anyString(), Mockito.anyObject())).thenReturn(responseEntityExpected);
		MvcResult result = mockMvc
				.perform(MockMvcRequestBuilders.get("/v2/sslcert/validate/certificatename.t-mobile.com/external")
						.header("vault-token", token).header("Content-Type", "application/json;charset=UTF-8")
						.requestAttr("UserDetails", userDetails).content(expected))
				.andExpect(status().isOk()).andReturn();

		String actual = result.getResponse().getContentAsString();
		assertEquals(expected, actual);
	}
	
	@Test
	public void testdeleteCertificate_Success() {
		String certName = "test@t-mobile.com";		
		String certficateType = "internal";
		when(sslCertificateService.deleteCertificate(token,certficateType, certName, userDetails ))
				.thenReturn(new ResponseEntity<>(HttpStatus.OK));
		when(httpServletRequest.getAttribute("UserDetails")).thenReturn(userDetails);
		assertEquals(HttpStatus.OK,
				sslCertificateService.deleteCertificate(token,certficateType, certName, userDetails).getStatusCode());

	}

	@Test
	public void test_getAllCertificatesOnCertType_success() throws Exception {
		// Mock response
		when(sslCertificateService.getAllCertificatesOnCertType(userDetails, "internal", 1, 0))
				.thenReturn(new ResponseEntity<>(HttpStatus.OK));
		assertEquals(HttpStatus.OK,
				sslCertificateService.getAllCertificatesOnCertType(userDetails, "internal", 1, 0).getStatusCode());
	}

	
	@Test
	public void test_getAllSelfServiceGroups_success() {
		// Mock response
		when(sslCertificateService.getAllSelfServiceGroups(userDetails))
				.thenReturn(new ResponseEntity<>(HttpStatus.OK));
		assertEquals(HttpStatus.OK,
				sslCertificateService.getAllSelfServiceGroups(userDetails).getStatusCode());
	}
	
	 @Test
	    public void test_onboardCertificates() throws Exception {
	        // Mock response        
	        when(sslCertificateService.onboardCerts(userDetails,"5PDrOhsy4ig8L3EpsJZSLAMg",0,1)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
	        assertEquals(HttpStatus.OK, sslCertificateService.onboardCerts(userDetails,"5PDrOhsy4ig8L3EpsJZSLAMg",0,1).getStatusCode());
	    }
	 
	 @Test
	    public void test_onboardSingleCertificates() throws Exception {
	        // Mock response        
	        when(sslCertificateService.onboardSingleCert(userDetails,"5PDrOhsy4ig8L3EpsJZSLAMg","internal","testcert","tvt")).thenReturn(new ResponseEntity<>(HttpStatus.OK));
	        assertEquals(HttpStatus.OK, sslCertificateService.onboardSingleCert(userDetails,"5PDrOhsy4ig8L3EpsJZSLAMg","internal","testcert","tvt").getStatusCode());
	    }

	@Test
	public void testCreateAWSRoleForSSL() throws Exception {
		CertificateAWSRole certificateAWSRole = new CertificateAWSRole("certificatename.t-mobile.com", "role1", "read", "internal");

		String inputJson = new ObjectMapper().writeValueAsString(certificateAWSRole);
		String responseJson = "{\"messages\":[\"AWS Role created \"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);		
		when(sslCertificateAWSRoleService.createAWSRoleForSSL(Mockito.eq(userDetails), Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"),
				Mockito.any(AWSLoginRole.class))).thenReturn(responseEntityExpected);

		mockMvc.perform(MockMvcRequestBuilders.post("/v2/sslcert/aws/role")
				.requestAttr("UserDetails", userDetails).header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
				.header("Content-Type", "application/json;charset=UTF-8").content(inputJson))
				.andExpect(status().isOk()).andExpect(content().string(containsString(responseJson)));
	}

	@Test
	public void testCreateIAMRoleForSSL() throws Exception {
		CertificateAWSRole certificateAWSRole = new CertificateAWSRole("certificatename.t-mobile.com", "role1", "read", "external");

		String inputJson = new ObjectMapper().writeValueAsString(certificateAWSRole);
		String responseJson = "{\"messages\":[\"AWS Role created \"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);		
		when(sslCertificateAWSRoleService.createIAMRoleForSSL(Mockito.eq(userDetails), Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"),
				Mockito.any(AWSIAMRole.class))).thenReturn(responseEntityExpected);

		mockMvc.perform(MockMvcRequestBuilders.post("/v2/sslcert/aws/iam/role")
				.requestAttr("UserDetails", userDetails).header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
				.header("Content-Type", "application/json;charset=UTF-8").content(inputJson))
				.andExpect(status().isOk()).andExpect(content().string(containsString(responseJson)));
	}

	@Test
    public void testAddAWSroletoSSLCertificate() throws Exception {
		CertificateAWSRole certificateAWSRole = new CertificateAWSRole("certificatename", "role1", "read", "external");

        String inputJson =new ObjectMapper().writeValueAsString(certificateAWSRole);
        String responseJson = "{\"messages\":[\"AWS Role successfully associated with SSL Certificate\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
        when(sslCertificateAWSRoleService.addAwsRoleToSSLCertificate(Mockito.eq(userDetails), Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any(CertificateAWSRole.class))).thenReturn(responseEntityExpected);
        mockMvc.perform(MockMvcRequestBuilders.post("/v2/sslcert/aws").requestAttr("UserDetails", userDetails)
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseJson)));
    }

    @Test
    public void testRemoveAWSRoleFromSSLCertificate() throws Exception {
		CertificateAWSRoleRequest certificateAWSRoleRequest = new CertificateAWSRoleRequest("certificatename", "role1",
				"internal");
		String inputJson = new ObjectMapper().writeValueAsString(certificateAWSRoleRequest);
        String responseJson = "{\"messages\":[\"AWS Role is successfully removed from SSL Certificate\"]}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);        
        when(sslCertificateAWSRoleService.removeAWSRoleFromSSLCertificate(Mockito.eq(userDetails), Mockito.eq("5PDrOhsy4ig8L3EpsJZSLAMg"), Mockito.any(CertificateAWSRoleRequest.class))).thenReturn(responseEntityExpected);
        mockMvc.perform(MockMvcRequestBuilders.delete("/v2/sslcert/aws").requestAttr("UserDetails", userDetails)
                .header("vault-token", "5PDrOhsy4ig8L3EpsJZSLAMg")
                .header("Content-Type", "application/json;charset=UTF-8")
                .content(inputJson))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(responseJson)));
    }

	@Test
	public void testGetServiceCertificates() throws Exception {
		String responseJson = "{  \"keys\": [    {      \"akamid\": \"102463\",      \"applicationName\": \"tvs\", "
				+ "     \"applicationOwnerEmailId\": \"abcdef@mail.com\",      \"applicationTag\": \"TVS\",  "
				+ "    \"authority\": \"T-Mobile Issuing CA 01 - SHA2\",      \"certCreatedBy\": \"rob\",     "
				+ " \"certOwnerEmailId\": \"ntest@gmail.com\",      \"certType\": \"internal\",     "
				+ " \"certificateId\": 59480,      \"certificateName\": \"CertificateName.t-mobile.com\",   "
				+ "   \"certificateStatus\": \"Active\",      \"containerName\": \"VenafiBin_12345\",    "
				+ "  \"createDate\": \"2020-06-24T03:16:29-07:00\",      \"expiryDate\": \"2021-06-24T03:16:29-07:00\",  "
				+ "    \"projectLeadEmailId\": \"project@email.com\"    }  ]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
		String expected = responseEntityExpected.getBody();
		when(sslCertificateService.getAllSSLCertificatesToManage(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
				.thenReturn(responseEntityExpected);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/v2/sslcert?certificateName=CertificateName.t-mobile.com&certType=internal").header("vault-token", token)
				.header("Content-Type", "application/json;charset=UTF-8").requestAttr("UserDetails", userDetails)
				.content(expected)).andExpect(status().isOk()).andReturn();
		String actual = result.getResponse().getContentAsString();
		assertEquals(expected, actual);
	}

	@Test
    public void testAddGroupToCertificateSuccess() throws Exception {
		CertificateGroup certGroup = new CertificateGroup("certificatename.t-mobile.com","testgroup","read", "internal");
		String inputJson = getJSON(certGroup);
		String responseJson = "{\"messages\":[\"Group is successfully associated with Certificate\"]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
		when(sslCertificateService.addGroupToCertificate(Mockito.anyObject(), Mockito.any(), Mockito.anyObject()))
				.thenReturn(responseEntityExpected);
		MvcResult result = mockMvc
				.perform(MockMvcRequestBuilders.post("/v2/sslcert/group")
						.requestAttr("UserDetails", userDetails).header("vault-token", token)
						.header("Content-Type", "application/json;charset=UTF-8").content(inputJson))
				.andExpect(status().isOk()).andReturn();
		String actual = result.getResponse().getContentAsString();
		assertEquals(responseJson, actual);
	}


	@Test
	public void testGetCertificateDetailsSuccess() throws Exception {
		String responseJson = "{ \"data\": {\"akmid\":\"103001\",\"applicationName\":\"tvt\", "
				+ " \"applicationOwnerEmailId\":\"appowneremail@test.com\", \"applicationTag\":\"T-Vault\", "
				+ " \"authority\":\"T-Mobile Issuing CA 01 - SHA2\", \"certCreatedBy\": \"testuser1\", "
				+ " \"certOwnerEmailId\":\"owneremail@test.com\", \"certOwnerNtid\": \"testuser1\", \"certType\": \"internal\", "
				+ " \"certificateId\":\"62765\",\"certificateName\":\"certificatename.t-mobile.com\", "
				+ " \"certificateStatus\":\"Active\", \"containerName\":\"VenafiBin_12345\", "
				+ " \"createDate\":\"2020-06-24\", \"expiryDate\":\"2021-06-24\", "
				+ " \"projectLeadEmailId\":\"project@email.com\"}}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
		String expected = responseEntityExpected.getBody();
		when(sslCertificateService.getCertificateDetails(Mockito.anyString(), Mockito.anyString(),Mockito.anyString()))
				.thenReturn(responseEntityExpected);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/v2/sslcert/certificate/internal?certificate_name=CertificateName.t-mobile.com").header("vault-token", token)
				.header("Content-Type", "application/json;charset=UTF-8").requestAttr("UserDetails", userDetails)
				.content(expected)).andExpect(status().isOk()).andReturn();
		String actual = result.getResponse().getContentAsString();
		assertEquals(expected, actual);
	}

	@Test
	public void testGetListOfCertificatesSuccess() throws Exception {
		String responseJson = "{  \"keys\": [    {      \"akamid\": \"102463\",      \"applicationName\": \"tvs\", "
				+ "     \"applicationOwnerEmailId\": \"abcdef@mail.com\",      \"applicationTag\": \"TVS\",  "
				+ "    \"authority\": \"T-Mobile Issuing CA 01 - SHA2\",      \"certCreatedBy\": \"rob\",     "
				+ " \"certOwnerEmailId\": \"ntest@gmail.com\",      \"certType\": \"internal\",     "
				+ " \"certificateId\": 59480,      \"certificateName\": \"CertificateName.t-mobile.com\",   "
				+ "   \"certificateStatus\": \"Active\",      \"containerName\": \"VenafiBin_12345\",    "
				+ "  \"createDate\": \"2020-06-24T03:16:29-07:00\",      \"expiryDate\": \"2021-06-24T03:16:29-07:00\",  "
				+ "    \"projectLeadEmailId\": \"project@email.com\"    }  ]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
		String expected = responseEntityExpected.getBody();
		when(sslCertificateService.getListOfCertificates(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
				.thenReturn(responseEntityExpected);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/v2/sslcert/certificates/internal").header("vault-token", token)
				.header("Content-Type", "application/json;charset=UTF-8").requestAttr("UserDetails", userDetails)
				.content(expected)).andExpect(status().isOk()).andReturn();
		String actual = result.getResponse().getContentAsString();
		assertEquals(expected, actual);
	}

	@Test
	public void testGetAllCertificatesSuccess() throws Exception {
		String responseJson = "{  \"data\":{  \"keys\": [    {      \"akamid\": \"102463\",      \"applicationName\": \"tvs\", "
				+ "     \"applicationOwnerEmailId\": \"abcdef@mail.com\",      \"applicationTag\": \"TVS\",  "
				+ "    \"authority\": \"T-Mobile Issuing CA 01 - SHA2\",      \"certCreatedBy\": \"rob\",     "
				+ " \"certOwnerEmailId\": \"ntest@gmail.com\",      \"certType\": \"internal\",     "
				+ " \"certificateId\": 59480,      \"certificateName\": \"CertificateName.t-mobile.com\",   "
				+ "   \"certificateStatus\": \"Active\",      \"containerName\": \"VenafiBin_12345\",    "
				+ "  \"createDate\": \"2020-06-24T03:16:29-07:00\",      \"expiryDate\": \"2021-06-24T03:16:29-07:00\",  "
				+ "    \"projectLeadEmailId\": \"project@email.com\"    }  ]}}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
		String expected = responseEntityExpected.getBody();
		when(sslCertificateService.getAllCertificates(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
				.thenReturn(responseEntityExpected);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/v2/sslcert/list?certificateName=CertificateName.t-mobile.com").header("vault-token", token)
				.header("Content-Type", "application/json;charset=UTF-8").requestAttr("UserDetails", userDetails)
				.content(expected)).andExpect(status().isOk()).andReturn();
		String actual = result.getResponse().getContentAsString();
		assertEquals(expected, actual);
	}

	@Test
	public void testGetAllCertificatesOnCertTypeSuccess() throws Exception {
		String responseJson = "{\"data\":[{\"cert\":\"certificateName.t-mobile.com\"},{\"cert\":\"certificateName1.t-mobile.com\"}]}";
		ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
		String expected = responseEntityExpected.getBody();
		when(sslCertificateService.getAllCertificatesOnCertType(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
				.thenReturn(responseEntityExpected);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/v2/sslcert/list/internal").header("vault-token", token)
				.header("Content-Type", "application/json;charset=UTF-8").requestAttr("UserDetails", userDetails)
				.content(expected)).andExpect(status().isOk()).andReturn();
		String actual = result.getResponse().getContentAsString();
		assertEquals(expected, actual);
	}

    @Test
    public void testOnboardSingleCertSuccess() throws Exception {
        when(sslCertificateService.onboardSingleCert(userDetails, token, "internal", "CertificateName.t-mobile.com", "tvt")).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        when(httpServletRequest.getAttribute("UserDetails")).thenReturn(userDetails);
        assertEquals(HttpStatus.OK, SslCertificateController.onboardSingleCertificate(httpServletRequest, token, "internal", "CertificateName.t-mobile.com", "tvt").getStatusCode());
    }

    @Test
    public void testOnboardCertsSuccess() throws Exception {
        when(sslCertificateService.onboardCerts(userDetails, token, 0, 20)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        when(httpServletRequest.getAttribute("UserDetails")).thenReturn(userDetails);
        assertEquals(HttpStatus.OK, SslCertificateController.onboardCerts(httpServletRequest, token, 0, 20).getStatusCode());
    }

    @Test
    public void testGetAllSelfServiceGroupsSuccess() {
        when(sslCertificateService.getAllSelfServiceGroups(userDetails)).thenReturn(new ResponseEntity<>(HttpStatus.OK));
        when(httpServletRequest.getAttribute("UserDetails")).thenReturn(userDetails);
        assertEquals(HttpStatus.OK, SslCertificateController.getAllSelfServiceGroups(httpServletRequest, token).getStatusCode());
    }
    

    @Test
    public void test_getFullCertificateList() throws Exception {
        String responseJson = "{\n" +
                "  \"internal\": [\n" +
                "    \"certtest24022021.t-mobile.com\",\n" +
                "    \"certtest240220211.t-mobile.com\",\n" +
                "    \"certtest240220212.t-mobile.com\"\n" +
                "  ],\n" +
                "  \"external\": []\n" +
                "}";
        ResponseEntity<String> responseEntityExpected = ResponseEntity.status(HttpStatus.OK).body(responseJson);
        String expected = responseEntityExpected.getBody();
        when(sslCertificateService.getFullCertificateList(token, userDetails, ""))
                .thenReturn(responseEntityExpected);
        mockMvc.perform(MockMvcRequestBuilders.get("/v2/sslcert/allcertificates")
                .header("vault-token", token)
                .header("Content-Type", "application/json;charset=UTF-8"))
                .andExpect(status().isOk());
    }
}
