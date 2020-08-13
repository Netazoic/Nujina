package mujina.idp;

import mujina.api.IdpConfiguration;
import mujina.saml.SAMLAttribute;
import mujina.saml.SAMLPrincipal;

import org.opensaml.Configuration;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.ecp.Request;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.Validator;
import org.owasp.esapi.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

@Controller
public class SsoController {

  @Autowired
  private SAMLMessageHandler samlMessageHandler;

  @Autowired
  private IdpConfiguration idpConfiguration;

  @GetMapping("/SingleSignOnService")
  public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
    throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
    doSSO(request, response, authentication, false);
  }

  @PostMapping("/SingleSignOnService")
  public void singleSignOnServicePost(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
    throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException, SecurityException, MessageDecodingException, MetadataProviderException, ServletException {
    doSSO(request, response, authentication, true);
  }

  @SuppressWarnings("unchecked")
  private void doSSO(HttpServletRequest request, HttpServletResponse response, Authentication authentication, boolean postRequest) throws ValidationException, SecurityException, MessageDecodingException, MarshallingException, SignatureException, MessageEncodingException, MetadataProviderException, IOException, ServletException {
    SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response, postRequest);
    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

    String assertionConsumerServiceURL = idpConfiguration.getAcsEndpoint() != null ? idpConfiguration.getAcsEndpoint() : authnRequest.getAssertionConsumerServiceURL();
    List<SAMLAttribute> attributes = attributes(authentication);

    SAMLPrincipal principal = new SAMLPrincipal(
      authentication.getName(),
      attributes.stream()
        .filter(attr -> "urn:oasis:names:tc:SAML:1.1:nameid-format".equals(attr.getName()))
        .findFirst().map(attr -> attr.getValue()).orElse(NameIDType.UNSPECIFIED),
      attributes,
      authnRequest.getIssuer().getValue(),
      authnRequest.getID(),
      assertionConsumerServiceURL,
      messageContext.getRelayState());

 	 // Check for a credential (SP public key) in the request
	BasicX509Credential spCredential = null;
    Signature sig = authnRequest.getSignature();
    if(sig!=null) {
    	X509Certificate certificate = sig.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);

    	java.security.cert.X509Certificate spCert = null;

    	if (certificate != null) {
    		//Converts org.opensaml.xml.signature.X509Certificate to BasicX509Credential
    		String lexicalXSDBase64Binary = certificate.getValue();
    		byte[] decoded = DatatypeConverter.parseBase64Binary(lexicalXSDBase64Binary);

    		try {
    			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    			spCert = (java.security.cert.X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decoded));
    			spCredential = new BasicX509Credential();
    			spCredential.setEntityCertificate(spCert);   

    		}catch(Exception ex) {
    			throw new ValidationException(ex.getMessage());
    		}
    	}
    }
    samlMessageHandler.sendAuthnResponse(principal, response, spCredential);
  }

  @SuppressWarnings("unchecked")
  private List<SAMLAttribute> attributes(Authentication authentication) {
    String uid = authentication.getName();
    Map<String, List<String>> result = new HashMap<>(idpConfiguration.getAttributes());


    Optional<Map<String, List<String>>> optionalMap = idpConfiguration.getUsers().stream()
      .filter(user -> user.getPrincipal().equals(uid))
      .findAny()
      .map(FederatedUserAuthenticationToken::getAttributes);
    optionalMap.ifPresent(result::putAll);

    //See SAMLAttributeAuthenticationFilter#setDetails
    Map<String, String[]> parameterMap = (Map<String, String[]>) authentication.getDetails();
    parameterMap.forEach((key, values) -> {
      result.put(key, Arrays.asList(values));
    });

    //Check if the user wants to be persisted
    if (parameterMap.containsKey("persist-me") && "on".equalsIgnoreCase(parameterMap.get("persist-me")[0])) {
      result.remove("persist-me");
      FederatedUserAuthenticationToken token = new FederatedUserAuthenticationToken(
        uid,
        authentication.getCredentials(),
        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
      token.setAttributes(result);
      idpConfiguration.getUsers().removeIf(existingUser -> existingUser.getPrincipal().equals(uid));
      idpConfiguration.getUsers().add(token);
    }

    //Provide the ability to limit the list attributes returned to the SP
    return result.entrySet().stream()
      .filter(entry -> !entry.getValue().stream().allMatch(StringUtils::isEmpty))
      .map(entry -> entry.getKey().equals("urn:mace:dir:attribute-def:uid") ?
        new SAMLAttribute(entry.getKey(), singletonList(uid)) :
        new SAMLAttribute(entry.getKey(), entry.getValue()))
      .collect(toList());
  }

}
