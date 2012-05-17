package uk.ac.cam.ucs.webauth.tomcat;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.servlet.ServletException;

import org.apache.catalina.Session;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import uk.ac.cam.ucs.webauth.WebauthException;
import uk.ac.cam.ucs.webauth.WebauthRequest;
import uk.ac.cam.ucs.webauth.WebauthResponse;
import uk.ac.cam.ucs.webauth.WebauthValidator;

/**
 * Tomcat Valve that restricts access to users who have been authenticated by the Raven authentication system.
 * Uses the uk.ac.cam.ucs.webauth package to perform the validation on the Raven WLS responses.
 * 
 * <p>
 * The 'life' parameter in the Raven response is not used.  Since a user once authorised has a Tomcat session (and
 * does not access Raven again for the life of that session), the session-life that can be configured directly
 * in Tomcat is preferred.
 * </p>
 * 
 * <p>
 * Properties keyName and keyBase should be used to configure where the Raven certificate is found, and what
 * name is used for it.  Defaults to conf/raven_pubkey.crt and webauth-pubkey2
 * </p>
 * 
 * @author William Billingsley
 *
 */
public class RavenValve extends ValveBase {

	public static final String WLS_RESPONSE_PARAM = "WLS-Response";

	public static final String RAVEN_REQ_KEY = "RavenReq";

	public static final String STORED_STATE_KEY = "RavenState";

	/**
	 * This is the default path and filename prefix for the raven public keys
	 */
	public static final String DEFAULT_KEYBASE = "conf/raven_pubkey.crt";

	/**
	 * This is the default name for the raven public key
	 */
	public static final String DEFAULT_KEYNAME = "webauth-pubkey2";	
	
	protected KeyStore keyStore = null;
	
	protected String keyName = DEFAULT_KEYNAME;

	protected Log log = LogFactory.getLog(RavenValve.class);

	protected String keyBase = (new File(DEFAULT_KEYBASE)).isAbsolute() ? DEFAULT_KEYBASE : (new File(System
			.getProperty("catalina.base"), DEFAULT_KEYBASE).getAbsolutePath());

	protected WebauthValidator webauthValidator;

	protected KeyStore getKeyStore() {
		if (keyStore == null) {
			String newkeyBase = (new File(keyBase)).isAbsolute() ? keyBase : (new File(System
					.getProperty("catalina.base"), keyBase).getAbsolutePath());
			try {
				keyStore = KeyStore.getInstance("JKS");
				keyStore.load(null, new char[] {}); // Null InputStream, no
													// password
				CertificateFactory factory = CertificateFactory.getInstance("X.509");
				Certificate cert = factory.generateCertificate(new FileInputStream(newkeyBase));
				keyStore.setCertificateEntry(this.getKeyName(), cert);
			} catch (Exception e) {
				throw new RuntimeException("Failed to set up keystore", e);
			}
		}
		return keyStore;
	}
	
	protected WebauthValidator getWebauthValidator() {
		if (webauthValidator == null) {
			webauthValidator = new WebauthValidator(getKeyStore());
		}
		return webauthValidator;
	}

	/**
	 * Java Bean methods for setting the keybase in server.xml
	 */
	public void setKeyBase(String keyBase) {
		this.keyBase = keyBase;
	}

	/**
	 * Java Bean methods for getting the keybase
	 */
	public String getKeyBase() {
		return keyBase;
	}
	
	public void setKeyName(String keyName) {
		this.keyName = keyName;
	}
	
	public String getKeyName() {
		return this.keyName;
	}

	@Override
  public void invoke(Request request, Response response) throws IOException, ServletException {

		// Check for an authentication reply in the request
		String wlsResponse = request.getParameter(WLS_RESPONSE_PARAM);
		log.debug("RavenValve: WLS-Response is " + wlsResponse);

		Session session = request.getSessionInternal();
		WebauthResponse storedResponse = (WebauthResponse) session.getNote(WLS_RESPONSE_PARAM);
		log.debug("RavenValve: Stored Response is " + (storedResponse == null ? "null" : storedResponse.toString()));

		WebauthRequest storedRavenReq = (WebauthRequest) session.getNote(RAVEN_REQ_KEY);
		log.debug("RavenValve: Stored Raven Request is "
				+ (storedRavenReq == null ? "null" : storedRavenReq.toString()));

		RavenState storedState = (RavenState) session.getNote(STORED_STATE_KEY);
		log.debug("RavenValve: Stored Raven State is " + (storedState == null ? "null" : storedState.toString()));

		/*
		 * Check the stored state if we have it
		 */
		if (storedState != null) {
			if (storedState.status != 200) {
				session.setNote(STORED_STATE_KEY, null);
				response.sendError(storedState.status);
				return;
			}
			
			/*
			 * We do not check for expiry of the state because in this implementation we simply use the session expiry
			 * the web admin has configured in Tomcat (since the Raven authentication is only used to set up the session,
			 * it makes sense to use the session's expiry rather than Raven's).
			 */
			
			/*
			 * We do not check for state.last or state.issue being in the future.  State.issue is already checked in the 
			 * WebauthValidator when the state is initially created.  State.last is set by System.currentTimeMillis at state
			 * creation time and therefore cannot be in the future.
			 */

			if (wlsResponse == null || wlsResponse.length() == 0) {
				session.setPrincipal(storedState.principal);
				request.setUserPrincipal(storedState.principal);
				Valve v = this.getNext();
				if (v != null) {
					v.invoke(request, response);
				}
				return;
			}
		}

		/*
		 * Check the received response if we have it.
		 * 
		 * Note - if we have both a stored state and a WLS-Response, we let the WLS-Response override the stored state
		 * (this is no worse than if the same request arrived a few minutes later when the first session would have expired, thus 
		 * removing the stored state)
		 */
		if (wlsResponse != null && wlsResponse.length() > 0) {
			WebauthResponse webauthResponse = new WebauthResponse(wlsResponse);
			session.setNote(WLS_RESPONSE_PARAM, webauthResponse);
			try {
				log.debug("RavenValve: validating received response with stored request");
				this.getWebauthValidator().validate(storedRavenReq, webauthResponse);
				
				session.setPrincipal(new RavenPrincipal(webauthResponse.get("principal")));
				RavenState state = new RavenState(200, webauthResponse.get("issue"), webauthResponse.get("life"),
						webauthResponse.get("id"), session.getPrincipal(), webauthResponse.get("auth"), webauthResponse
								.get("sso"), webauthResponse.get("params"));
				
				log.debug("RavenValve: storing new state " + state.toString());
				session.setNote(STORED_STATE_KEY, state);
				request.setUserPrincipal(session.getPrincipal());

				/*
				 * We do a redirect here so the user doesn't see the WLS-Response in his browser location
				 */
				response.sendRedirect(webauthResponse.get("url"));
				return;
			} catch (WebauthException e) {
				log.debug("RavenValve: response validation failed - " + e.getMessage());
				response.sendError(500, "RavenValve: response validation failed - " + e.getMessage());
				return;
			}
		} else {
			/*
			 * No WLS-Response, no stored state.  Redirect the user to Raven to log in
			 */
			WebauthRequest webauthReq = new WebauthRequest();

			StringBuffer url = request.getRequestURL();
			if (request.getQueryString() != null && request.getQueryString().length() > 0) {
				url.append('?');
				url.append(request.getQueryString());
			}
			log.debug("RavenValve: redirecting with url " + url.toString());
			webauthReq.set("url", url.toString());
			session.setNote(RAVEN_REQ_KEY, webauthReq);
			response.sendRedirect("https://raven.cam.ac.uk/auth/authenticate.html?" + webauthReq.toQString());
			return;
		}

	}
}

class RavenPrincipal implements Principal {
	protected String name;

	public RavenPrincipal(String name) {
		this.name = name;
	}

	@Override
  public String getName() {
		return name;
	}

	@Override
  public String toString() {
		return "RavenPrincipal--" + name;
	}

}

class RavenState {

	int status;

	String issue;

	long last;

	String life;

	String id;

	Principal principal;

	String aauth;

	String sso;

	String params;

	public RavenState(int status, String issue, String life, String id, Principal principal, String aauth, String sso,
			String params) {
		this.status = status;
		this.issue = issue;
		this.last = System.currentTimeMillis();
		this.life = life;
		this.id = id;
		this.principal = principal;
		this.aauth = aauth;
		this.sso = sso;
		this.params = params;
	}

	@Override
  public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(" Status: ");
		sb.append(status);
		sb.append(" Issue: ");
		sb.append(issue);
		sb.append(" Last: ");
		sb.append(last);
		sb.append(" Life: ");
		sb.append(life);
		sb.append(" ID: ");
		sb.append(id);
		sb.append(" Principal: ");
		sb.append(principal);
		sb.append(" AAuth: ");
		sb.append(aauth);
		sb.append(" SSO: ");
		sb.append(sso);
		sb.append(" Params: ");
		sb.append(params);
		return sb.toString();
	}
}

