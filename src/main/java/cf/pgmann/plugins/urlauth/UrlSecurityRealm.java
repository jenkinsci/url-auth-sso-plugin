package cf.pgmann.plugins.urlauth;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.dao.DataAccessException;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import jenkins.model.Jenkins;

public class UrlSecurityRealm extends SecurityRealm implements UserDetailsService {
	public final String targetUrl, ssoLoginUrl, userNameKey, displayNameKey, emailKey;
	public static final String DEFAULT_USERNAME_KEY = "user_name", DEFAULT_DISPLAYNAME_KEY = "display_name", DEFAULT_EMAIL_KEY = "public_email";
	public static final String REFERER_KEY = UrlSecurityRealm.class.getName()+".referer";
	protected static UrlSecurityRealm self;

	@DataBoundConstructor
	public UrlSecurityRealm(String targetUrl, String ssoLoginUrl, String userNameKey, String displayNameKey, String emailKey) {
		self = this;
		this.targetUrl = targetUrl;
		this.ssoLoginUrl = ssoLoginUrl;
		this.userNameKey = userNameKey;
		this.displayNameKey = displayNameKey;
		this.emailKey = emailKey;
	}

	@Override
	public SecurityComponents createSecurityComponents() {
		return new SecurityComponents(new AuthenticationManager() {
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				return authentication;
			}
		}, new UserDetailsService() {
			@Override
			public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
				Authentication a = SecurityContextHolder.getContext().getAuthentication();
				if(a instanceof UrlAuthToken) return ((UrlAuthToken)a).getUserDetails();
				return new UrlAuthUserDetails(username, username, ""); // Fixes bug which causes a FAILED Job Build Status.
			}
		});
	}

	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		super.createFilter(filterConfig);
		return new Filter() {
			@Override
			public void init(FilterConfig filterConfig) throws ServletException {}

			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
				self=UrlSecurityRealm.this;
				SecurityContext c = SecurityContextHolder.getContext();

				HttpServletRequest r = (HttpServletRequest)request;
				if(r.getCookies() != null && targetUrl != null && !targetUrl.isEmpty()) {
					String cookies = r.getHeader("Cookie");
					UrlAuthToken t = new UrlAuthToken(cookies);
					if(t.isAuthenticated()) {
						c.setAuthentication(t);
						User u = User.current();
						if(u != null) {
							u.setFullName(t.getUserDetails().getDisplayName());
							if(!t.getUserDetails().getEmail().isEmpty()) u.addProperty(new Mailer.UserProperty(t.getUserDetails().getEmail()));
						}
					} else {
						// Log out a user which can no longer be authenticated
						c.setAuthentication(Jenkins.ANONYMOUS);
					}
				} else {
					c.setAuthentication(Jenkins.ANONYMOUS);
				}
				chain.doFilter(request, response);
			}

			@Override
			public void destroy() {}
		};
	}

	@Override
	public boolean allowsSignup() {
		return false;
	}
	@Override
	public boolean canLogOut() {
		return false;
	}

	@Override
	public String getLoginUrl() {
		return "securityRealm/login";
	}

	public HttpResponse doLogin(StaplerRequest request, @Header("Referer") String referer, @Header("Cookie") String cookies) throws IOException {
		// The doFilter() method will run before this and try to authenticate the user.
		self=this;
		
		if(SecurityContextHolder.getContext().getAuthentication().equals(Jenkins.ANONYMOUS)) {
			// If the user still isn't authenticated - redirect to the SSO Login URL so they can log in.
			if(ssoLoginUrl == null || ssoLoginUrl.isEmpty())
				throw new IllegalArgumentException("Please set the authentication Login URL in Jenkins global security configuration.");
			
			request.getSession().setAttribute(REFERER_KEY, referer); // save the previous page
			return new HttpRedirect(ssoLoginUrl);
		} else {
			// The user has now been successfully authenticated - send them back to where they were before clicking login (as accurately as possible)
			// Try to return to the session saved referer, the referer or the context root (in this order of preference)
			Object savedReferer = request.getSession().getAttribute(REFERER_KEY);
			if(savedReferer instanceof String && !((String)savedReferer).isEmpty()) return new HttpRedirect((String)savedReferer);
			else if(referer != null && !referer.isEmpty()) return new HttpRedirect(referer);
			else return HttpRedirect.CONTEXT_ROOT;
		}
	}

	@Extension
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
		@Override
		public String getDisplayName() {
			return "URL Auth Plugin";
		}
		public String getDefaultUserNameKey() {
			return DEFAULT_USERNAME_KEY;
		}
		public String getDefaultDisplayNameKey() {
			return DEFAULT_DISPLAYNAME_KEY;
		}
		public String getDefaultEmailKey() {
			return DEFAULT_EMAIL_KEY;
		}
		public DescriptorImpl() {
			super();
		}
		public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
			super(clazz);
		}
	}
}
