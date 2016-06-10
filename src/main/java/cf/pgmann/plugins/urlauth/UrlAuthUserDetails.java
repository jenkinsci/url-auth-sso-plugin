package cf.pgmann.plugins.urlauth;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;

public class UrlAuthUserDetails extends User implements UserDetails {
	private static final long serialVersionUID = 1L;
	private String userName, displayName, email;
	
	public UrlAuthUserDetails(String userName, String displayName, String email) {
		super(userName, "", true, true, true, true, new GrantedAuthority[]{});
		this.userName = userName;
		this.displayName = displayName;
		this.email = email;
	}

	public String getUserName() {
		return userName;
	}

	public String getDisplayName() {
		return displayName;
	}
	public void setDisplayName(String name) {
		this.displayName = name;
	}

	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	
	@Override
	public boolean equals(Object that) {
		if(!(that instanceof UrlAuthUserDetails)) return false;
		UrlAuthUserDetails user = (UrlAuthUserDetails) that;
		
		if(!userName.equals(user.userName)) return false;
		if(!displayName.equals(user.displayName)) return false;
		if(!email.equals(user.email)) return false;
		
		return super.equals(that);
	}
	
	@Override
	public int hashCode() {
		return super.hashCode();
	}
}
