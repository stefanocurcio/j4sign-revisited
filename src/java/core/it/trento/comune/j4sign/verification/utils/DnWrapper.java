package it.trento.comune.j4sign.verification.utils;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

public class DnWrapper {

	private LdapName dn;
	private String givenName;
	private String surname;
	private String commonName;
	private String organization;
	private String serialNumber;

	public DnWrapper(String dnString) throws InvalidNameException {

		this.dn = new LdapName(dnString);

		init();
	}

	private void init() {
		java.util.List<Rdn> rdns = this.dn.getRdns();

		for (final Rdn r : rdns) {
			String type = r.getType();
			if("CN".equals(type))
				this.commonName = (String) r.getValue();
			if("O".equals(type))
				this.organization = (String) r.getValue();
			if("GIVENNAME".equals(type))
				this.givenName = (String) r.getValue();
			if("SURNAME".equals(type))
				this.surname = (String) r.getValue();
			if("SERIALNUMBER".equals(type))
				this.serialNumber = (String) r.getValue();
		}
	}

	public String getCommonName() {
		return commonName;
	}

	public String getOrganization() {
		return organization;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public String getGivenName() {
		return givenName;
	}

	public String getSurname() {
		return surname;
	}


}
