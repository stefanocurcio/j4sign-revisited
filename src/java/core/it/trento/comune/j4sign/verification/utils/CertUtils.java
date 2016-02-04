package it.trento.comune.j4sign.verification.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;

public class CertUtils {

	public static class QCStatements {
		public static final String EMAIL = "rfc822name";
		public static final String EMAIL1 = "email";
		public static final String EMAIL2 = "EmailAddress";
		public static final String EMAIL3 = "E";
		public static final String DNS = "dNSName";
		public static final String URI = "uniformResourceIdentifier";
		public static final String URI1 = "uri";
		public static final String URI2 = "uniformResourceId";
		public static final String IPADDR = "iPAddress";
		public static final String DIRECTORYNAME = "directoryName";
		/** Microsoft altName for windows smart card logon */
		public static final String UPN = "upn";
		/** ObjectID for upn altName for windows smart card logon */
		public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";

		/**
		 * Returns true if the certificate contains a QC-statements extension.
		 * 
		 * @param cert
		 *            Certificate containing the extension
		 * @return true or false.
		 * @throws IOException
		 *             if there is a problem parsing the certificate
		 */
		public static boolean hasQcStatement(Certificate cert)
				throws IOException {
			boolean ret = false;
			if (cert instanceof X509Certificate) {
				X509Certificate x509cert = (X509Certificate) cert;
				DERObject obj = getExtensionValue(x509cert,
						X509Extensions.QCStatements.getId());
				if (obj != null) {
					ret = true;
				}
			}
			return ret;
		}

		/**
		 * Return an Extension DERObject from a certificate
		 */
		protected static DERObject getExtensionValue(X509Certificate cert,
				String oid) throws IOException {
			if (cert == null) {
				return null;
			}
			byte[] bytes = cert.getExtensionValue(oid);
			if (bytes == null) {
				return null;
			}
			ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(
					bytes));
			ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
			aIn = new ASN1InputStream(
					new ByteArrayInputStream(octs.getOctets()));
			return aIn.readObject();
		} // getExtensionValue

		private static String getStringFromGeneralNames(DERObject names) {
			ASN1Sequence namesSequence = ASN1Sequence.getInstance(
					(ASN1TaggedObject) names, false);
			if (namesSequence.size() == 0) {
				return null;
			}
			DERTaggedObject taggedObject = (DERTaggedObject) namesSequence
					.getObjectAt(0);
			return new String(ASN1OctetString.getInstance(taggedObject, false)
					.getOctets());
		} // getStringFromGeneralNames

		/**
		 * Returns all the 'statementId' defined in the QCStatement extension
		 * (rfc3739).
		 * 
		 * @param cert
		 *            Certificate containing the extension
		 * @return Collection of String with the oid, for example "1.1.1.2", or
		 *         empty Collection if no identifier is found, never returns
		 *         null.
		 * @throws IOException
		 *             if there is a problem parsing the certificate
		 */
		public static Collection getQcStatementIds(Certificate cert)
				throws IOException {
			ArrayList ret = new ArrayList();
			if (cert instanceof X509Certificate) {
				X509Certificate x509cert = (X509Certificate) cert;
				DERObject obj = getExtensionValue(x509cert,
						X509Extensions.QCStatements.getId());
				if (obj == null) {
					return ret;
				}
				ASN1Sequence seq = (ASN1Sequence) obj;
				for (int i = 0; i < seq.size(); i++) {
					QCStatement qc = QCStatement
							.getInstance(seq.getObjectAt(i));
					DERObjectIdentifier oid = qc.getStatementId();
					if (oid != null) {
						ret.add(oid.getId());
					}
				}
			}
			return ret;
		}

		public static ASN1Sequence getQcStatements(Certificate cert)
				throws IOException {

			ASN1Sequence seq = null;

			ArrayList ret = new ArrayList();
			if (cert instanceof X509Certificate) {
				X509Certificate x509cert = (X509Certificate) cert;
				DERObject obj = getExtensionValue(x509cert,
						X509Extensions.QCStatements.getId());

				seq = (ASN1Sequence) obj;
			}

			return seq;
		}

		/**
		 * Returns the value limit ETSI QCStatement if present.
		 * 
		 * @param cert
		 *            Certificate possibly containing the QCStatement extension
		 * @return String with the value and currency (ex '50000 SEK')or null if
		 *         the extension is not present
		 * @throws IOException
		 *             if there is a problem parsing the certificate
		 */
		public static String getQcStatementValueLimit(Certificate cert)
				throws IOException {
			String ret = null;
			if (cert instanceof X509Certificate) {
				X509Certificate x509cert = (X509Certificate) cert;
				DERObject obj = getExtensionValue(x509cert,
						X509Extensions.QCStatements.getId());
				if (obj == null) {
					return null;
				}
				ASN1Sequence seq = (ASN1Sequence) obj;
				MonetaryValue mv = null;
				// Look through all the QCStatements and see if we have a
				// stadard ETSI LimitValue
				for (int i = 0; i < seq.size(); i++) {
					QCStatement qc = QCStatement
							.getInstance(seq.getObjectAt(i));
					DERObjectIdentifier oid = qc.getStatementId();
					if (oid != null) {
						if (oid
								.equals(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue)) {
							// We MAY have a MonetaryValue object here
							ASN1Encodable enc = qc.getStatementInfo();
							if (enc != null) {
								mv = MonetaryValue.getInstance(enc);
								// We can break the loop now, we got it!
								break;
							}
						}
					}
				}
				if (mv != null) {
					BigInteger amount = mv.getAmount();
					BigInteger exp = mv.getExponent();
					BigInteger ten = BigInteger.valueOf(10);
					// A possibly gotcha here if the monetary value is larger
					// than what fits in a long...
					long value = amount.longValue()
							* (ten.pow(exp.intValue())).longValue();
					if (value < 0) {
						System.out.println("ETSI LimitValue amount is < 0.");
					}
					String curr = mv.getCurrency().getAlphabetic();
					if (curr == null) {
						System.out.println("ETSI LimitValue currency is null");
					}
					if ((value >= 0) && (curr != null)) {
						ret = value + " " + curr;
					}
				}
			}
			return ret;
		}

		// From:
		// https://svn.cesecore.eu/svn/ejbca/branches/Branch_3_7/ejbca/src/java/org/ejbca/util/cert/QCStatementExtension.java
		/**
		 * Returns the 'NameRegistrationAuthorities' defined in the QCStatement
		 * extension (rfc3739).
		 * 
		 * @param cert
		 *            Certificate containing the extension
		 * @return String with for example 'rfc822Name=foo2bar.se,
		 *         rfc822Name=bar2foo.se' etc. Supports email, dns and uri name,
		 *         or null of no RAs are found.
		 * @throws IOException
		 *             if there is a problem parsing the certificate
		 */
		public static String getQcStatementAuthorities(Certificate cert)
				throws IOException {
			String ret = null;
			if (cert instanceof X509Certificate) {
				X509Certificate x509cert = (X509Certificate) cert;
				DERObject obj = getExtensionValue(x509cert,
						X509Extensions.QCStatements.getId());
				if (obj == null) {
					return null;
				}
				ASN1Sequence seq = (ASN1Sequence) obj;
				SemanticsInformation si = null;
				// Look through all the QCStatements and see if we have a
				// standard RFC3739 pkixQCSyntax
				for (int i = 0; i < seq.size(); i++) {
					QCStatement qc = QCStatement
							.getInstance(seq.getObjectAt(i));
					DERObjectIdentifier oid = qc.getStatementId();
					if (oid != null) {
						if (oid
								.equals(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1)
								|| oid
										.equals(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v2)) {
							// We MAY have a SemanticsInformation object here
							ASN1Encodable enc = qc.getStatementInfo();
							if (enc != null) {
								si = SemanticsInformation.getInstance(enc);
								// We can break the loop now, we got it!
								break;
							}
						}
					}
				}
				if (si != null) {
					GeneralName[] gns = si.getNameRegistrationAuthorities();
					if (gns == null) {
						return null;
					}
					StringBuffer strBuf = new StringBuffer();
					for (int i = 0; i < gns.length; i++) {
						GeneralName gn = gns[i];
						if (strBuf.length() != 0) {
							// Append comma so we get nice formatting if there
							// are more than one authority
							strBuf.append(", ");
						}
						String str = getGeneralNameString(gn.getTagNo(), gn
								.getName());
						if (str != null) {
							strBuf.append(str);
						}
					}
					if (strBuf.length() > 0) {
						ret = strBuf.toString();
					}
				}
			}
			return ret;
		}

		/**
		 * GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1]
		 * IA5String, dNSName [2] IA5String, x400Address [3] ORAddress,
		 * directoryName [4] Name, ediPartyName [5] EDIPartyName,
		 * uniformResourceIdentifier [6] IA5String, iPAddress [7] OCTET STRING,
		 * registeredID [8] OBJECT IDENTIFIER}
		 * 
		 * @param tag
		 *            the no tag 0-8
		 * @param value
		 *            the DEREncodable value as returned by
		 *            GeneralName.getName()
		 * @return String in form rfc822Name=<email> or uri=<uri> etc
		 * @throws IOException
		 * @see #getSubjectAlternativeName
		 */
		public static String getGeneralNameString(int tag, DEREncodable value)
				throws IOException {
			String ret = null;
			switch (tag) {
			case 0:
				ASN1Sequence seq = getAltnameSequence(value.getDERObject()
						.getEncoded());
				String upn = getUPNStringFromSequence(seq);
				// OtherName can be something else besides UPN
				if (upn != null) {
					ret = UPN + "=" + upn;
				}
				break;
			case 1:
				ret = EMAIL + "=" + DERIA5String.getInstance(value).getString();
				break;
			case 2:
				ret = DNS + "=" + DERIA5String.getInstance(value).getString();
				break;
			case 3: // SubjectAltName of type x400Address not supported
				break;
			case 4: // SubjectAltName of type directoryName not supported
				break;
			case 5: // SubjectAltName of type ediPartyName not supported
				break;
			case 6:
				ret = URI + "=" + DERIA5String.getInstance(value).getString();
				break;
			case 7:
				ASN1OctetString oct = ASN1OctetString.getInstance(value);
				ret = IPADDR + "=" + ipOctetsToString(oct.getOctets());
				break;
			default: // SubjectAltName of unknown type
				break;
			}
			return ret;
		}

		private static ASN1Sequence getAltnameSequence(byte[] value)
				throws IOException {
			DERObject oct = (new ASN1InputStream(
					new ByteArrayInputStream(value)).readObject());
			ASN1Sequence seq = ASN1Sequence.getInstance(oct);
			return seq;
		}

		/**
		 * Helper method for the above method
		 * 
		 * @param seq
		 *            the OtherName sequence
		 */
		private static String getUPNStringFromSequence(ASN1Sequence seq) {
			if (seq != null) {
				// First in sequence is the object identifier, that we must
				// check
				DERObjectIdentifier id = DERObjectIdentifier.getInstance(seq
						.getObjectAt(0));
				if (id.getId().equals(UPN_OBJECTID)) {
					ASN1TaggedObject obj = (ASN1TaggedObject) seq
							.getObjectAt(1);
					DERUTF8String str = DERUTF8String.getInstance(obj
							.getObject());
					return str.getString();
				}
			}
			return null;
		}

		/**
		 * Converts ip-adress octets, according to ipStringToOctets to human
		 * readable string in form 10.1.1.1 for ipv4 adresses.
		 * 
		 * @param octets
		 * @return ip address string, null if input is invalid
		 * @see #ipStringToOctets(String)
		 */
		public static String ipOctetsToString(final byte[] octets) {
			String ret = null;
			if (octets.length == 4) {
				String ip = "";
				// IPv4 address
				for (int i = 0; i < 4; i++) {
					// What is going on there is that we are promoting a
					// (signed) byte to int,
					// and then doing a bitwise AND operation on it to wipe out
					// everything but
					// the first 8 bits. Because Java treats the byte as signed,
					// if its unsigned
					// value is above > 127, the sign bit will be set, and it
					// will appear to java
					// to be negative. When it gets promoted to int, bits 0
					// through 7 will be the
					// same as the byte, and bits 8 through 31 will be set to 1.
					// So the bitwise
					// AND with 0x000000FF clears out all of those bits.
					// Note that this could have been written more compactly as;
					// 0xFF & buf[index]
					final int intByte = (0x000000FF & ((int) octets[i]));
					final short t = (short) intByte; // NOPMD, we need short
					if ("".equals(ip)) {
						ip += ".";
					}
					ip += t;
				}
				ret = ip;
			}
			// TODO: IPv6
			return ret;
		}

	}

	/**
	 * Converts a byte array in its exadecimal representation.
	 * 
	 * @param bytes
	 *            byte[]
	 * @return java.lang.String
	 */
	public static String formatAsHexString(byte[] bytes) {
		int n, x;
		String w = new String();
		String s = new String();
		for (n = 0; n < bytes.length; n++) {

			x = (int) (0x000000FF & bytes[n]);
			w = Integer.toHexString(x).toUpperCase();
			if (w.length() == 1) {
				w = "0" + w;
			}
			s = s + w + ((n + 1) % 16 == 0 ? "\n" : " ");
		}
		return s;
	}
	
    /**
     * Returns Common Name (string) of the given Distinguished Name <br>
     * <br>
     * Restituisce il CN del DN in oggetto
     * 
     * @param userCert
     *            X509Certificate
     * @return String
     */
    public static String getCommonName(String DN) {
        int offset = DN.indexOf("CN=");
        int end = DN.indexOf(",", offset);
        String CN;
        if (end != -1) {
            CN = DN.substring(offset + 3, end);
        } else {
            CN = DN.substring(offset + 3, DN.length());
        }
        return CN;
    }

}
