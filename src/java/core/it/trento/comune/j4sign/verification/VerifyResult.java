/**
 *	j4sign - an open, multi-platform digital signature solution
 *	Copyright (c) 2005 Francesco Cendron - Infocamere;
 *  Copyright (c) 2014 Roberto Resoli - Comune di Trento;
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

package it.trento.comune.j4sign.verification;

import it.trento.comune.j4sign.verification.utils.CertUtils;
import it.trento.comune.j4sign.verification.utils.DefaultCMSSignatureAlgorithmNameGenerator;

import java.io.*;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.ListIterator;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.util.encoders.Base64;

/**
 * Object used to perform verification about certificate validity and signature
 * integrity. Methods get... perform action, methods is... just return value. It
 * is obviously necessary performing verification before returning the value <br>
 * <br>
 * Oggetto che effettua e restituisce le verifiche sul certificato e
 * sull'integrità della firma. I metodi get perfomano la verifica, i metodi is
 * restituiscono solo il risultato. E' ovviamente necessario prima effettuare la
 * verifica e poi restituire il risultato.
 * 
 * @author Francesco Cendron
 */
public class VerifyResult {

	private Properties conf = null;
	private Logger log = Logger.getLogger(this.getClass().getName());
	private boolean isPathValid;

	private boolean integrityChecked = false;
	private boolean contentTypeDataPresent = false;
	private boolean messageDigestPresent = false;

	private boolean keyUsageNonRepudiationAloneCritical = false;

	private boolean isRevoked;
	private boolean isExpired;
	private boolean isInUse; // contrario di NotYetValid

	private CertValidity cv;

	private String CRLerror = "";
	private String certPathError = "";

	private SignerInformation signer;

	private boolean counterSignature = false;

	private CMSSignedData cms;
	private X509Certificate cert;
	private String encodedDigest;
	private boolean crlDownloadForced;

	private boolean encryptionRSA = false;
	private boolean hashingSHA256 = false;
	private boolean cades = false;

	private boolean checkQCStatements = true;

	private Date signingTime = null;
	private String signingAlgorithmName = null;

	private boolean passed;

	private Hashtable<X500Principal, VerifyResult> risultatiCs;

	private File crlDir = null;

	/**
	 * Constructor
	 * 
	 * @param c
	 *            X509Certificate
	 * @param cm
	 *            CMSSignedData
	 * @param C
	 *            CertificationAuthorities
	 * @param s
	 *            SignerInformation
	 */
	public VerifyResult(Properties aConf, Store certs, X509Certificate c,
			CMSSignedData cm, CertificationAuthorities C, SignerInformation s) {
		this(aConf, certs, c, cm, C, s, false, false, true, null);

	}

	/**
	 * Constructor
	 * 
	 * @param c
	 *            X509Certificate
	 * @param cm
	 *            CMSSignedData
	 * @param C
	 *            CertificationAuthorities
	 * @param s
	 *            SignerInformation
	 * @param isDownloadCRLForced
	 *            boolean
	 */
	public VerifyResult(Properties aConf, Store certs, X509Certificate c,
			CMSSignedData cm, CertificationAuthorities roots,
			SignerInformation s, boolean counterSignature,
			boolean isDownloadCRLForced, boolean checkQCS, File crlDir) {

		conf = aConf;
		integrityChecked = false;
		cert = c;
		signer = s;
		this.counterSignature = counterSignature;

		this.crlDownloadForced = isDownloadCRLForced;

		this.crlDir = crlDir;

		log.info("Verification start");

		cv = new CertValidity(conf, c, roots, this.crlDownloadForced, this.crlDir);

		cms = cm;
		encodedDigest = null;
		passed = false;

		checkQCStatements = checkQCS;

		initCountersignatures(certs, cm, roots, s, isDownloadCRLForced);

	}

	private void initCountersignatures(Store certs, CMSSignedData cm,
			CertificationAuthorities roots, SignerInformation parentSigner,
			boolean isDownloadCRLForced) {

		SignerInformationStore cs = parentSigner.getCounterSignatures();
		if (cs.size() > 0) {

			risultatiCs = new Hashtable<X500Principal, VerifyResult>();

			log.info("detected " + cs.size() + " countersignatures for "
					+ cert.getSubjectX500Principal());

			Iterator<SignerInformation> csIterator = cs.getSigners().iterator();

			while (csIterator.hasNext()) {
				SignerInformation counterSigner = csIterator.next();
				Collection cc = null;
				try {
					cc = certs.getMatches(counterSigner.getSID());

				} catch (StoreException ex1) {
					log.severe("Errore nel CertStore");
					// errors.add("Errore nel CertStore");
				}

				if (cc.size() == 1) {

					X509CertificateHolder ch = (X509CertificateHolder) cc
							.toArray()[0];

					// get Certificate
					X509Certificate c;
					try {
						c = new JcaX509CertificateConverter().setProvider("BC")
								.getCertificate(ch);

						log.info("CounterSigner CN: "
								+ Verifier.getCommonName(c));

						VerifyResult vr = new VerifyResult(conf, certs, c, cm, roots,
								counterSigner, true, this.crlDownloadForced,
								this.checkQCStatements, this.crlDir);

						risultatiCs.put(c.getSubjectX500Principal(), vr);

					} catch (CertificateException e) {
						log.severe("Errore nell'estrazione del certificato del controfirmatario: "
								+ e.getMessage());
					}

				}

			}
		}
	}

	public X509CRL getCrl() {
		return cv.getCRL();
	}

	public X509Certificate getCert() {
		return cert;
	}

	/**
	 * Main signature verification and signature attributes correctness<br>
	 * <br>
	 * Verifica principale della firma e di correttezza degli attributi.
	 * 
	 * @return boolean
	 */
	public boolean checkIntegrity() {

		this.integrityChecked = this.messageDigestPresent = this.contentTypeDataPresent = false;

		if (signer == null) {
			log.info("No signers");
			return integrityChecked;
		}

		log.info("\nSigner DN: " + cert.getSubjectDN() + "\nSigner SID: "
				+ signer.getSID().toString() + "\n");

		// ===== List authenticated attributes =========
		AttributeTable attrs = signer.getSignedAttributes();

		if (attrs == null) {
			log.info("No authenticated attributes!");
			return false;
		}

		Iterator<Attribute> iter = attrs.toHashtable().values().iterator();

		log.info("Listing authenticated attributes:");

		int count = 1;
		while (iter.hasNext()) {
			Attribute a = iter.next();

			log.info("Attribute " + count + ")");

			if (a.getAttrType().getId()
					.equals(CMSAttributes.contentType.getId())) {
				if (CMSObjectIdentifiers.data.getId().equals(
						DERObjectIdentifier.getInstance(
								a.getAttrValues().getObjectAt(0)).getId()))

					this.contentTypeDataPresent = true;

				log.info("Content Type: PKCS7_DATA");
			}

			if (a.getAttrType().getId()
					.equals(CMSAttributes.messageDigest.getId())) {
				byte[] md = DEROctetString.getInstance(
						a.getAttrValues().getObjectAt(0)).getOctets();

				this.messageDigestPresent = true;

				log.info("Message Digest:\n" + CertUtils.formatAsHexString(md));
			}

			if (a.getAttrType()
					.getId()
					.equals(PKCSObjectIdentifiers.id_aa_signingCertificateV2
							.getId()))

				log.info("Reference to signing certificate (CAdES): signingCertificateV2");

			if (a.getAttrType().getId()
					.equals(CMSAttributes.signingTime.getId())) {
				Time time = Time.getInstance(a.getAttrValues().getObjectAt(0));

				log.info("Signing time: " + time.getDate());

				this.signingTime = time.getDate();
			}

			log.info("\nAttribute dump follows:");
			log.info(ASN1Dump.dumpAsString(a) + "\n");

			count++;
		}

		signingAlgorithmName = new DefaultCMSSignatureAlgorithmNameGenerator()
				.getSignatureName(AlgorithmIdentifier.getInstance(signer
						.getDigestAlgOID()), AlgorithmIdentifier
						.getInstance(signer.getEncryptionAlgOID()));

		log.info("\nSigning algorithm is : " + signingAlgorithmName + "\n");

		try {

			// BC API version 2
			/*
			 * Note: we should test for EncryptionAlg = RSA before doing
			 * this!!!! integrityChecked = signer .verify(new
			 * BcRSASignerInfoVerifierBuilder( new
			 * DefaultDigestAlgorithmIdentifierFinder(), new
			 * BcDigestCalculatorProvider()) .build(new
			 * X509CertificateHolder(cert.getEncoded())));
			 */

			integrityChecked = signer
					.verify(new JcaSimpleSignerInfoVerifierBuilder()
							.build(new X509CertificateHolder(cert.getEncoded())));

			// Now deprecated
			// integrityChecked = signer.verify(cert, "BC");

		} catch (CMSException ex) {
			System.out.println(ex.getMessage());
		} catch (CertificateNotYetValidException ex) {
			System.out.println(ex.getMessage());
		} catch (CertificateExpiredException ex) {
			System.out.println(ex.getMessage());
		} catch (CertificateException e) {
			System.out.println(e.getMessage());
		} catch (OperatorCreationException e) {
			System.out.println(e.getMessage());
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}

		return integrityChecked;
	}

	public boolean isIntegrityChecked() {

		return integrityChecked;
	}

	/**
	 * Perform the global verification and return the global result<br>
	 * <br>
	 * Metodo complessivo che esegue e restituisce la verifica
	 * 
	 * @return boolean
	 */
	public boolean getPassed() {

		checkIntegrity();

		log.info("Mandatory authenticated attributes present: "
				+ mandatoryAuthenticatedAttributesPresent());

		log.info("Integrity check: " + integrityChecked);

		log.info("Starting Certificate verification...");

		boolean certValid = cv.getPassed();

		log.info("Certificate Verification: " + cv.isPassed());

		getKeyUsageNonRepudiationAloneCritical();

		log.info("KeyUsage is nonRepudiation only: "
				+ isKeyUsageNonRepudiationAloneCritical());

		passed = isIntegrityChecked()
				&& (isCounterSignature() || isMandatoryAuthenticatedAttributesPresent())
				&& certValid && isKeyUsageNonRepudiationAloneCritical();

		if (checkQCStatements) {
			passed = passed && cv.getHasQcStatements();

			if (cv.getQcStatementsStrings() != null) {
				log.info("QC Statements present: ");
				ListIterator<String> li = cv.getQcStatementsStrings()
						.listIterator();
				while (li.hasNext())
					log.info(li.next());
			}
		}

		getEncryptionRSA();
		log.info("\nEncryption Algorithm OID: " + signer.getEncryptionAlgOID());
		log.info("\nEncryption is RSA: " + isEncryptionRSA());

		// RSA is mandatory, but sometimes Encryption alg OID is incorrect;
		// be relaxed if signing alg is OK
		passed = passed
				&& (isEncryptionRSA() || getSigningAlgorithmName().contains(
						"RSA"));

		// CAdES and SHA-256 are mandatory in Italy for signatures
		// created after June 30, 2011
		getCAdES();
		log.info("CAdES format: " + isCades());

		getHashingSHA256();
		log.info("Hashing Algorithm OID: " + signer.getDigestAlgOID());
		log.info("Hashing is SHA-256: " + isHashingSHA256());

		// Get Italian timezone
		Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("CEST"));
		// Set calendar to June 30, 2011
		cal.set(2011, Calendar.JUNE, 30);
		if (signingTime != null)
			if (signingTime.after(cal.getTime())) {
				passed = passed && isCades() && isHashingSHA256();
				log.info("Signing Time is after June 30 2011, CAdES and SHA-256 hashing are critical");
			}

		CRLerror = cv.getCRLerror();

		log.info("*** Verification for this signer passed: " + passed + " ***");

		if (risultatiCs != null) {

			Iterator<X500Principal> principalIterator = risultatiCs.keySet()
					.iterator();

			boolean csVerified = false;
			int i = 0;
			while (principalIterator.hasNext()) {
				X500Principal signer = principalIterator.next();
				VerifyResult sv = risultatiCs.get(signer);
				csVerified = sv.getPassed() && ((i == 0) || csVerified);
			}

			passed = passed && csVerified;

		}

		CRLerror = cv.getCRLerror();
		certPathError = cv.getCertPathError();

		return passed;
	}

	public boolean isCounterSignature() {
		return counterSignature;
	}

	public Hashtable<X500Principal, VerifyResult> getRisultatiCs() {
		return risultatiCs;
	}

	/**
	 * Perform the global verification and return the global result<br>
	 * <br>
	 * Metodo complessivo che esegue e restituisce la verifica
	 * 
	 * @return boolean
	 */
	public boolean getPassed_cnipasigner_expired() {

		passed = checkIntegrity() && cv.getPassed_noExpiredCheck();
		CRLerror = cv.getCRLerror();
		return passed;
	}

	/**
	 * Return CRLerror (error during CRL download)<br>
	 * <br>
	 * Restituisce l'errore CRLerror (errore durante il download della CRL)
	 * 
	 * @return String
	 */
	public String getCRLerror() {

		return CRLerror;
	}

	public String getCertPathError() {
		return certPathError;
	}

	/**
	 * Checks certification path by IssuerX500Principal keyed in CAroot<br>
	 * <br>
	 * risale il certification path attraverso IssuerX500Principal chiave in
	 * CAroot
	 * 
	 * @return boolean
	 */
	public boolean isPathValid() {

		return cv.isPathValid();
	}

	public boolean isRevoked() {

		return cv.isRevoked();
	}

	public boolean isExpired() {

		return cv.getExpired();
	}

	public boolean isInUse() {

		return cv.getInUse();
	}

	public boolean isPassed() {

		return passed;
	}

	public boolean isDownloadCRLForced() {

		return crlDownloadForced;
	}

	/**
	 * Checks if CRL is already been checked<br>
	 * <br>
	 * True se la CRL è stata verificata
	 * 
	 * @return boolean
	 */
	public boolean isCRLChecked() {

		return cv.isCRLChecked();
	}

	public void setPassed(boolean b) {
		passed = b;
	}

	/**
	 * Creates the base64 encoding of a byte array.
	 * 
	 * @param bytes
	 *            byte[]
	 * @return java.lang.String
	 */
	public String encodeFromBytes(byte[] bytes) {

		String encString = new String(Base64.encode(bytes));

		return encString;
	}

	/**
	 * Return signed content Ritorna il contenuto firmato (la firma)
	 * 
	 * @return byte[]
	 */
	byte[] getRawBytes() {
		return (byte[]) cms.getSignedContent().getContent();
	}

	public boolean mandatoryAuthenticatedAttributesPresent() {
		return contentTypeDataPresent && messageDigestPresent;
	}

	public Date getSigningTime() {
		return signingTime;
	}

	public boolean getKeyUsageNonRepudiationAloneCritical() {

		boolean isNonRepudiationPresent = false;
		boolean isKeyUsageCritical = false;
		boolean isNonRepudiationAlone = false;

		Set<String> oids = cert.getCriticalExtensionOIDs();
		if (oids != null) {
			// check presence between critical extensions of oid:2.5.29.15
			// (KeyUsage)
			isKeyUsageCritical = oids.contains("2.5.29.15");
		}

		boolean[] keyUsages = cert.getKeyUsage();
		if (keyUsages != null) {
			// check non repudiation (index 1)
			isNonRepudiationPresent = keyUsages[1];

			// check if non repudiation is alone
			int i = 0;
			do {
				if (i != 1)
					isNonRepudiationAlone = !keyUsages[i];
				i++;
			} while (i < keyUsages.length && isNonRepudiationAlone);

		}
		this.keyUsageNonRepudiationAloneCritical = isKeyUsageCritical
				&& isNonRepudiationPresent && isNonRepudiationAlone;

		return keyUsageNonRepudiationAloneCritical;

	}

	public boolean isKeyUsageNonRepudiationAloneCritical() {
		return keyUsageNonRepudiationAloneCritical;
	}

	public boolean getCAdES() {

		AttributeTable attrs = signer.getSignedAttributes();
		if (attrs != null) {
			Attribute signingCertificateV2 = attrs
					.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);

			this.cades = (signingCertificateV2 != null);
		}

		return cades;
	}

	public boolean getEncryptionRSA() {

		this.encryptionRSA = CMSSignedDataGenerator.ENCRYPTION_RSA
				.equals(signer.getEncryptionAlgOID());

		return encryptionRSA;
	}

	public boolean getHashingSHA256() {

		this.hashingSHA256 = CMSSignedDataGenerator.DIGEST_SHA256.equals(signer
				.getDigestAlgOID());

		return hashingSHA256;
	}

	public boolean isCades() {
		return cades;
	}

	public String getSigningAlgorithmName() {
		return signingAlgorithmName;
	}

	public boolean isEncryptionRSA() {
		return encryptionRSA;
	}

	public boolean isHashingSHA256() {
		return hashingSHA256;
	}

	public boolean isMandatoryAuthenticatedAttributesPresent() {
		return contentTypeDataPresent && messageDigestPresent;
	}

	public boolean isQcStatementsPresent() {
		return cv.getHasQcStatements();
	}

	public Collection<String> getQcStatementStrings() {
		return cv.getQcStatementsStrings();
	}

}
