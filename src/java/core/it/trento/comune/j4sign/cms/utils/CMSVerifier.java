/**
 *	j4sign - an open, multi-platform digital signature solution
 *	Copyright (c) 2014 Roberto Resoli - Servizio Sistema Informativo, Comune di Trento.
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
package it.trento.comune.j4sign.cms.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

/**
 * An helper class for doing a basic verification of CMS files.
 * <p>
 * No CRL checking nor certificate chain check is performed; {@link CMSVerifier#basicVerify()} 
 * does integrity check only and verifies that signer certificate is into its time validity range.<br/>
 * Authenticated attributes are parsed and sent to standard output.
 * </p>
 * 
 */
public class CMSVerifier implements Serializable {

	private static final long serialVersionUID = 6421041758448327199L;

	private boolean debug = false;

	public boolean isDebug() {
		return debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	private CMSSignedData cmsSignedData = null;
	private String signerDN;
	private String notAfter;
	private String notBefore;
	private boolean validNotExpired = false;
	private boolean integrityChecked = false;
	private Date signingTime = null;

	public String getSignerDN() {
		return signerDN;
	}

	public String getNotAfter() {
		return notAfter;
	}

	public String getNotBefore() {
		return notBefore;
	}

	public boolean isValidNotExpired() {
		return validNotExpired;
	}

	public boolean isIntegrityChecked() {
		return integrityChecked;
	}

	public CMSVerifier(InputStream signedDataStream) {

		try {

			this.cmsSignedData = new CMSSignedData(signedDataStream);

		} catch (CMSException e) {
			if (debug)
				System.out.println("Dati firmati non corretti: "
						+ e.getMessage());
		}
	}

	public CMSVerifier(CMSSignedData signedData) {

		this.cmsSignedData = signedData;

	}

	private void addBCProvider() {
		if (java.security.Security.getProvider("BC") == null) {
			if (debug)
				System.out.println("Adding \"BC\" provider.");
			Security.insertProviderAt(new BouncyCastleProvider(), 2);
			// iaik.security.provider.IAIK.addAsProvider(true);
			if (debug)
				System.out.println("BC provider added.");
		}
	}
	
	
	public void basicVerify() {

		addBCProvider();

		SimpleDateFormat df = new SimpleDateFormat("dd MMMMM yyyy HH:mm:ss z");

		try {

			Store certs = this.cmsSignedData.getCertificates();

			// Recupero i firmatari.
			SignerInformationStore signerStore = this.cmsSignedData
					.getSignerInfos();


			Collection<SignerInformation> c = signerStore.getSigners();

			if (debug)
				System.out.println(c.size() + " firmatari diversi trovati");

			Iterator<SignerInformation> it = c.iterator();

			// ciclo tra tutti i firmatari
			int i = 0;
			X509Certificate cert = null;

			while (it.hasNext()) {

				SignerInformation signer = it.next();

				Collection<?> certCollection = null;

				try {
					certCollection = certs.getMatches(signer.getSID());
				} catch (StoreException ex1) {
					System.out.println("Errore nel CertStore");
				}

				if (certCollection.size() == 1) {

					X509CertificateHolder ch = (X509CertificateHolder) certCollection
							.toArray()[0];

					try {
						// get Certificate
						cert = new JcaX509CertificateConverter().setProvider(
								"BC").getCertificate(ch);
						if (debug)
							System.out.println(i
									+ ") Verifiying signature from:\n"
									+ cert.getSubjectDN());

						this.signerDN = cert.getSubjectDN().toString();

						if (debug)
							System.out.println("Certificato valido fino a "
									+ cert.getNotAfter());

						this.notBefore = df.format(cert.getNotBefore());

						this.notAfter = df.format(cert.getNotAfter());

						cert.checkValidity();
						this.validNotExpired = true;

					} catch (CertificateExpiredException ex) {
						if (debug)
							System.out.println("Certificato scaduto il "
									+ cert.getNotAfter());

					} catch (CertificateNotYetValidException ex) {
						if (debug)
							System.out
									.println("Certificato non ancora valido. Valido da "
											+ cert.getNotBefore());
					} catch (CertificateException e) {
						if (debug)
							System.out.println("Errore Certificato  ");
					}

					// VERIFICA INTEGRITA' (passando il certificato)
					// verify that the given certificate successfully handles
					// and confirms the signature associated with this signer
					// and, if a signingTime attribute is available, that the
					// certificate was valid at the time the signature was
					// generated.

					// try {
					// ROB: faccio solo controllo integrità -> passo solo la
					// chiave pubblica.

					if (signer
							.verify(new JcaSimpleSignerInfoVerifierBuilder()
									.build(new X509CertificateHolder(cert
											.getEncoded())))) {

						if (debug)
							System.out.println("Firma " + i + " integra.");

						this.integrityChecked = true;

					} else {
						if (debug)
							System.err.println("Firma " + i + " non integra!");
					}
					
					parseAuthenticatedAttributes(signer);
					
					/*
					 * } catch (CertificateExpiredException e) {
					 * System.out.println("Certificato per la Firma " + i +
					 * " scaduto."); } catch (CertificateNotYetValidException e)
					 * { System.out.println("Certificato per la Firma " + i +
					 * " non ancora valido."); }
					 */

				} else {
					if (debug)
						System.out
								.println("There is not exactly one certificate for this signer!");
				}
				i++;
			}

		} catch (CMSException e) {
			if (debug)
				System.out.println("Dati firmati non corretti: "
						+ e.getMessage());
		} catch (CertificateEncodingException e) {
			if (debug)
				System.out.println("Encoding certificato non corretto: "
						+ e.getMessage());
		} catch (OperatorCreationException e) {
			if (debug)
				System.out.println(e.getMessage());
		} catch (CertificateException e) {
			if (debug)
				System.out.println("Errore nel certificato: " + e.getMessage());
		} catch (IOException e) {
			if (debug)
				System.out.println(e.getMessage());
		}

	}

	private void parseAuthenticatedAttributes(SignerInformation signer) {
		AttributeTable attr = signer.getSignedAttributes();

		Iterator<Attribute> iter = attr.toHashtable().values().iterator();

		if (debug)
			System.out.println("Listing authenticated attributes:");
		int count = 1;
		while (iter.hasNext()) {
			Attribute a = iter.next();

			if (debug)
				System.out.println("Attribute " + count + ":");
			if (a.getAttrType().getId()
					.equals(CMSAttributes.signingTime.getId())) {
				Time time = Time.getInstance(a.getAttrValues().getObjectAt(0));
				if (debug)
					System.out.println("Authenticated time: " + time.getDate());

				this.signingTime = time.getDate();
			}
			if (a.getAttrType().getId()
					.equals(CMSAttributes.contentType.getId())) {
				if (CMSObjectIdentifiers.data.getId().equals(
						DERObjectIdentifier.getInstance(
								a.getAttrValues().getObjectAt(0)).getId()))
					if (debug)
						System.out.println("Content Type: PKCS7_DATA");
			}
			if (a.getAttrType().getId()
					.equals(CMSAttributes.messageDigest.getId())) {
				byte[] md = DEROctetString.getInstance(
						a.getAttrValues().getObjectAt(0)).getOctets();
				if (debug)
					System.out
							.println("Message Digest (hash of data content):\n"
									+ CMSBuilder.formatAsString(md, " ", 16));
			}
			if (debug)
				System.out.println("\nAttribute dump follows:");
			if (debug)
				System.out.println(ASN1Dump.dumpAsString(a) + "\n");

			count++;
		}

	}

	public CMSSignedData getCmsSignedData() {
		return cmsSignedData;
	}

	public String getSigningTimeAsString() {
		SimpleDateFormat df = new SimpleDateFormat("dd MMMMM yyyy HH:mm:ss z");

		if (this.signingTime != null)
			return df.format(this.signingTime);

		return "";

	}

	public Date getSigningTime() {

		return signingTime;

	}

	public byte[] getCMSContent() {

		byte[] content = null;

		content = (byte[]) this.cmsSignedData.getSignedContent().getContent();

		return content;

	}

}
