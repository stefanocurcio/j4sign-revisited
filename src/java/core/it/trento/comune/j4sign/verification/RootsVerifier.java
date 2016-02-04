/**
 *	verifica-firma - a simple web application for verifying CMS/PKCS7 signed files
 *  Copyright (c) 2009 Roberto Resoli - Comune di Trento;
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



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import java.util.logging.Logger;

import javax.swing.JOptionPane;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

public class RootsVerifier {

	private Logger log = Logger.getLogger(this.getClass().getName());

	private CertificationAuthorities roots = null;

	//private Configuration conf = null;
	private Properties conf = null;

	private static RootsVerifier instance = null;

	private String confDir = null;

	private File crlDir = null;

	private String CNIPADir = null;

	private String CAFilePath = null;

	private String CNIPACACertFilePath = null;

	private byte[] userApprovedFingerprint = null;

	public static RootsVerifier getInstance(String confDir, byte[] fingerprint) {
		if (instance == null) {
			try {
				instance = new RootsVerifier(confDir, fingerprint);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return instance;
	}

	private RootsVerifier(String aConfDir, byte[] fingerprint)
			throws FileNotFoundException, IOException {

		this.confDir = aConfDir;
		//this.conf = new PropertiesConfiguration(aConfDir
		//		+ System.getProperty("file.separator") + "conf.properties");
		
		this.conf = new Properties();
				
		conf.load(new FileInputStream(aConfDir + System.getProperty("file.separator") + "conf.properties"));

		init();
		this.userApprovedFingerprint = fingerprint;

	}

	public File getCrlDir() {
		return crlDir;
	}

	public void setCrlDir(File crlDir) {
		this.crlDir = crlDir;
	}

	private void init() {

		this.CNIPADir = this.confDir + System.getProperty("file.separator")
				+ conf.getProperty("cnipa.dir")
				+ System.getProperty("file.separator");

		this.CAFilePath = CNIPADir + conf.getProperty("cnipa.roots");

		this.CNIPACACertFilePath = CNIPADir + conf.getProperty("cnipa.ca");
	}

	/*
	 * private byte[] getFingerprint() {
	 * 
	 * byte[] fingerprint = null;
	 * 
	 * CertStore certs = null; CMSSignedData CNIPA_CMS = null; try {
	 * 
	 * CNIPA_CMS = getCNIPA_CMS();
	 * 
	 * } catch (FileNotFoundException ex) {
	 * log.severe("Errore nella lettura del file delle RootCA: " + ex); } catch
	 * (CMSException e) { // TODO Auto-generated catch block
	 * log.severe("Errore nel CMS delle RootCA: " + e); }
	 * 
	 * Provider p = new org.bouncycastle.jce.provider.BouncyCastleProvider(); if
	 * (Security.getProvider(p.getName()) == null) Security.addProvider(p);
	 * 
	 * try { certs = CNIPA_CMS.getCertificatesAndCRLs("Collection", "BC"); }
	 * catch (CMSException ex2) { log.severe("Errore nel CMS delle RootCA"); }
	 * catch (NoSuchProviderException ex2) {
	 * log.severe("Non esiste il provider del servizio"); } catch
	 * (NoSuchAlgorithmException ex2) { log.severe("Errore nell'algoritmo"); }
	 * 
	 * if (certs == null) log.severe("No certs for CNIPA signature!"); else {
	 * SignerInformationStore signers = CNIPA_CMS.getSignerInfos(); Collection c
	 * = signers.getSigners(); if (c.size() != 1) {
	 * log.severe("There is not exactly one signer!"); } else {
	 * 
	 * Iterator it = c.iterator();
	 * 
	 * if (it.hasNext()) { SignerInformation signer = (SignerInformation)
	 * it.next(); Collection certCollection = null; try { certCollection =
	 * certs.getCertificates(signer.getSID());
	 * 
	 * if (certCollection.size() == 1) { fingerprint =
	 * getCertFingerprint((X509Certificate) certCollection .toArray()[0]); }
	 * else log.severe("There is not exactly one certificate for this signer!");
	 * 
	 * } catch (CertStoreException ex1) { log.severe("Errore nel CertStore"); }
	 * } } }
	 * 
	 * 
	 * return fingerprint; }
	 */

	public static String formatAsGUString(byte[] bytes) {
		int n, x;
		String w = new String();
		String s = new String();

		boolean separe = false;

		for (n = 0; n < bytes.length; n++) {
			x = (int) (0x000000FF & bytes[n]);
			w = Integer.toHexString(x).toUpperCase();
			if (w.length() == 1)
				w = "0" + w;
			// Group 2 consecutive bytes
			separe = (((n + 1) % 2) == 0) && (n + 1 != bytes.length);

			s = s + w + (separe ? " " : "");

		} // for
		return s;
	}

	private byte[] getBytesFromPath(String fileName) throws IOException {

		byte[] risultato = null;

		try {
			byte[] buffer = new byte[1024];
			FileInputStream fis = new FileInputStream(fileName);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int bytesRead = 0;
			while ((bytesRead = fis.read(buffer, 0, buffer.length)) >= 0) {
				baos.write(buffer, 0, bytesRead);
			}
			fis.close();
			risultato = baos.toByteArray();

		} catch (IOException ioe) {

			throw ioe;
		}
		return risultato;
	}

	private CMSSignedData getCNIPA_CMS() throws CMSException,
			FileNotFoundException {

		FileInputStream is = null;

		is = new FileInputStream(CAFilePath);

		return new CMSSignedData(is);
	}

	public CertificationAuthorities getRoots() throws GeneralSecurityException,
			IOException {

		if (this.roots == null)

			if (verify(true))
				this.roots = new CertificationAuthorities(
						getCmsInputStream(this.CAFilePath), true);
			else
				log.severe("Verifica del file CNIPA delle root CA fallita!");

		else if (!verify(false)) {
			this.roots = null;
			log.severe("Verifica del file CNIPA delle root CA fallita!");
		}

		return this.roots;
	}

	/*
	 * public void loadRoots() throws GeneralSecurityException, IOException {
	 * 
	 * CertificationAuthorities loadedRoots = null;
	 * 
	 * if (verify(true)) {
	 * 
	 * loadedRoots = new CertificationAuthorities(
	 * getCmsInputStream(this.CAFilePath), true);
	 * 
	 * } else {
	 * 
	 * log.severe("Verifica del file CNIPA delle root CA fallita!");
	 * 
	 * }
	 * 
	 * this.roots = loadedRoots;
	 * 
	 * }
	 */
	private boolean verify(boolean forceCRLDownload) {

		String error = null;
		boolean rootsOk = false;

		log.info("Starting root certificates verification.");

		try {

			CertificationAuthorities CNIPARoot = new CertificationAuthorities();
			try {
				CNIPARoot.addCertificateAuthority(CNIPARoot
						.getBytesFromPath(this.CNIPACACertFilePath));
			} catch (GeneralSecurityException e) {
				log.severe("Errore nell'inizializzazione della CA CNIPA: " + e);
			}

			Store certs = null;

			CMSSignedData CNIPA_CMS = null;
			try {

				CNIPA_CMS = getCNIPA_CMS();

			} catch (FileNotFoundException ex) {
				log.severe("Errore nell'acquisizione del file: " + ex);
			}

			Provider p = new org.bouncycastle.jce.provider.BouncyCastleProvider();
			if (Security.getProvider(p.getName()) == null)
				Security.addProvider(p);

			certs = CNIPA_CMS.getCertificates();

			if (certs != null) {
				SignerInformationStore signers = CNIPA_CMS.getSignerInfos();
				Collection c = signers.getSigners();

				log.info(c.size() + " signers found.");

				Iterator it = c.iterator();

				// ciclo tra tutti i firmatari
				int i = 0;
				while (it.hasNext()) {
					SignerInformation signer = (SignerInformation) it.next();
					Collection certCollection = null;
					try {
						certCollection = certs.getMatches(signer.getSID());
					} catch (StoreException ex1) {
						log.severe("CertStore error: " + ex1);
					}

					if (certCollection.size() == 1) {

						X509CertificateHolder ch = (X509CertificateHolder) certCollection
								.toArray()[0];

						byte[] signerFingerprint = getCertFingerprint(ch
								.getEncoded());

						log.info("Signer fingerprint: "
								+ formatAsGUString(signerFingerprint));

						if (Arrays.equals(signerFingerprint,
								this.userApprovedFingerprint)) {

							// get Certificate
							java.security.cert.X509Certificate cert = null;
							try {

								cert = new JcaX509CertificateConverter()
										.setProvider("BC").getCertificate(ch);

								VerifyResult vr = new VerifyResult(this.conf, certs, cert,
										CNIPA_CMS, CNIPARoot, signer, false,
										forceCRLDownload, false, getCrlDir());

								// rootsOk = vr.getPassed_cnipasigner_expired();
								rootsOk = vr.getPassed();
								error = vr.getCRLerror();

							} catch (CertificateException e) {
								log.severe("Certificate error:"
										+ e.getMessage());
							}

						} else
							log.severe("Signer cert has wrong fingerprint!");
					} else
						log.severe("There is not exactly one certificate for this signer!");

					i++;
				}

			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.severe(e.getMessage());
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			log.severe(e.getMessage());
		}

		return rootsOk;

	}

	public Properties getConf() {
		return conf;
	}

	private byte[] getCertFingerprint(byte[] certBytes) {
		MessageDigest md;
		byte[] fingerprint = null;
		try {

			md = MessageDigest.getInstance("SHA1");
			md.update(certBytes);

			fingerprint = md.digest();

		} catch (NoSuchAlgorithmException e) {
			log.severe(e.getMessage());
		}

		return fingerprint;
	}

	public byte[] getUserApprovedFingerprint() {
		return userApprovedFingerprint;
	}

	// ROB duplicato del metodo in VerifyTask ...
	private InputStream getCmsInputStream(String path) {

		FileInputStream is = null;
		try {
			is = new FileInputStream(path);
		} catch (FileNotFoundException ex) {
			log.severe("Errore nell'acquisizione del file: " + ex);
		}
		ByteArrayInputStream bais = null;
		try {
			CMSSignedData cms = new CMSSignedData(is);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			cms.getSignedContent().write(baos);
			bais = new ByteArrayInputStream(baos.toByteArray());
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return bais;

	}

}
