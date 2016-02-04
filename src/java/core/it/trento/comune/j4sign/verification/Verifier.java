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

import it.trento.comune.j4sign.verification.CertificationAuthorities;
import it.trento.comune.j4sign.verification.RootsVerifier;
import it.trento.comune.j4sign.verification.VerifyResult;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.util.encoders.Base64;

public class Verifier {
	private Logger log = Logger.getLogger(this.getClass().getName());

	private CertificationAuthorities CAroot;

	private boolean done;

	private boolean canceled;

	private ArrayList<X500Principal> signersList;

	private Iterator<SignerInformation> currentSigner;

	private CMSSignedData cms;

	private Vector<VerifyResult> risultati;

	private Vector<String> errors = new Vector<String>();

	private boolean isDownloadCRLForced;

	private RootsVerifier rootsVerifier = null;

	private File crlDir = null;

	private Properties conf = null;

	public Verifier(boolean isDownloadCRLForced, RootsVerifier rv)
			throws Exception {

		signersList = new ArrayList<X500Principal>();
		this.isDownloadCRLForced = isDownloadCRLForced;
		this.rootsVerifier = rv;
		this.conf = rootsVerifier.getConf();

	}

	public Verifier(String filePath, boolean isDownloadCRLForced,
			RootsVerifier rv) throws Exception {

		this(isDownloadCRLForced, rv);

		try {

			CMSSignedData aCms = buildCmsFromFile(filePath);
			setCms(aCms);

		} catch (CMSException e) {
			log.severe("Errore: il file non è una busta crittografica  CMS: "
					+ e.getMessage());
			errors.add("Errore: il file non è una busta crittografica  CMS.");
		} catch (IOException e) {
			log.severe("Errore di IO nell'accesso al file: " + e.getMessage());
			errors.add("Errore di IO nell'accesso al file");
		} catch (Exception e) {
			log.severe("Errore: " + e.getMessage());
			errors.add("Errore: " + e.getMessage());
		}

		init();

	}

	public Verifier(CMSSignedData cms, boolean isDownloadCRLForced,
			RootsVerifier rv) throws Exception {

		this(isDownloadCRLForced, rv);

		setCms(cms);
		
		init();

	}

	private void init() throws Exception {
		
		initCARoots();

		if (CAroot != null) {
			risultati = new Vector<VerifyResult>();
		}
	}
	
	public CMSSignedData getCms() {
		return cms;
	}

	private void setCms(CMSSignedData aCms) {

		this.cms = aCms;

		if (errors.isEmpty() && (cms != null)) {
			org.bouncycastle.jce.provider.BouncyCastleProvider p = new org.bouncycastle.jce.provider.BouncyCastleProvider();
			if (Security.getProvider(p.getName()) == null)
				Security.addProvider(p);

			// Recupero i firmatari.
			SignerInformationStore signers = cms.getSignerInfos();

			Collection c = signers.getSigners();

			// non avrebbe senso che fossero uguali
			// quindi fa il ciclo tra i firmatari
			// PERO' PUO' CAPITARE CHE CI SIA UN FIRMATARIO CHE FIRMA DUE VOLTE
			// E IN QUESTO CASO DOVREBBE FARE IL GIRO SUI CERTIFICATI!!!
			currentSigner = c.iterator();
			if (!currentSigner.hasNext()) {
				done = true;
			}
		} else {
			canceled = true;
		}
	}

	public File getCrlDir() {
		return crlDir;
	}

	public void setCrlDir(File crlDir) {
		this.crlDir = crlDir;
	}

	public boolean isCanceled() {
		return canceled;
	}

	public void initCARoots() throws Exception {
		try {
			CAroot = this.rootsVerifier.getRoots();
		} catch (Exception ex) {
			log.severe("Errore nell'inizializzazione delle CA: " + ex);
			errors.add("Errore nell'inizializzazione delle CA: " + ex);
			throw (new Exception(ex));
		}
		if (CAroot == null)
			throw (new Exception("Errore nell'inizializzazione delle CA"));
	}

	public Vector<String> getErrors() {
		return errors;
	}

	public static CMSSignedData buildCmsFromStream(InputStream is)
			throws CMSException, IOException {

		CMSSignedData aCms = null;

		aCms = new CMSSignedData(is);

		return aCms;
	}

	public static CMSSignedData buildCmsFromFile(String filepath)
			throws IOException, CMSException {

		CMSSignedData aCms = null;

		FileInputStream is = new FileInputStream(filepath);

		// Try to build object directly from file stream
		// (it's going to work if file is DER encoded)
		try {
			aCms = buildCmsFromStream(is);

		} catch (CMSException ex1) {
			// Not a DER encoding ...

			if (is != null)
				is.close();

			if (aCms == null) {
				// Try with PEM decoding
				try {
					FileReader r = new FileReader(filepath);
					PEMReader pr = new PEMReader(r);
					ContentInfo ci = (ContentInfo) pr.readObject();
					r.close();
					pr.close();

					aCms = new CMSSignedData(ci);

				} catch (Exception ePEM) {
					// Trying (at last) raw base64 ...
					byte[] buffer = new byte[1024];

					is = new FileInputStream(filepath);

					ByteArrayOutputStream baos = new ByteArrayOutputStream();

					while (is.read(buffer) > 0) {
						baos.write(buffer);
					}

					byte[] signedBytes = Base64.decode(baos.toByteArray());
					aCms = new CMSSignedData(signedBytes);

					is.close();

				}

			}
		}

		return aCms;
	}

	public void verify() {

		org.bouncycastle.jce.provider.BouncyCastleProvider p = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		if (Security.getProvider(p.getName()) == null)
			Security.addProvider(p);

		Store certs = this.cms.getCertificates();

		if (certs != null) {
			SignerInformation signer = currentSigner.next();

			Collection<?> certCollection = null;

			try {
				certCollection = certs.getMatches(signer.getSID());
			} catch (StoreException ex1) {
				log.severe("Errore nel CertStore");
				errors.add("Errore nel CertStore");
			}

			if (certCollection.size() == 1) {
				// Iterator certIt = certCollection.iterator();
				// X509Certificate cert = (X509Certificate)
				// certIt.next();

				X509CertificateHolder ch = (X509CertificateHolder) certCollection
						.toArray()[0];

				// get Certificate
				java.security.cert.X509Certificate cert = null;
				try {
					cert = new JcaX509CertificateConverter().setProvider("BC")
							.getCertificate(ch);

					// inserisce in una lista i DN dei firmatari
					signersList.add(cert.getSubjectX500Principal());

					log.info("Signer CN: " + getCommonName(cert));

					VerifyResult vr = new VerifyResult(conf, certs, cert, cms,
							CAroot, signer, false, isDownloadCRLForced, true,
							getCrlDir());

					// do verification!!!
					vr.getPassed();

					risultati.add(vr);

				} catch (CertificateException e) {
					log.severe("Certificate error:" + e.getMessage());
				}

			} else {
				log.severe("There is not exactly one certificate for this signer!");
				errors.add("There is not exactly one certificate for this signer!");
			}
			if (!currentSigner.hasNext()) {
				done = true;
			}

		}

	}

	public boolean isDone() {
		return done;
	}

	/**
	 * Returns the Common name of given certificate<br>
	 * <br>
	 * Restituisce il CN del subjct certificato in oggetto
	 * 
	 * @param userCert
	 *            certificato da cui estrarre il Common Name
	 * @return la stringa contenente il CN
	 */
	public static String getCommonName(X509Certificate userCert) {
		String DN = userCert.getSubjectDN().toString();
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

	byte[] getFile() {
		return (byte[]) cms.getSignedContent().getContent();
	}

	public Vector<VerifyResult> getRisultati() {
		return risultati;
	}



}
