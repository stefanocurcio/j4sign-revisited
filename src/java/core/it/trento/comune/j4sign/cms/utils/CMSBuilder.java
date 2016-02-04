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

import it.trento.comune.j4sign.cms.ExternalSignatureCMSSignedDataGenerator;
import it.trento.comune.j4sign.cms.ExternalSignatureSignerInfoGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.SimpleTimeZone;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.NoSuchStoreException;
import org.bouncycastle.x509.X509Store;

/**
 * An helper class for generating CMS files, following CAdES specification,
 * where encryption is done elsewhere.
 * <p>
 * CMSBuilder takes care of:
 * <ul>
 * <li>Generating data to be signed, and streaming content to be signed, in a
 * synchronized way.</li>
 * <li>Receiving raw signature and building the corresponding CMS envelope.</li>
 * </ul>
 * </p>
 * 
 */
public class CMSBuilder implements Serializable {

	private static int WRAP_AFTER = 16;

	private ExternalSignatureSignerInfoGenerator infoGen = null;
	private String digestAlgorithm = null;
	private String encryptionAlgorithm = null;

	private byte[] dataHash = null;
	private String dataPath = null;

	private byte[] streamHash = null;

	private byte[] certBytes = null;

	private String encodedDigest = null;

	private Date signingTime = null;

	private String dataContentType = null;

	private String dataFileName = null;

	public CMSBuilder(String digestAlgorithm, String encryptionAlgorithm) {
		super();

		initializeInfoGen(digestAlgorithm, encryptionAlgorithm);

	}

	public CMSBuilder(InputStream dataStream, String digestAlgorithm,
			String encryptionAlgorithm) throws IOException,
			NoSuchAlgorithmException {
		super();

		initializeInfoGen(digestAlgorithm, encryptionAlgorithm);

		// Calcolo dataHash
		initializeDataHash(dataStream);

	}

	public CMSBuilder(byte[] docHash, String digestAlgorithm,
			String encryptionAlgorithm) throws IOException,
			NoSuchAlgorithmException {
		super();

		initializeInfoGen(digestAlgorithm, encryptionAlgorithm);

		this.dataHash = docHash;

	}

	/**
	 * Calculates the content data hash.
	 * 
	 * <p>
	 * All subsequent content related calculation, such as in
	 * {@link #updateEncodedDigest()} method, will keep this value as integrity
	 * reference.
	 * </p>
	 * 
	 * @param dataStream
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public void initializeDataHash(InputStream dataStream)
			throws NoSuchAlgorithmException, IOException {

		this.dataHash = hashContent(dataStream);

		this.streamHash = null;

		dataStream.close();
	}

	private void initializeInfoGen(String digestAlgorithm,
			String encryptionAlgorithm) {

		this.digestAlgorithm = digestAlgorithm;
		this.encryptionAlgorithm = encryptionAlgorithm;

		if (java.security.Security.getProvider("BC") == null) {
			System.out.println("Adding BC provider as second...(to avoid JDK 1.4 bug).");

			Security.insertProviderAt(new BouncyCastleProvider(), 2);

			System.out.println("BC provider added.");
		}

		System.out.println("Building SignerInfoGenerator.");
		this.infoGen = new ExternalSignatureSignerInfoGenerator(
				this.digestAlgorithm, this.encryptionAlgorithm);

	}

	/**
	 * Triggers encoded digest recalculation.
	 * <p>
	 * Invokes the private <code>getAuthenticatedAttributesBytes()</code> method
	 * obtaining the raw digest, encapsulates it in a <code>digestInfo</code>
	 * structure, finally encoding the result in <code>base64</code>.
	 * </p>
	 * 
	 * @return the <code>base64</code> encoding of the data to be signed.
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public String updateEncodedDigest() throws NoSuchAlgorithmException,
			IOException {

		String ed = null;

		byte[] bytesToSign = getAuthenticatedAttributesBytes();

		byte[] rawDigest = null;
		byte[] dInfoBytes = null;

		if (bytesToSign != null) {
			rawDigest = applyDigest(digestAlgorithm, bytesToSign);

			System.out.println("Raw digest bytes:\n"
					+ formatAsString(rawDigest, " ", WRAP_AFTER));

			System.out.println("Encapsulating in a DigestInfo...");

			dInfoBytes = encapsulateInDigestInfo(digestAlgorithm, rawDigest);

			System.out.println("DigestInfo bytes:\n"
					+ formatAsString(dInfoBytes, " ", WRAP_AFTER));

			ed = new String(Base64.encode(dInfoBytes));

			this.encodedDigest = ed;
		}

		return ed;
	}

	private byte[] applyDigest(String digestAlg, byte[] bytes)
			throws NoSuchAlgorithmException {

		System.out.println("Applying digest algorithm...");
		MessageDigest md = MessageDigest.getInstance(this.digestAlgorithm);
		md.update(bytes);

		return md.digest();
	}

	private byte[] encapsulateInDigestInfo(String digestAlg, byte[] digestBytes)
			throws IOException {

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		DEROutputStream dOut = new DEROutputStream(bOut);

		DERObjectIdentifier digestObjId = new DERObjectIdentifier(digestAlg);
		AlgorithmIdentifier algId = new AlgorithmIdentifier(digestObjId, null);
		DigestInfo dInfo = new DigestInfo(algId, digestBytes);

		dOut.writeObject(dInfo);

		return bOut.toByteArray();

	}

	private byte[] applyPkcs1Padding(int resultLength, byte[] srcBytes) {

		int paddingLength = resultLength - srcBytes.length;

		byte[] dstBytes = new byte[resultLength];

		dstBytes[0] = 0x00;
		dstBytes[1] = 0x01;
		for (int i = 2; i < (paddingLength - 1); i++) {
			dstBytes[i] = (byte) 0xFF;
		}
		dstBytes[paddingLength - 1] = 0x00;
		for (int i = 0; i < srcBytes.length; i++) {
			dstBytes[paddingLength + i] = srcBytes[i];
		}
		return dstBytes;
	}

	/**
	 * 
	 * Calculates data to be signed.
	 * <p>
	 * Builds the CMS authenticated attributes; ContentType and MessageDigest
	 * are mandatory, optional SigningTime (taken from current system time) is
	 * added by default. This method waits for the completion of the
	 * synchronized {@link streamAndHashContent} method, so that bytes to sign
	 * is returned only when the streamed content is identical to the original
	 * one.
	 * </p>
	 * 
	 * @return the byte[] containing the calculated authenticated attributes;
	 */
	private synchronized byte[] getAuthenticatedAttributesBytes() {

		System.out.println("Building AuthenticatedAttributes from content.");
		byte[] bytesToSign = null;

		long timeout = 10000;

		try {

			long millisBefore = System.currentTimeMillis();
			long millisWaited = 0;

			if (this.streamHash == null) {

				System.out.println("getAuthenticatedAttributesBytes: Thread '"
						+ Thread.currentThread().getName()
						+ "' starts waiting; timeout " + timeout + " ms.");

				/*
				 * // Notify streamAndHashContent System.out
				 * .println("getAuthenticatedAttributesBytes: Thread '" +
				 * Thread.currentThread().getName() + "' issues notify.");
				 * notify();
				 */

				wait(timeout);

				millisWaited = System.currentTimeMillis() - millisBefore;

				if (millisWaited < timeout)
					System.out
							.println("getAuthenticatedAttributesBytes: Thread '"
									+ Thread.currentThread().getName()
									+ "' waited: " + millisWaited + "ms");
				else
					System.out
							.println("getAuthenticatedAttributesBytes: Thread '"
									+ Thread.currentThread().getName()
									+ " "
									+ timeout + "ms timeout expired!");

			}

			if (this.streamHash != null) {

				if (Arrays.equals(this.streamHash, this.dataHash)) {

					this.signingTime = new Date();

					bytesToSign = this.infoGen.getBytesToSign(
							PKCSObjectIdentifiers.data, this.dataHash,
							this.signingTime, "BC");

					this.streamHash = null;

				} else
					System.out
							.println("getAuthenticatedAttributesBytes: Error - stream Hash is different from data Hash");
			} else
				System.out
						.println("getAuthenticatedAttributesBytes: Error - stream Hash is null!!!");

		} catch (Exception e) {
			System.out.println("getAuthenticatedAttributesBytes: Error - " + e);
		}

		if (bytesToSign != null) {

			StringWriter printout = new StringWriter();
			PrintWriter pw = new PrintWriter(printout);

			// Now signingTime is explicitly set in getBytesToSign(), see above
			// this.signingTime = parseSigningTime(bytesToSign, pw);

			// System.out.println(printout);
		}

		return bytesToSign;
	}

	public String getSigningTimeAsString() {
		SimpleDateFormat df = new SimpleDateFormat("dd MMMMM yyyy HH:mm:ss z");

		if (this.signingTime != null)
			return df.format(this.signingTime);

		return "";

	}

	public String getEncodedGMTSigningTime() {

		if (this.signingTime != null) {
			SimpleDateFormat df = new SimpleDateFormat(
					"dd MMMMM yyyy HH:mm:ss z");

			Calendar cal = Calendar.getInstance(new SimpleTimeZone(0, "GMT"));
			df.setCalendar(cal);

			try {
				return new String(Base64.encode(df.format(this.signingTime)
						.getBytes("UTF-8")));
			} catch (UnsupportedEncodingException e) {
				System.out.println(e);
			}
		}
		return "";
	}

	private Date parseSigningTime(byte[] bytes, PrintWriter pw) {

		Date parsedSigningTime = null;

		try {

			ASN1InputStream aIn = new ASN1InputStream(bytes);
			ASN1Set signedAttributes = (ASN1Set) aIn.readObject();

			AttributeTable attr = new AttributeTable(signedAttributes);

			Iterator iter = attr.toHashtable().values().iterator();

			pw.println("Listing authenticated attributes:");
			int count = 1;
			while (iter.hasNext()) {
				Attribute a = (Attribute) iter.next();

				pw.println("Attribute " + count + ":");
				if (a.getAttrType().getId()
						.equals(CMSAttributes.signingTime.getId())) {
					Time time = Time.getInstance(a.getAttrValues().getObjectAt(
							0));
					pw.println("Authenticated time (SERVER local time): "
							+ time.getDate());

					parsedSigningTime = time.getDate();

				}
				if (a.getAttrType().getId()
						.equals(CMSAttributes.contentType.getId())) {
					if (CMSObjectIdentifiers.data.getId().equals(
							DERObjectIdentifier.getInstance(
									a.getAttrValues().getObjectAt(0)).getId()))
						pw.println("Content Type: PKCS7_DATA");
				}
				if (a.getAttrType().getId()
						.equals(CMSAttributes.messageDigest.getId())) {
					byte[] md = DEROctetString.getInstance(
							a.getAttrValues().getObjectAt(0)).getOctets();
					pw.println("Message Digest (hash of data content): "
							+ formatAsString(md, " ", 16));
				}
				pw.println("\nAttribute dump follows:");
				pw.println(ASN1Dump.dumpAsString(a) + "\n");

				count++;
			}
		} catch (Exception e) {
			pw.println(e);
			return null;
		}
		pw.flush();

		return parsedSigningTime;

	}

	public CMSSignedData buildCMSSignedData(InputStream contentStream,
			String encodedEcryptedDigest) throws NoSuchAlgorithmException,
			IOException {

		byte[] ecryptedDigestBytes = Base64.decode(encodedEcryptedDigest);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		streamAndHashContent(contentStream, baos);

		contentStream.close();
		baos.close();

		CMSSignedData sd = buildCMSSignedData(this.infoGen, baos.toByteArray(),
				ecryptedDigestBytes, this.certBytes);

		return sd;
	}

	public CMSSignedData buildCMSSignedData(InputStream contentStream,
			String encodedEcryptedDigest, String encodedCert)
			throws IOException, NoSuchAlgorithmException {

		byte[] ecryptedDigestBytes = Base64.decode(encodedEcryptedDigest);
		byte[] certBytes = Base64.decode(encodedCert);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		streamAndHashContent(contentStream, baos);

		contentStream.close();
		baos.close();

		CMSSignedData sd = buildCMSSignedData(this.infoGen, baos.toByteArray(),
				ecryptedDigestBytes, certBytes);

		return sd;
	}

	/*
	 * public CMSSignedData buildCMSSignedData(String encodedEcryptedDigest,
	 * String encodedCert) {
	 * 
	 * byte[] ecryptedDigestBytes = Base64.decode(encodedEcryptedDigest); byte[]
	 * certBytes = Base64.decode(encodedCert);
	 * 
	 * CMSSignedData sd = buildCMSSignedData(this.infoGen, this.data,
	 * ecryptedDigestBytes, certBytes);
	 * 
	 * return sd; }
	 */

	public CMSSignedData buildCMSSignedData(
			ExternalSignatureSignerInfoGenerator infoGen, byte[] data,
			byte[] sigBytes, byte[] certBytes) {

		CMSSignedData cms = null;

		System.out.println("building CMSSignedData.");

		try {
			CMSProcessable msg = new CMSProcessableByteArray(data);

			// Conterrà la lista dei certificati; come minimo dovrà
			// contenere i certificati dei firmatari; opzionale, ma
			// consigliabile,
			// l'aggiunta dei certificati root per completare le catene di
			// certificazione.
			ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();

			// get Certificate
			java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
					.getInstance("X.509");

			java.io.ByteArrayInputStream bais1 = new java.io.ByteArrayInputStream(
					certBytes);

			java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
					.generateCertificate(bais1);

			infoGen.setCertificate(javaCert);
			infoGen.setSignedBytes(sigBytes);

			certList.add(javaCert);

			// questa versione del generatore è priva della classe interna per
			// la generazione delle SignerInfo, che è stata promossa a classe a
			// sè.
			ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();

			gen.addSignerInf(infoGen);

			if (certList.size() != 0) {

				// Per passare i certificati al generatore li si incapsula in un
				// CertStore.
				CertStore store;

				store = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(certList), "BC");

				System.out.println("Adding certificates ... ");

				gen.addCertificatesAndCRLs(store);

				// Finalmente, si può creare il l'oggetto CMS.
				System.out.println("Generating CMSSignedData ");
				cms = gen.generate(msg, true);

			}
		} catch (CertificateException e) {
			System.out.println("Eccezione certificato: " + e);
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Algoritmo non valido: " + e);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algoritmo non trovato: " + e);
		} catch (NoSuchProviderException e) {
			System.out.println("Provider non trovato: " + e);
		} catch (CertStoreException e) {
			System.out.println("Eccezione CertStore: " + e);
		} catch (CMSException e) {
			System.out.println("Eccezione CMS: " + e);
		}
		return cms;
	}

	public static String formatAsString(byte[] bytes, String byteSeparator,
			int wrapAfter) {
		int n, x;
		String w = new String();
		String s = new String();

		String separator = null;

		for (n = 0; n < bytes.length; n++) {
			x = (int) (0x000000FF & bytes[n]);
			w = Integer.toHexString(x).toUpperCase();
			if (w.length() == 1)
				w = "0" + w;

			if ((n % wrapAfter) == (wrapAfter - 1))
				separator = "\n";
			else
				separator = byteSeparator;

			s = s + w + ((n + 1 == bytes.length) ? "" : separator);

		} // for
		return s;
	}

	public Date getSigningTime() {
		return signingTime;
	}

	public void setSigningTime(Date signingTime) {
		this.signingTime = signingTime;
	}

	public void setCertBytes(byte[] certBytes) {
		this.certBytes = certBytes;

		if (this.infoGen != null) {
			java.security.cert.CertificateFactory cf;

			try {
				cf = java.security.cert.CertificateFactory.getInstance("X.509");

				java.io.ByteArrayInputStream bais1 = new java.io.ByteArrayInputStream(
						certBytes);

				java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
						.generateCertificate(bais1);

				this.infoGen.setCertificate(javaCert);

			} catch (CertificateException e) {
				System.out.println("Eccezione certificato: " + e);
			}
		}
	}

	public void setCertBytes(String encodedCert) {
		setCertBytes(Base64.decode(encodedCert));
	}

	public String getEncodedDigest() {
		return encodedDigest;
	}

	public String getEncodedDataHash() {
		return new String(Base64.encode(this.dataHash));
	}

	/**
	 * Connects an input stream to an output stream hashing on the fly.
	 * <p>
	 * The calculated hash is saved in a private property. This method is
	 * synchronized with the private
	 * <code>getAuthenticatedAttributesBytes</code> (invoked by public
	 * {@link #updateEncodedDigest()}) which waits for its completion.
	 * </p>
	 * 
	 * @param in
	 *            The input stream the hash is calculated upon.
	 * @param out
	 *            The output stream.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public synchronized void streamAndHashContent(InputStream in,
			OutputStream out) throws IOException, NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance(this.digestAlgorithm);

		DigestInputStream dis = new DigestInputStream(in, md);
		/*
		 * // Certificate already set, wait for getAuthenticatedAttributesBytes
		 * // notify if (wait && this.certBytes != null) { long timeout = 10000;
		 * 
		 * long millisBefore = System.currentTimeMillis(); long millisWaited =
		 * 0;
		 * 
		 * try { System.out.println("streamAndHashContent: Thread '" +
		 * Thread.currentThread().getName() + "' starts waiting (timeout " +
		 * timeout + "ms).");
		 * 
		 * wait(timeout);
		 * 
		 * millisWaited = System.currentTimeMillis() - millisBefore;
		 * 
		 * if (millisWaited < timeout)
		 * System.out.println("streamAndHashContent: Thread '" +
		 * Thread.currentThread().getName() + "' waited: " + millisWaited +
		 * "ms"); else System.out.println("streamAndHashContent: Thread '" +
		 * Thread.currentThread().getName() + " " + timeout +
		 * "ms timeout expired!");
		 * 
		 * } catch (InterruptedException e) {
		 * System.out.println("streamAndHashContent: Error, " + e.getMessage());
		 * }
		 * 
		 * }
		 */
		int bytesRead = 0;
		byte[] buffer = new byte[1024];
		while ((bytesRead = dis.read(buffer, 0, buffer.length)) >= 0)
			out.write(buffer, 0, bytesRead);

		this.streamHash = md.digest();

		System.out.println("streamAndHashContent: stream hash follows:\n"
				+ formatAsString(this.streamHash, " ", 16));
		System.out.println("streamAndHashContent: Thread '"
				+ Thread.currentThread().getName() + "' issues notify.");

		notify();

	}

	private byte[] hashContent(InputStream in) throws IOException,
			NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance(this.digestAlgorithm);

		DigestInputStream dis = new DigestInputStream(in, md);

		int bytesRead = 0;
		byte[] buffer = new byte[1024];
		while ((bytesRead = dis.read(buffer, 0, buffer.length)) >= 0)
			;

		return md.digest();

	}

	public String getDataPath() {
		return dataPath;
	}

	public void setDataPath(String dataPath) {
		this.dataPath = dataPath;
	}

	public String getDataContentType() {
		return dataContentType;
	}

	public void setDataContentType(String dataContentType) {
		this.dataContentType = dataContentType;
	}

	public String getDataFileName() {
		return dataFileName;
	}

	public void setDataFileName(String dataFileName) {
		this.dataFileName = dataFileName;
	}

	/**
	 * Merges two SignedData Objects
	 * 
	 * @param cms
	 *            existing cms signed data
	 * @param s
	 *            new cms signed data
	 * @param checkSameDigest
	 *            check if messageDigest value is the same for all signers?
	 * @return the merged cms
	 */
	public CMSSignedData mergeCms(CMSSignedData cms, CMSSignedData s) {

		try {

			SignerInformationStore existingSignersStore = cms.getSignerInfos();
			Collection<SignerInformation> existingSignersCollection = existingSignersStore
					.getSigners();

			SignerInformationStore newSignersStore = s.getSignerInfos();
			Collection<SignerInformation> newSignersCollection = newSignersStore
					.getSigners();

			// do some sanity checks
			if (existingSignersCollection.isEmpty()) {
				System.out
						.println("Error: existing signed data has no signers.");
				return null;
			}
			if (newSignersCollection.isEmpty()) {
				System.out.println("Error: new signed data has no signers.");
				return null;
			}
			byte[] cmsBytes = (byte[]) cms.getSignedContent()
					.getContent();
			byte[] sBytes = (byte[]) s.getSignedContent()
					.getContent();
			if(!Arrays.equals(cmsBytes, sBytes)){
				System.out.println("Error: content data differs.");
				return null;
			}
			
/* Digest could differ, if hashing algorithms are different
			if (checkSameDigest)
				if (!isSameDigest(existingSignersCollection,
						newSignersCollection)) {
					System.out
							.println("Error: messageDigest for some signers differ.");
					
					return null;
				}
*/
			CertStore existingCertsStore = cms.getCertificatesAndCRLs(
					"Collection", "BC");
			CertStore newCertsStore = s.getCertificatesAndCRLs("Collection",
					"BC");

			X509Store x509Store = cms.getAttributeCertificates("Collection",
					"BC");
			X509Store newX509Store = s.getAttributeCertificates("Collection",
					"BC");

			Collection newCertsCollection = newCertsStore.getCertificates(null);

			Iterator<SignerInformation> existingSignersIterator = existingSignersCollection
					.iterator();
			// ciclo tra tutti i vecchi firmatari
			while (existingSignersIterator.hasNext()) {
				SignerInformation exSigner = existingSignersIterator.next();
				// Controllo la presenza di certificati firmatario corrente
				// tra i nuovi certificati
				Collection exSignerCerts = newCertsStore
						.getCertificates(exSigner.getSID());

				// ... e nel caso li rimuovo
				Iterator exSignerCertsIt = exSignerCerts.iterator();
				while (exSignerCertsIt.hasNext())
					newCertsCollection.remove(exSignerCertsIt.next());
			}
			// Rigenero la lista dei nuovi certificati,
			// ora disgiunta da quella dei vecchi
			newCertsStore = CertStore
					.getInstance("Collection",
							new CollectionCertStoreParameters(
									newCertsCollection), "BC");

			// Si crea un CMSSignedDataGenerator locale,
			// inizializzandolo conn i dati già presenti.

			CMSSignedDataGenerator signGen = new CMSSignedDataGenerator();

			// add old certs
			signGen.addCertificatesAndCRLs(existingCertsStore);
			// add old certs attributes
			signGen.addAttributeCertificates(x509Store);
			// add old signers
			signGen.addSigners(existingSignersStore);

			// add new certs
			signGen.addCertificatesAndCRLs(newCertsStore);
			// add new certs attributes
			signGen.addAttributeCertificates(newX509Store);
			// add new signers
			signGen.addSigners(newSignersStore);

			CMSProcessable cp = new CMSProcessableByteArray((byte[]) cms
					.getSignedContent().getContent());

			s = signGen.generate(cp, true, "BC");

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return s;
	}

	private boolean isSameDigest(Collection<SignerInformation> sc1,
			Collection<SignerInformation> sc2) {

		boolean sameDigest = false;

		for (Iterator<SignerInformation> sc1i = sc1.iterator(); sc1i.hasNext();) {

			SignerInformation s1 = sc1i.next();

			AttributeTable s1Attrs = s1.getSignedAttributes();

			Attribute s1MdAttr = s1Attrs.get(CMSAttributes.messageDigest);

			byte[] s1Md = DEROctetString.getInstance(
					s1MdAttr.getAttrValues().getObjectAt(0)).getOctets();

			for (Iterator<SignerInformation> sc2i = sc2.iterator(); sc2i
					.hasNext();) {

				SignerInformation s2 = sc2i.next();

				AttributeTable s2Attrs = s2.getSignedAttributes();

				Attribute s2MdAttr = s2Attrs.get(CMSAttributes.messageDigest);
				byte[] s2Md = DEROctetString.getInstance(
						s2MdAttr.getAttrValues().getObjectAt(0)).getOctets();

				sameDigest = Arrays.equals(s1Md, s2Md);
				
				if(!sameDigest) return false;
					
			}
		}
		
		return sameDigest;
	}

}
