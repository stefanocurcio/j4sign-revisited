/**
 *	j4sign - an open, multi-platform digital signature solution
 *	Copyright (c) 2004 Roberto Resoli - Servizio Sistema Informativo - Comune di Trento.
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
/*
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/examples/CLITest.java,v 1.20 2015/04/03 09:23:18 resoli Exp $
 * $Revision: 1.20 $
 * $Date: 2015/04/03 09:23:18 $
 */
package it.trento.comune.j4sign.examples;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import it.trento.comune.j4sign.cms.ExternalSignatureCMSSignedDataGenerator;
import it.trento.comune.j4sign.cms.ExternalSignatureSignerInfoGenerator;
import it.trento.comune.j4sign.pcsc.CardInfo;
import it.trento.comune.j4sign.pcsc.PCSCHelper;
import it.trento.comune.j4sign.pkcs11.PKCS11Signer;
import it.trento.comune.j4sign.verification.RootsVerifier;
import it.trento.comune.j4sign.verification.VerifyResult;
import it.trento.comune.j4sign.verification.Verifier;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

//Alternative (NOT pure java) solution for password hiding
//import jline.ConsoleReader;

/**
 * <p>
 * A command line interface program for testing the generation of a CMS signed
 * message, using a pkcs11 token (usually a SmartCard). This is a complete
 * example covering all aspects of digital signature, from token management to
 * CMS message generation and verification.
 * <p/>
 * <p>
 * Multiple signatures are permitted, each with different token types; the
 * generated CMS message keeps signers informations at the same level (similar
 * to a paper document with multiple signatures). I call this arrangement
 * "combined signatures", in contrast with "nested signatures" (like a signed
 * paper document put in a signed envelope). A hierarchical type of multiple
 * signatures, ("CounterSignature", OID: 1.2.840.113549.1.9.6) is also
 * contemplated by CMS standard in RFC 3852, but it is not currently supported.
 * <p/>
 * <p>
 * The example adopts a special class for securing token PIN management
 * (Unfortunately the java language does not provide any standard method to hide
 * character input). This could cause some problem on IDEs, where the default
 * input - output streams are not the standard console, then password hiding can
 * be disabled. <br>
 * <p/>
 * <p>
 * After having signed, (or instead of signing, if the file to verify path is
 * passed) it is possible to perform a full verification, with signer
 * certificate check (certificate chain check, revocation through the CRL
 * distribution service specified in the signer certificate), CAdES details
 * checks, etc.<br/>
 * The verification policy conforms to the latest italian regulations, see: <a
 * href=
 * "http://www.agid.gov.it/sites/default/files/circolari/deliberazione_cnipa_45_9_novembre_2009_gu_modificata_dalla_dt_69_2010_1.pdf"
 * > REGOLE PER IL RICONOSCIMENTO E LA VERIFICA DEL DOCUMENTO INFORMATICO<a>.<br/>
 * These rules comply also to the electronic signature european regulation
 * framework.
 * <p>
 * The configuration of the tests is specified in three properties file:
 * <ul>
 * <li><code>clitest.properties</code> which specify internal behavior and
 * resources needed by the tests.</li>
 * <li><code>conf.properties</code>for configuration and resources needed by the
 * verification process.</li>
 * <li><code>logging.properties</code> for logging (standard java.util.logging
 * is used).</li>
 * </ul>
 * </p>
 * 
 * @author Roberto Resoli
 */
public class CLITest {

	private String cryptokiLib = null;

	private boolean forcingCryptoki = false;

	String signDN;

	KeyPair signKP;

	X509Certificate signCert;

	String origDN;

	KeyPair origKP;

	X509Certificate origCert;

	String reciDN;

	KeyPair reciKP;

	X509Certificate reciCert;

	KeyPair dsaSignKP;

	X509Certificate dsaSignCert;

	KeyPair dsaOrigKP;

	X509Certificate dsaOrigCert;

	byte[] msgBytes = { 'C', 'I', 'A', 'O' };

	private static int WRAP_AFTER = 16;

	private boolean makeDigestOnToken = false;

	private String digestAlg = CMSSignedDataGenerator.DIGEST_SHA256;

	private String encAlg = CMSSignedDataGenerator.ENCRYPTION_RSA;

	private static String PROPERTIES_FILE = "clitest.properties";

	private String filePath = null;

	private String fingerprintString = null;

	private File crlDir = null;

	private boolean interactive = true;

	public CLITest() {
		System.out
				.println("============== CLITest initialization ================");

		loadProperties();

		System.out
				.println("============== Initialization ended ================");
	}

	private void loadProperties() {

		String propertiesFile = PROPERTIES_FILE;
		Properties props = new Properties();

		System.out.println("Trying to load properties from: '."
				+ System.getProperty("file.separator") + propertiesFile + "'");
		try {

			FileInputStream fis = new FileInputStream("."
					+ System.getProperty("file.separator") + propertiesFile);

			props.load(fis);
			fis.close();

		} catch (IOException e) {
			System.out.println(e);
		}

		if (props.size() > 0) {
			Iterator<Entry<Object, Object>> i = props.entrySet().iterator();
			System.out.println("loaded properties:");
			while (i.hasNext()) {
				Entry<Object, Object> me = i.next();
				System.out.println((me.getKey().toString() + ": " + me
						.getValue()));
			}

			if (props.getProperty("digest.algorithm") != null)
				this.digestAlg = props.getProperty("digest.algorithm");

			if (props.getProperty("digest.ontoken") != null)
				this.makeDigestOnToken = Boolean.valueOf(
						props.getProperty("digest.ontoken")).booleanValue();

			if (props.getProperty("encryption.algorithm") != null)
				this.encAlg = props.getProperty("encryption.algorithm");

			if (props.getProperty("roots.fingerprint") != null)
				this.fingerprintString = props.getProperty("roots.fingerprint");

			if (props.getProperty("roots.fingerprint") != null)
				this.crlDir = new File("."
						+ System.getProperty("file.separator")
						+ props.getProperty("crl.dir"));

			if (props.getProperty("logging.config") != null)
				System.setProperty(
						"java.util.logging.config.file",
						"." + System.getProperty("file.separator")
								+ props.getProperty("logging.config"));

			if (props.getProperty("cryptoki") != null) {
				this.cryptokiLib = props.getProperty("cryptoki");
				this.forcingCryptoki = true;
			}

		}

	}

	/**
	 * CLITest constructor that takes a file path as argument.
	 * 
	 * @param filePath
	 *            Currently this is assumed to be the path of a signed CMS file
	 *            to verify;
	 */
	public CLITest(String filePath) {
		this();
		this.filePath = filePath;

	}

	/**
	 * <p>
	 * the main method Adds BouncyCastle cryptographic provider, instantiates
	 * the CLITest class, and launches the signature/verification process. The
	 * message to sign is the fixed word "CIAO".<br/>
	 * A CMS signed file path can be provided as parameter; in that case the
	 * signature procedure is skipped, and only verification is performed.
	 * </p>
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		// Security.insertProviderAt(new MyPKCS11Provider(), 2);
		Security.insertProviderAt(new BouncyCastleProvider(), 3);

		CLITest rt = null;

		if (args.length > 0) {
			rt = new CLITest(args[0]);
			if ((args.length == 2) && "-b".equals(args[1]))
				rt.setInteractive(false);
		} else
			rt = new CLITest();

		// non per SC
		// rt.initSW();

		// rt.initHW();

		// test sw
		// rt.testSHA1WithRSAEncapsulated();

		// per SC
		// rt.testMD5WithRSAEncapsulated();

		// per provider SMARTCARD
		// rt.testSCProvider();

		if (rt.getFilePath() == null) {
			rt.testExternalSignature();
		}
		// Verifica con controllo revoca
		rt.testFullVerification();
	}

	public String getFilePath() {
		return filePath;
	}

	/**
	 * The cryptoki library currently used, as set in
	 * {@link #detectCardAndCriptoki()}method.
	 * 
	 * @return the cryptoki native library to use to access the current PKCS#11
	 *         token.
	 */

	public String getCryptokiLib() {
		return cryptokiLib;
	}

	/**
	 * Sets th cryptoki library to use to access the current PKCS#11 token; This
	 * method is used internally in {@link #detectCardAndCriptoki()}method.
	 * 
	 * @param lib
	 */
	private void setCryptokiLib(String lib) {
		this.cryptokiLib = lib;
	}

	/**
	 * This triggers the PCSC wrapper stuff; a {@link PCSCHelper}class is used
	 * to detect reader and token presence, trying also to provide a candidate
	 * PKCS#11 cryptoki for it.
	 * 
	 * @return true if a token with corresponding candidate cryptoki was
	 *         detected.
	 * @throws IOException
	 */
	private boolean detectCardAndCriptoki() throws IOException {
		CardInfo ci = null;
		boolean cardPresent = false;
		System.out.println("\n\n========= DETECTING CARD ===========");

		PCSCHelper pcsc = new PCSCHelper(true);
		List cards = pcsc.findCards();
		cardPresent = !cards.isEmpty();

		if (!isForcingCryptoki()) {
			if (cardPresent) {
				ci = (CardInfo) cards.get(0);
				System.out.println("\n\nFor signing we will use card: '"
						+ ci.getProperty("description") + "' with criptoki '"
						+ ci.getProperty("lib") + "'");
				System.out.println(ci.getProperty("lib"));

				setCryptokiLib(ci.getProperty("lib"));
			} else
				System.out.println("Sorry, no card detected!");
		} else
			System.out
					.println("\n\nFor signing we are forcing use of cryptoki: '"
							+ getCryptokiLib() + "'");

		System.out.println("=================================");
		return (getCryptokiLib() != null);
	}

	/**
	 * Currently not used.; initializes sw keys and certificate for a signature
	 * test completely in sw.
	 * 
	 */
	/*
	 * public void initSW() { try {
	 * System.out.println("Init test with SW keys an certs ..."); signDN =
	 * "O=Bouncy Castle, C=AU"; signKP = CMSTestUtil.makeKeyPair(); signCert =
	 * CMSTestUtil.makeCertificate(signKP, signDN, signKP, signDN);
	 * 
	 * origDN =
	 * "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
	 * origKP = CMSTestUtil.makeKeyPair(); origCert =
	 * CMSTestUtil.makeCertificate(origKP, origDN, signKP, signDN); } catch
	 * (Exception ex) { System.out.println(ex); } }
	 */

	/*
	 * public void initHW(String criptoki) { try { System.out.println("Init test
	 * with PKCS11 token ...");
	 * 
	 * MessageDigest md = MessageDigest.getInstance("MD5");
	 * 
	 * md.update(this.msgBytes);
	 * 
	 * ByteArrayInputStream bais = new ByteArrayInputStream(md.digest());
	 * 
	 * SmartCardHandler tokenTest = new SmartCardHandler(criptoki, bais);
	 * 
	 * tokenTest.doTest(); } catch (Exception ex) { System.out.println(ex); } }
	 * 
	 * public void testMD5WithRSAEncapsulated() { try { // if(this.tokenTest ==
	 * null) // return;
	 * 
	 * CMSProcessable msg = //new CMSProcessableByteArray("Hello
	 * World!".getBytes()); new CMSProcessableByteArray(this.msgBytes);
	 * 
	 * 
	 * //CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	 * EncryptedDigestCMSSignedDataGenerator gen = new
	 * EncryptedDigestCMSSignedDataGenerator();
	 * 
	 * //gen.addSigner( // origKP.getPrivate(), // origCert, //
	 * CMSSignedDataGenerator.DIGEST_SHA1);
	 * gen.addSigner(CMSSignedDataGenerator.DIGEST_MD5); // N.B.:Questo metodo
	 * viene eseguito durante il processo di // generazione della firma. //
	 * gen.addCertificatesAndCRLs(certs);
	 * 
	 * CMSSignedData s = gen.generate(msg, true, "BC");
	 * 
	 * 
	 * 
	 * //Verifica firma CertStore certs = s.getCertificatesAndCRLs("Collection",
	 * "BC"); SignerInformationStore signers = s.getSignerInfos(); Collection c
	 * = signers.getSigners();
	 * 
	 * Iterator it = c.iterator();
	 * 
	 * while (it.hasNext()) { SignerInformation signer = (SignerInformation)
	 * it.next(); Collection certCollection = certs.getCertificates(signer
	 * .getSID());
	 * 
	 * Iterator certIt = certCollection.iterator(); X509Certificate cert =
	 * (X509Certificate) certIt.next();
	 * 
	 * if (signer.verify(cert, "BC")) System.out.println("OK!"); else
	 * System.out.println("Failure!"); }
	 * 
	 * String filePath = "D:/bc117.txt.p7m";
	 * System.out.println("SAVING FILE TO: " + filePath);
	 * 
	 * FileOutputStream fos = new FileOutputStream(filePath);
	 * fos.write(s.getEncoded()); fos.flush(); fos.close(); } catch (Exception
	 * ex) { System.out.println(ex); } }
	 * 
	 * public void testSHA1WithRSAEncapsulated() { try { ArrayList certList =
	 * new ArrayList(); CMSProcessable msg = //new
	 * CMSProcessableByteArray("Hello World!".getBytes()); new
	 * CMSProcessableByteArray(msgBytes);
	 * 
	 * certList.add(origCert); certList.add(signCert);
	 * 
	 * CertStore certs = CertStore.getInstance("Collection", new
	 * CollectionCertStoreParameters(certList), "BC");
	 * 
	 * //CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	 * EncryptedDigestCMSSignedDataGenerator gen = new
	 * EncryptedDigestCMSSignedDataGenerator();
	 * 
	 * gen.addSigner(origKP.getPrivate(), origCert,
	 * //CMSSignedDataGenerator.DIGEST_SHA1);
	 * CMSSignedDataGenerator.DIGEST_MD5);
	 * 
	 * //indispensabile sesi usa CMSSignedDataGenerator invece di //
	 * EncryptedDigestCMSSignedDataGenerator
	 * //gen.addCertificatesAndCRLs(certs);
	 * 
	 * CMSSignedData s = gen.generate(msg, true, "BC");
	 * 
	 * ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
	 * ASN1InputStream aIn = new ASN1InputStream(bIn);
	 * 
	 * s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));
	 * 
	 * certs = s.getCertificatesAndCRLs("Collection", "BC");
	 * 
	 * SignerInformationStore signers = s.getSignerInfos(); Collection c =
	 * signers.getSigners(); Iterator it = c.iterator();
	 * 
	 * while (it.hasNext()) { SignerInformation signer = (SignerInformation)
	 * it.next(); Collection certCollection = certs.getCertificates(signer
	 * .getSID());
	 * 
	 * Iterator certIt = certCollection.iterator(); X509Certificate cert =
	 * (X509Certificate) certIt.next();
	 * 
	 * if (signer.verify(cert, "BC")) { String filePath = "D:/bc117.txt.p7m";
	 * System.out.println("OK - SAVING FILE TO: " + filePath);
	 * 
	 * FileOutputStream fos = new FileOutputStream(filePath);
	 * fos.write(s.getEncoded()); fos.flush(); fos.close(); } else
	 * System.out.println("Failure!"); } } catch (Exception ex) {
	 * System.out.println(ex); } }
	 */

	/*
	 * public byte[] readCertFile(String filePath) throws java.io.IOException {
	 * 
	 * System.out.println("reading certificate from file: " + filePath);
	 * 
	 * FileInputStream fis = new FileInputStream(filePath);
	 * 
	 * byte[] buffer = new byte[1024]; ByteArrayOutputStream baos = new
	 * ByteArrayOutputStream(); int bytesRead = 0; while ((bytesRead =
	 * fis.read(buffer, 0, buffer.length)) >= 0) { baos.write(buffer, 0,
	 * bytesRead); } fis.close(); System.out.println("FINISHED\n"); return
	 * baos.toByteArray(); }
	 */

	/*
	 * public void testSCProvider() { try { ArrayList certList = new
	 * ArrayList(); CMSProcessable msg = //new CMSProcessableByteArray("Hello
	 * World!".getBytes()); new CMSProcessableByteArray(msgBytes);
	 * 
	 * certList.add(origCert); certList.add(signCert);
	 * 
	 * CertStore certs = CertStore.getInstance("Collection", new
	 * CollectionCertStoreParameters(certList), "BC");
	 * 
	 * CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	 * //EncryptedDigestCMSSignedDataGenerator gen = new //
	 * EncryptedDigestCMSSignedDataGenerator();
	 * 
	 * gen.addSigner(origKP.getPrivate(), origCert,
	 * //CMSSignedDataGenerator.DIGEST_SHA1);
	 * CMSSignedDataGenerator.DIGEST_MD5);
	 * 
	 * gen.addCertificatesAndCRLs(certs);
	 * 
	 * CMSSignedData s = gen.generate(msg, true, "SMARTCARD");
	 * 
	 * ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
	 * ASN1InputStream aIn = new ASN1InputStream(bIn);
	 * 
	 * s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));
	 * 
	 * certs = s.getCertificatesAndCRLs("Collection", "BC");
	 * 
	 * SignerInformationStore signers = s.getSignerInfos(); Collection c =
	 * signers.getSigners(); Iterator it = c.iterator();
	 * 
	 * while (it.hasNext()) { SignerInformation signer = (SignerInformation)
	 * it.next(); Collection certCollection = certs.getCertificates(signer
	 * .getSID());
	 * 
	 * Iterator certIt = certCollection.iterator(); X509Certificate cert =
	 * (X509Certificate) certIt.next();
	 * 
	 * if (signer.verify(cert, "BC")) { String filePath = "D:/bc117.txt.p7m";
	 * System.out.println("OK - SAVING FILE TO: " + filePath);
	 * 
	 * FileOutputStream fos = new FileOutputStream(filePath);
	 * fos.write(s.getEncoded()); fos.flush(); fos.close(); } else
	 * System.out.println("Failure!"); } } catch (Exception ex) {
	 * System.out.println(ex); } }
	 */

	/**
	 * Tests (possibly multiple) digital signatures using PKCS#11 tokens. After
	 * correct integrity verification of all signatures, the CMS signed message
	 * is saved on the filesystem under the users's home directory.
	 * 
	 */
	public void testExternalSignature() {

		try {

			System.out
					.println("\n========= CMS (PKCS7) Signed message test ========\n");

			System.out.print("The test message to sign is:\t");
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(this.msgBytes);
			System.out.println(baos.toString());
			System.out.print("As exadecimal string:\t\t");
			System.out.println(formatAsString(this.msgBytes, " ", WRAP_AFTER));
			System.out.println();

			CMSProcessable msg = new CMSProcessableByteArray(this.msgBytes);

			// questa versione del generatore è priva della classe interna
			// per
			// la generazione delle SignerInfo, che è stata promossa a
			// classe a
			// sè.
			ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();

			// Conterrà la lista dei certificati; come minimo dovrà
			// contenere i certificati dei firmatari; opzionale, ma
			// consigliabile,
			// l'aggiunta dei certificati root per completare le catene di
			// certificazione.
			ArrayList certList = new ArrayList();

			ExternalSignatureSignerInfoGenerator sig = null;

			String answer = "STARTVALUE";
			String question = "Do you want to sign this message?";
			String defaultChoice = null;
			int i = 0;
			Prompt prompt = new Prompt();
			String[] choices = { "Y", "N" };

			while (!answer.equals("N")) {

				answer = prompt.question(question, "Type Y or N:", choices,
						defaultChoice);

				if (answer.equals("Y")) {
					System.out.println("========================");
					System.out.println("ADDING SIGNATURE " + i);

					if (detectCardAndCriptoki()) {
						System.out.println("Starting signing process.");
						// System.out
						// .println("Applying SHA1 digest with RSA
						// encryption.");
						sig = getSignerInfoGenerator(msg, this.digestAlg,
								this.encAlg, this.makeDigestOnToken, // digest
								// on
								// token?
								certList);

						if (sig != null)
							gen.addSignerInf(sig);
					}// if card detected

					question = "\nAdd another signature?";
					defaultChoice = "N";
					answer = "STARTVALUE";
				}
				i++;
			}

			if (certList.size() != 0) {

				// Per passare i certificati al generatore li si incapsula
				// in un
				// CertStore.
				CertStore store = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(certList), "BC");

				System.out.println("Adding certificates ... ");
				gen.addCertificatesAndCRLs(store);

				// Finalmente, si può creare il l'oggetto CMS.
				System.out.println("Generating CMSSignedData ");
				CMSSignedData s = gen.generate(msg, true);

				// Verifica

				System.out
						.println("\nStarting CMSSignedData verification ... ");
				// recupero dal CMS la lista dei certificati
				Store certs = s.getCertificates();

				// Recupero i firmatari.
				SignerInformationStore signers = s.getSignerInfos();
				Collection<?> c = signers.getSigners();

				System.out.println(c.size() + " signers found.");

				Iterator it = c.iterator();

				// ciclo tra tutti i firmatari
				i = 0;
				while (it.hasNext()) {
					SignerInformation signer = (SignerInformation) it.next();
					Collection<?> certCollection = certs.getMatches(signer
							.getSID());

					if (certCollection.size() == 1) {
						// Iterator certIt = certCollection.iterator();
						// X509Certificate cert = (X509Certificate)
						// certIt.next();

						X509CertificateHolder ch = (X509CertificateHolder) certCollection
								.toArray()[0];

						X509Certificate cert = new JcaX509CertificateConverter()
								.setProvider("BC").getCertificate(ch);

						System.out.println(i + ") Verifiying signature from:\n"
								+ cert.getSubjectDN());
						/*
						 * System.out.println("Certificate follows:");
						 * System.out
						 * .println("====================================");
						 * System.out.println(cert);
						 * System.out.println("===================================="
						 * );
						 */

						if (signer
								.verify(new JcaSimpleSignerInfoVerifierBuilder()
										.setProvider("BC").build(cert))) {

							System.out.println("SIGNATURE " + i + " OK!");
						} else
							System.err.println("SIGNATURE " + i + " Failure!");
					} else
						System.out
								.println("There is not exactly one certificate for this signer!");
					i++;
				}

				// writing CMS file to user's home directory

				this.filePath = System.getProperty("user.home")
						+ System.getProperty("file.separator") + "ciao.txt.p7m";

				System.out.println("\nSAVING FILE TO: " + filePath);

				FileOutputStream fos = new FileOutputStream(filePath);
				fos.write(s.getEncoded());
				fos.flush();
				fos.close();
			}

		} catch (Exception ex) {
			System.err.println("EXCEPTION:\n" + ex);
		}

	}

	/**
	 * Performs full (signer certificate chain and revocation status)
	 * verification of a CMS signed message.
	 * <p>
	 * Requires a suitable <code>conf</code> directory containing the signed
	 * zipfile of qualified root CAs (and related files), and the fingerprint
	 * value of signing certificate, provided in the
	 * <code>clitest.properties</code> file, for checking roots integrity.
	 * </p>
	 * <p>
	 * The verification policy strictly follows current italian regulations
	 * (CAdES, SHA256 hashing ...).
	 * </p>
	 * <p>
	 * See the <code>README</code> file for more informations.
	 * </p>
	 */
	public void testFullVerification() {

		System.out
				.println("\n========= Full CMS file verification test ========");

		if (this.filePath == null) {
			System.out.println("\nNO FILE TO VERIFY; Terminating.");
			return;
		}

		if (this.fingerprintString != null)
			System.out.println("\nROOTS SIGNER FINGERPRINT HAS TO BE:\n"
					+ this.fingerprintString + "\n");
		else {
			System.out
					.println("\nNO ROOTS SIGNER FINGERPRINT NOT CONFIGURED; Terminating.");
			return;
		}

		String confPath = ".";
		System.out.println("USING CONFIGURATION IN:\n" + "\""
				+ new File(confPath).getAbsolutePath() + "\"\n");

		try {
			String answer = "STARTVALUE";
			Prompt prompt = new Prompt();
			String[] choices = { "Y", "N" };

			while (isInteractive() && !answer.equals("N")
					&& !answer.equals("Y")) {
				answer = prompt.question(
						"DO YOU WANT TO PERFORM A FULL VERIFICATION OF:\n"
								+ "\"" + filePath + "\" ?", null, choices, "Y");
			}

			if (!isInteractive() || answer.equals("Y")) {

				System.out.println("\nSTARTING VERIFICATION OF: " + filePath);

				// Inizio verifica
				RootsVerifier rv;
				Verifier v = null;
				boolean isVerified = false;

				try {
					rv = RootsVerifier.getInstance(confPath,
							decodeHex(this.fingerprintString.toCharArray()));
					rv.setCrlDir(this.crlDir);

					v = new Verifier(this.filePath, false, rv);
					v.setCrlDir(this.crlDir);

				} catch (Exception e) {
					System.err
							.println("Errore nell'inizializzazione della verifica: "
									+ e.getMessage());
				}

				if (v != null) {
					while (!v.isCanceled() && !v.isDone())
						v.verify();

					Vector<VerifyResult> r = v.getRisultati();

					if (r != null) {
						Iterator<VerifyResult> resultsIterator = r.iterator();

						int i = 0;
						while (resultsIterator.hasNext()) {
							VerifyResult sv = resultsIterator.next();
							isVerified = sv.isPassed()
									&& ((i == 0) || isVerified);

						}

					}
				}

				System.out.print("FILE '" + this.filePath + "' ");

				if (isVerified) {
					String contentPath = this.filePath.substring(0,
							this.filePath.lastIndexOf(".p7m"));

					FileOutputStream fos = new FileOutputStream(contentPath);
					fos.write((byte[]) v.getCms().getSignedContent()
							.getContent());
					fos.flush();
					fos.close();

					System.out.println("VERIFIED - CONTENT SAVED IN: '"
							+ contentPath + "'");
				} else
					System.out.println("NOT VERIFIED!");

			}

		} catch (Exception ex) {
			System.err.println("EXCEPTION:\n" + ex);
		}
	}

	private long algToMechanism(boolean digestOnToken, String digestAlg,
			String encryptionAlg) {

		long mechanism = -1L;

		if (CMSSignedDataGenerator.ENCRYPTION_RSA.equals(encryptionAlg))
			if (digestOnToken) {
				if (CMSSignedDataGenerator.DIGEST_MD5.equals(digestAlg))
					mechanism = PKCS11Constants.CKM_MD5_RSA_PKCS;
				else if (CMSSignedDataGenerator.DIGEST_SHA1.equals(digestAlg))
					mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
				else if (CMSSignedDataGenerator.DIGEST_SHA256.equals(digestAlg))
					mechanism = PKCS11Constants.CKM_SHA256_RSA_PKCS;
			} else
				mechanism = PKCS11Constants.CKM_RSA_PKCS;

		return mechanism;
	}

	/**
	 * Implements a single signature, returning the
	 * {@link ExternalSignatureSignerInfoGenerator}that encapsulates all signer
	 * informations.
	 * 
	 * 
	 * @param msg
	 *            the content to sign
	 * @param certList
	 *            the list which the signer certificate is to be added to.
	 * @return the <code>ExternalSignatureSignerInfoGenerator</code> containing
	 *         all signer informations.
	 */
	ExternalSignatureSignerInfoGenerator getSignerInfoGenerator(
			CMSProcessable msg, String digestAlg, String encryptionAlg,
			boolean digestOnToken, ArrayList certList) {

		// Il SignerInfoGenerator è molto simile alla versione standard
		// SignerInf; la differenza maggiore
		// è la presenza del metodo generateBytesToSign() che permette di
		// esternalizzare la firma.
		// Il nuovo metodo toSignerInfo() (senza parametri) restituisce un
		// signerInfo che usa il digest crittato
		// e certificati precedentemente impostati dall'esterno.
		// Il digest crittato è ora una variabile del generatore,
		// impostabile dall'esterno.

		ExternalSignatureSignerInfoGenerator signerGenerator = new ExternalSignatureSignerInfoGenerator(
				digestAlg, encryptionAlg);

		byte[] certBytes = null;
		byte[] signedBytes = null;
		byte[] bytesToSign = null;
		byte[] dInfoBytes = null;

		try {

			long mechanism = -1L;
			long certHandle = -1L;
			long t = -1L;

			mechanism = algToMechanism(digestOnToken, digestAlg, encryptionAlg);

			if (mechanism != -1L) {
				PKCS11Signer signAgent = new PKCS11Signer(getCryptokiLib(),
						System.out);

				System.out
						.println("Finding a token supporting required mechanism and "
								+ "containing a suitable " + "certificate...");

				t = signAgent.findSuitableToken(mechanism);

				// if suitable token found
				if (t != -1L) {
					signAgent.setMechanism(mechanism);
					signAgent.setTokenHandle(t);

					signAgent.openSession();

					certHandle = signAgent
							.findCertificateWithNonRepudiationCritical();

					if (certHandle >= 0)

						certBytes = signAgent
								.getDEREncodedCertificate(certHandle);
					else
						System.out
								.println("\nNo suitable  certificate on token!");

					signAgent.closeSession();
					System.out.println("Cert session Closed.");

					// signAgent.libFinalize();
					// System.out.println("Criptoki library finalized.");

					if (certBytes != null) {
						System.out
								.println("======== Certificate found =========");

						// get Certificate
						java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
								.getInstance("X.509");
						java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(
								certBytes);
						java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
								.generateCertificate(bais);

						signerGenerator.setCertificate(javaCert);

						System.out.println("Calculating bytes to sign ...");

						bytesToSign = signerGenerator.getBytesToSign(
								PKCSObjectIdentifiers.data, msg, "BC");

						byte[] rawDigest = null;
						byte[] paddedBytes = null;

						/*
						 * Let's calculate DigestInfo in any case (even if
						 * digestOnToken is TRUE) , in order to compare with
						 * decryption result
						 */
						rawDigest = applyDigest(digestAlg, bytesToSign);

						System.out.println("Raw digest bytes:\n"
								+ formatAsString(rawDigest, " ", WRAP_AFTER));

						System.out.println("Encapsulating in a DigestInfo...");

						dInfoBytes = encapsulateInDigestInfo(digestAlg,
								rawDigest);

						System.out.println("DigestInfo bytes:\n"
								+ formatAsString(dInfoBytes, " ", WRAP_AFTER));

						if (!digestOnToken) {

							System.out.println("Adding Pkcs1 padding...");

							paddedBytes = applyPkcs1Padding(128, dInfoBytes);

							System.out.println("Padded DigestInfo bytes:\n"
									+ formatAsString(paddedBytes, " ",
											WRAP_AFTER));

						}

						// certBytes = null;
						System.out
								.println("============ Encrypting with pkcs11 token ============");
						/*
						 * mechanism = -1L; if
						 * (CMSSignedDataGenerator.ENCRYPTION_RSA
						 * .equals(encryptionAlg)) if (digestOnToken) { if
						 * (CMSSignedDataGenerator.DIGEST_MD5.equals(digestAlg))
						 * mechanism = PKCS11Constants.CKM_MD5_RSA_PKCS; else if
						 * (CMSSignedDataGenerator.DIGEST_SHA1
						 * .equals(digestAlg)) mechanism =
						 * PKCS11Constants.CKM_SHA1_RSA_PKCS; } else mechanism =
						 * PKCS11Constants.CKM_RSA_PKCS;
						 * 
						 * if (mechanism != -1L) { PKCS11Signer signAgent = new
						 * PKCS11Signer(getCryptokiLib(), System.out);
						 */

						/*
						 * System.out .println(
						 * "Finding a token supporting required mechanism and "
						 * + "containing a suitable" + "certificate...");
						 * 
						 * if (t != -1L) t =
						 * signAgent.findSuitableToken(mechanism);
						 */
						// if suitable token found
						// if (t != -1L) {
						signAgent.setMechanism(mechanism);
						signAgent.setTokenHandle(t);

						signAgent.openSession(readPassword());

						/*
						 * sign using the first key found on token
						 * 
						 * long privateKeyHandle = signAgent.findSignatureKey();
						 * 
						 * if(privateKeyHandle > 0){ signedBytes =
						 * signAgent.signDataSinglePart(privateKeyHandle,
						 * digest); long certHandle =
						 * signAgent.findCertificateFromSignatureKeyHandle
						 * (privateKeyHandle); certBytes =
						 * signAgent.getDEREncodedCertificate(certHandle);
						 * 
						 * }else System.out.println("\nNo private key found on
						 * token!");
						 */

						// trying a legal value signature finding suitable
						// objects
						// on
						// token
						if (certHandle == -1L)
							certHandle = signAgent
									.findCertificateWithNonRepudiationCritical();

						long privateKeyHandle = signAgent
								.findSignatureKeyFromCertificateHandle(certHandle);

						if (privateKeyHandle >= 0) {
							if (!digestOnToken) {
								// Here we could provide padded bytes or
								// DigestInfo
								// bytes;
								// but with padded bytes and Infocamere CNS
								// signDataSinglePart fails!
								// (CKR_FUNCTION_FAILED).
								signedBytes = signAgent.signDataSinglePart(
										privateKeyHandle, dInfoBytes);
							} else
								/*
								 * signedBytes = signAgent.signDataMultiplePart(
								 * privateKeyHandle, new ByteArrayInputStream(
								 * bytesToSign));
								 */
								signedBytes = signAgent.signDataSinglePart(
										privateKeyHandle, bytesToSign);

							// certBytes = signAgent
							// .getDEREncodedCertificate(certHandle);
						} else
							System.out
									.println("\nNo suitable private key and certificate on token!");

						signAgent.closeSession();
						System.out.println("Sign session Closed.");

						signAgent.libFinalize();
						System.out.println("Criptoki library finalized.");

					} // certBytes not null
				} // suitable token found
			} else
				System.out.println("Mechanism currently not supported");

			if ((certBytes != null) && (signedBytes != null)) {
				System.out.println("======== Encryption completed =========");
				System.out.println("\nBytes:\n"
						+ formatAsString(bytesToSign, " ", WRAP_AFTER));

				if (dInfoBytes != null)
					System.out.println("DigestInfo bytes:\n"
							+ formatAsString(dInfoBytes, " ", WRAP_AFTER));

				System.out.println("Encryption result:\n"
						+ formatAsString(signedBytes, " ", WRAP_AFTER) + "\n");

				// get Certificate
				java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
						.getInstance("X.509");
				java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(
						certBytes);
				java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
						.generateCertificate(bais);

				// Decription
				PublicKey pubKey = javaCert.getPublicKey();

				try {
					System.out.println("Decrypting...");

					Cipher c = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "BC");

					c.init(Cipher.DECRYPT_MODE, pubKey);

					byte[] decBytes = c.doFinal(signedBytes);

					System.out
							.println("Decrypted bytes (should match DigestInfo bytes):\n"
									+ formatAsString(decBytes, " ", WRAP_AFTER));

				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (InvalidKeyException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				} catch (IllegalStateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchProviderException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				if (signerGenerator.getCertificate() != null)
					signerGenerator.setCertificate(javaCert);
				signerGenerator.setSignedBytes(signedBytes);

				certList.add(javaCert);

			} else
				signerGenerator = null;
		} catch (Exception e) {
			System.out.println(e);
		} catch (Throwable e) {
			System.out.println(e);
		}

		return signerGenerator;
	}

	/**
	 * Formats a byte[] as an hexadecimal String, interleaving bytes with a
	 * separator string.
	 * 
	 * @param bytes
	 *            the byte[] to format.
	 * @param byteSeparator
	 *            the string to be used to separate bytes.
	 * 
	 * @return the formatted string.
	 */

	public String formatAsString(byte[] bytes, String byteSeparator,
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

	/**
	 * Uses the {@link PasswordMasker}class to securely read characters from the
	 * console; it's a pity that java language does not includes this in its
	 * standard set of features.
	 * 
	 * @return the characters read.
	 * @throws IOException
	 * @throws InterruptedException
	 */
	char[] readPassword() throws IOException, InterruptedException {

		System.out.println("Getting password ...\n");

		char[] password = null;
		System.out
				.println("N.B.: If you are not running the example from the console, password hiding could not work well;");

		// N.B::
		// Sotto Eclipse, con JLine la password viene comunque mostrata,
		// mentre la soluzione pure java non funziona correttamente.

		// implementazione pure java

		String answer = "STARTVALUE";
		Prompt prompt = new Prompt();
		String[] choices = { "Y", "N" };

		answer = prompt
				.question(
						"Do you want to enable password hiding?",
						"IF YOU ANSWER 'N' PASSWORD WILL BE VISIBLE WHILE YOU TYPE IT!!!!",
						choices, "Y");

		if (answer.equals("N")) {
			password = prompt
					.line("Enter user-PIN (VISIBLE) and press [return key]: ");
		} else {
			// Versione sicura, funziona male in Eclipse
			password = PasswordMasker
					.readConsoleSecure("Enter user-PIN (hidden) and press [return key]: ");
		}

		// implementazione JLine, NON pure java!
		// System.out
		// .println("This is an alternative implementation for password hiding,
		// using JLine project and JNI.\n" +
		// "See source code.\n");
		//
		//
		// ConsoleReader creader = new ConsoleReader();
		//
		// String prompt = "Enter user-PIN and press [return key]: ";
		// password = creader.readLine(prompt, new
		// Character('*')).toCharArray();
		// creader.setEchoCharacter(null);
		//

		return password;
	}

	private byte[] applyDigest(String digestAlg, byte[] bytes)
			throws NoSuchAlgorithmException {

		System.out.println("Applying digest algorithm...");
		MessageDigest md = MessageDigest.getInstance(digestAlg);
		md.update(bytes);

		return md.digest();
	}

	private byte[] encapsulateInDigestInfo(String digestAlg, byte[] digestBytes)
			throws IOException {

		byte[] bcDigestInfoBytes = null;
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

	public boolean isForcingCryptoki() {
		return forcingCryptoki;
	}

	public static byte[] decodeHex(char[] data) throws Exception {

		int len = data.length;

		if ((len & 0x01) != 0) {
			throw new Exception("Odd number of characters.");
		}

		byte[] out = new byte[len >> 1];

		// two characters form the hex value.
		for (int i = 0, j = 0; j < len; i++) {
			int f = toDigit(data[j], j) << 4;
			j++;
			f = f | toDigit(data[j], j);
			j++;
			out[i] = (byte) (f & 0xFF);
		}

		return out;
	}

	protected static int toDigit(char ch, int index) throws Exception {
		int digit = Character.digit(ch, 16);
		if (digit == -1) {
			throw new Exception("Illegal hexadecimal character " + ch
					+ " at index " + index);
		}
		return digit;
	}

	private class Prompt {

		PrintWriter output_ = null;
		BufferedReader input_ = null;

		public Prompt() {

			try {
				output_ = new PrintWriter(System.out, true);
				input_ = new BufferedReader(new InputStreamReader(System.in));
			} catch (Throwable thr) {
				thr.printStackTrace();
				output_ = new PrintWriter(System.out, true);
				input_ = new BufferedReader(new InputStreamReader(System.in));
			}

		}

		public String question(String question, String explanation,
				String[] choices, String defaultChoice) throws IOException {

			String answer = "STARTVALUE";

			output_.println(question
					+ ((defaultChoice != null) ? " [" + defaultChoice + "]"
							: ""));

			while (!answer.equals("N") && !answer.equals("Y")) {

				output_.println((explanation != null) ? explanation : "");
				output_.flush();
				answer = input_.readLine().toUpperCase();
				if (answer == null || "".equals(answer))
					if (defaultChoice != null)
						answer = defaultChoice;
				output_.flush();
			}

			return answer;
		}

		public char[] line(String explanation) throws IOException {

			output_.print(explanation);
			output_.flush();

			return input_.readLine().toCharArray();

		}

	}

	public boolean isInteractive() {
		return interactive;
	}

	public void setInteractive(boolean interactive) {
		this.interactive = interactive;
	}

}