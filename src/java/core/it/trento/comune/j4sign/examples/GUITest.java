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
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/examples/GUITest.java,v 1.7 2011/04/15 08:23:02 resoli Exp $
 * $Revision: 1.7 $
 * $Date: 2011/04/15 08:23:02 $
 */
package it.trento.comune.j4sign.examples;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import it.trento.comune.j4sign.cms.ExternalSignatureCMSSignedDataGenerator;
import it.trento.comune.j4sign.cms.ExternalSignatureSignerInfoGenerator;
import it.trento.comune.j4sign.pcsc.CardInfo;
import it.trento.comune.j4sign.pcsc.PCSCHelper;


import java.awt.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

/**
 * A graphical user interface program for testing the generation of a CMS signed
 * message, using a pkcs11 token (usually a SmartCard). This examples shows a
 * simple method for signing text files; other file types are explicitly
 * excluded because we want avoid to manage here complex issues related to file
 * visualization. <br>
 * The italian law states clearly that the signing procedure has to make aware
 * the signer of the content being signed. Signing files that contains macros or
 * other procedures that can dinamically modify the visualization of the content
 * is also explicitely prohibithed. <br>
 * As a good rule, we should sign only a content we know and comprehend
 * completely. <br>
 * For this reason, we also STRONGLY SUGGEST NOT TO SIGN proprietary file
 * formats. <br>
 * Threads and timers are used in this example are used to enhance user
 * interface, permitting live logging of signing procedure and the use of a
 * progress bar.
 * <p>
 * Multiple signatures are permitted, each with different token types; the
 * generated CMS message keeps signers informations at the same level (similar
 * to a paper document with multiple signatures). I call this arrangement
 * "combined signatures", in contrast with "nested signatures" (like a signed
 * paper document put in a signed envelope).
 * <p>
 * <b>N.B. note that in this example signature verification only ensures signed
 * data integrity; a complete verification to ensure non-repudiation requires
 * checking the full certification path including the CA root certificate, and
 * CRL verification on the CA side. <br>
 * (Good stuff for a next release ...) </b>
 * 
 * @author Roberto Resoli
 */
public class GUITest extends JFrame implements java.awt.event.ActionListener,
		DocumentListener {
	private JTextArea logArea = null;

	private JTextArea dataArea = null;

	private JPasswordField pwd = null;

	private JTextArea certArea = null;

	private DigestSignTask signTask = null;

	private Timer signTimer = null;

	private FindCertTask certTask = null;

	private Timer findTimer = null;

	private JButton f = null;

	private JButton c = null;

	private JButton s = null;

	private JProgressBar progressBar = null;

	boolean debug = false;

	boolean submitAfterSigning = false;

	private byte[] bytesToSign = null;

	private String encodedDigest = null;

	private byte[] encryptedDigest;

	private java.io.PrintStream log = null;

	public final static int ONE_SECOND = 1000;

	private java.lang.String cryptokiLib = null;

	private java.lang.String signerLabel = null;

	private byte[] certificate = null;

	private CMSProcessable msg = null;

	private ExternalSignatureCMSSignedDataGenerator cmsGenerator = null;

	private ExternalSignatureSignerInfoGenerator signerInfoGenerator = null;

	private ArrayList signersCertList = null;

	private File fileToSign = null;

	private boolean forcingCryptoki = false;

	private static String PROPERTIES_FILE = "clitest.properties";

	private boolean makeDigestOnToken = false;

	private String digestAlg = CMSSignedDataGenerator.DIGEST_SHA256;

	private String encAlg = CMSSignedDataGenerator.ENCRYPTION_RSA;

	/**
	 * @return Returns the forcingCryptoki.
	 */
	public boolean isForcingCryptoki() {
		return forcingCryptoki;
	}

	private void loadProperties() {
		Properties props = new Properties();

		String propertiesFile = PROPERTIES_FILE;

		System.out.println("Trying to load properties from: '" + propertiesFile
				+ "'");
		try {
			InputStream in = getClass().getResourceAsStream(
					"/" + propertiesFile);
			if (in != null) {
				props.load(in);
				in.close();
			} else
				System.out.println("'" + propertiesFile + "' not found!");
		} catch (IOException e) {
			System.out.println(e);
		}

		if (props.size() > 0) {
			Iterator i = props.entrySet().iterator();
			System.out.println("loaded properties:");
			while (i.hasNext()) {
				Map.Entry me = (Map.Entry) i.next();
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
		}

	}

	/**
	 * The class constructor.
	 * 
	 * @param title
	 *            , shown on the window title bar.
	 * @param aDebug
	 *            if True, causes operation log to be shown in the GUI, in a
	 *            dedicated pane.
	 * @throws java.awt.HeadlessException
	 */
	public GUITest(String title, String aDebug, String aCryptoki) {
		super(title);

		System.out.println("Initializing GUITest ...");

		System.out.println("Loading properties ...");
		loadProperties();

		if (aDebug != null)
			this.debug = Boolean.valueOf(aDebug).booleanValue();

		if (aCryptoki != null) {
			this.cryptokiLib = aCryptoki;
			this.forcingCryptoki = true;
		}

		System.out.println("\nUsing cryptoki:\t" + getCryptokiLib());
		System.out.println("Using signer:\t" + getSignerLabel() + "\n");

		getContentPane().setLayout(new BorderLayout());

		if (!debug)
			log = System.out;
		else {
			logArea = new JTextArea();
			logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

			log = new PrintStream(new JTextAreaOutputStream(logArea), true);

			dataArea = new JTextArea();

			JPanel dataAreaPanel = new JPanel();
			dataAreaPanel.setLayout(new BorderLayout());
			dataAreaPanel.add(dataArea, BorderLayout.CENTER);
			dataAreaPanel.add(new JLabel("Put down here the text to sign:"),
					BorderLayout.NORTH);

			dataArea.getDocument().addDocumentListener(this);
			//dataArea.getDocument().putProperty("data", "Text Area");


			f = new JButton("Load File");
			f.setEnabled(true);

			c = new JButton("Save Certificate");
			c.setEnabled(false);

			s = new JButton("Save Signed File");
			s.setEnabled(false);

			f.addActionListener(this);
			c.addActionListener(this);
			s.addActionListener(this);

			JScrollPane logScrollPane = new JScrollPane(logArea);
			JScrollPane dataScrollPane = new JScrollPane(dataAreaPanel);

			JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
					logScrollPane, dataScrollPane);
			splitPane.setOneTouchExpandable(true);

			splitPane.setDividerLocation(200);
			// splitPane.setDividerLocation(0);

			// Provide minimum sizes for the two components in the split pane
			/*
			 * Dimension minimumSize = new Dimension(100, 50);
			 * logScrollPane.setMinimumSize(minimumSize);
			 * dataScrollPane.setMinimumSize(minimumSize);
			 */
			// Provide a preferred size for the split pane
			splitPane.setPreferredSize(new Dimension(600, 400));

			getContentPane().add(splitPane, BorderLayout.CENTER);
		}

		pwd = new JPasswordField();
		pwd.setPreferredSize(new Dimension(100, 25));
		pwd.addActionListener(this);

		JPanel southPanel = new JPanel();
		southPanel.setLayout(new BoxLayout(southPanel, BoxLayout.Y_AXIS));
		JPanel controlsPanel = new JPanel();
		JPanel statusPanel = new JPanel();

		JPanel certPanel = new JPanel();
		certPanel.setLayout(new BoxLayout(certPanel, BoxLayout.X_AXIS));

		certArea = new JTextArea();
		certArea.setPreferredSize(new Dimension(100, 40));
		certArea.setEditable(false);
		certArea.setLineWrap(true);
		certArea.setFont(new Font("Sans-serif", Font.BOLD, 12));

		certPanel.add(certArea);

		statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.X_AXIS));

		controlsPanel.add(pwd);

		if (debug) {
			controlsPanel.add(f);
			controlsPanel.add(s);
			controlsPanel.add(c);
		}

		progressBar = new JProgressBar();
		progressBar.setStringPainted(false);
		progressBar.setStringPainted(true);

		// setStatus(DigestSignTask.RESET,
		// "Inserire il pin e battere INVIO per firmare.");

		statusPanel.add(progressBar);

		southPanel.add(controlsPanel);
		southPanel.add(certPanel);
		southPanel.add(statusPanel);

		getContentPane().add(southPanel,
				debug ? BorderLayout.SOUTH : BorderLayout.CENTER);

		enableControls(false);

		findCert();

	}

	private void findCert() {

		long mechanism = algToMechanism(this.makeDigestOnToken, this.digestAlg,
				this.encAlg);

		if (mechanism == -1L)
			setStatus(ERROR, "Impossibile determinare il meccanismo!");
		else {

			// find certificate action
			initStatus(0, FindCertTask.FIND_MAXIMUM);

			// Create a new sign task.
			certTask = new FindCertTask(getCryptokiLib(), getSignerLabel(), log);
			// Create a timer.
			// NOTE: we define an action listener on the fly while
			// passing
			// an instance of it to the Timer constructor.
			findTimer = new Timer(ONE_SECOND,
					new java.awt.event.ActionListener() {

						public void actionPerformed(
								java.awt.event.ActionEvent evt) {

							setStatus(certTask.getCurrent(), certTask
									.getMessage());

							if (!certTask.isTokenPresent()) {
								progressBar.setIndeterminate(true);
								enableControls(false);
							} else {
								progressBar.setIndeterminate(false);
							}
							if (certTask.done()) {
								findTimer.stop();
								progressBar.setValue(progressBar.getMinimum());
								if (certTask.getCurrent() == FindCertTask.FIND_DONE) {
									Toolkit.getDefaultToolkit().beep();

									setCertificate(certTask.getCertificate());

									try {
										certArea.setText(getJavaCertificate()
												.getSubjectDN().toString());
									} catch (CertificateException e) {
										log
												.println("Error getting certificate Subject DN");
									}

								}

								if (!"".equals(dataArea.getText()))
									enableControls(true);
							}
						}// end of actionPerformed definition
					});// end of ActionListener definition and Timer
			// constructor call.
		}

		certTask.setMechanism(mechanism);
		certTask.go();
		findTimer.start();
	}

	public static void main(String[] args) {

		Security.insertProviderAt(new BouncyCastleProvider(), 3);

		String cryptoki = (args.length == 1) ? args[0] : null;

		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (UnsupportedLookAndFeelException ex) {
		} catch (IllegalAccessException ex) {
		} catch (InstantiationException ex) {
		} catch (ClassNotFoundException ex) {
		}

		GUITest frame = new GUITest("j4sign GUI Test", "true", cryptoki);

		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		frame.pack();

		Dimension d = Toolkit.getDefaultToolkit().getScreenSize();
		frame.setLocation((d.width - frame.getWidth()) / 2, (d.height - frame
				.getHeight()) / 2);

		frame.setVisible(true);

	}

	/**
	 * Prepares a signing procedure.
	 * 
	 * @param digestAlg
	 * @param encryptionAlg
	 * @param digestOnToken
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws CMSException
	 * @throws CertificateException
	 */
	private void openSignature(String digestAlg, String encryptionAlg,
			boolean digestOnToken) throws InvalidKeyException,
			SignatureException, NoSuchProviderException,
			NoSuchAlgorithmException, IOException, CMSException,
			CertificateException {

		this.msg = new CMSProcessableByteArray(dataArea.getText().getBytes(
				"UTF8"));

		this.cmsGenerator = new ExternalSignatureCMSSignedDataGenerator();

		this.signersCertList = new ArrayList();

		log.println("Certificate bytes:\n"
				+ formatAsHexString(getCertificate()));

		java.security.cert.X509Certificate javaCert = getJavaCertificate();

		this.signerInfoGenerator = new ExternalSignatureSignerInfoGenerator(
				digestAlg, encryptionAlg);
		this.signerInfoGenerator.setCertificate(javaCert);

		this.signersCertList.add(javaCert);

		this.bytesToSign = this.signerInfoGenerator.getBytesToSign(
				PKCSObjectIdentifiers.data, msg, "BC");

		if (!digestOnToken) {
			log.println("\nCalculating digest ...\n");

			MessageDigest md = MessageDigest.getInstance(digestAlg);
			md.update(bytesToSign);
			byte[] rawDigest = md.digest();

			log.println("Encapsulating in a DigestInfo...");

			byte[] dInfoBytes = encapsulateInDigestInfo(digestAlg, rawDigest);

			log.println("Adding Pkcs1 padding...");

			byte[] paddedBytes = applyPkcs1Padding(128, dInfoBytes);

			log.println("Encapsulated digest:\n"
					+ formatAsHexString(dInfoBytes));
			log.println("Done.");
			setEncodedDigest(encodeFromBytes(dInfoBytes));
		}

	}

	/**
	 * Starts a signing task in a separate thread.
	 * 
	 * @param digestOnToken
	 *            if true, the cryptoki - card takes care of digesting; raw
	 *            bytes to sign are passed to cryptoki functions.
	 */
	private void sign() {

		initStatus(0, DigestSignTask.SIGN_MAXIMUM);

		// Create a new sign task.
		signTask = new DigestSignTask(getCryptokiLib(), getSignerLabel(), log);

		// Create a timer.
		// NOTE: we define an action listener on the fly while
		// passing
		// an instance of it to the Timer constructor.
		signTimer = new Timer(ONE_SECOND, new java.awt.event.ActionListener() {

			public void actionPerformed(java.awt.event.ActionEvent evt) {
				setStatus(signTask.getCurrent(), signTask.getMessage());
				if (signTask.done()) {
					signTimer.stop();
					progressBar.setValue(progressBar.getMinimum());
					if (signTask.getCurrent() == DigestSignTask.SIGN_DONE) {
						Toolkit.getDefaultToolkit().beep();

						setEncryptedDigest(signTask.getEncryptedDigest());
						setCertificate(signTask.getCertificate());

						try {
							closeSignature();
						} catch (CertificateException e) {
							log.println("Error closing signature process:\n"
									+ e);
						}

					}
					enableControls(true);
				}
			}// end of actionPerformed definition
		});// end of ActionListener definition and Timer
		// constructor call.

		if (!this.makeDigestOnToken && getEncodedDigest() == null)
			setStatus(ERROR, "Digest non impostato");
		else {
			enableControls(false);
			if (!this.makeDigestOnToken)
				signTask.setDigest(decodeToBytes(getEncodedDigest()));
			else
				signTask.setDataStream(new ByteArrayInputStream(
						this.bytesToSign));

			long mechanism = algToMechanism(this.makeDigestOnToken,
					this.digestAlg, this.encAlg);

			if (mechanism == -1L)
				setStatus(ERROR, "Impossibile determinare il meccanismo!");
			else {
				signTask.setMechanism(mechanism);
				signTask.setPassword(pwd.getPassword());
				signTask.go();
				signTimer.start();
			}
		}
	}

	/**
	 * Terminates the signing procedure creating the signer information data
	 * structure.
	 * 
	 * @throws CertificateException
	 */
	private void closeSignature() throws CertificateException {
		if ((getCertificate() != null) && (getEncryptedDigest() != null)) {

			log.println("======== Encryption completed =========");
			log.println("Encrypted Digest bytes:\n"
					+ formatAsHexString(getEncryptedDigest()));

			this.signerInfoGenerator.setSignedBytes(getEncryptedDigest());

			this.cmsGenerator.addSignerInf(this.signerInfoGenerator);

			s.setEnabled(true);
			c.setEnabled(true);

		}
	}

	/**
	 * Creates the signed data structure, using signer infos precedently
	 * accumulated.
	 * 
	 * @return
	 * @throws CertStoreException
	 * @throws InvalidAlgorithmParameterException
	 * @throws CertificateExpiredException
	 * @throws CertificateNotYetValidException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws CMSException
	 */
	private CMSSignedData buildCMSSignedData() throws CertStoreException,
			InvalidAlgorithmParameterException, CertificateExpiredException,
			CertificateNotYetValidException, NoSuchAlgorithmException,
			NoSuchProviderException, CMSException {
		CMSSignedData s = null;

		if (this.signersCertList.size() != 0) {

			// Per passare i certificati al generatore li si incapsula
			// in un
			// CertStore.
			CertStore store = CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(this.signersCertList),
					"BC");

			log.println("Adding certificates ... ");
			this.cmsGenerator.addCertificatesAndCRLs(store);

			// Finalmente, si può creare il l'oggetto CMS.
			log.println("Generating CMSSignedData ");
			s = this.cmsGenerator.generate(this.msg, true);

			// Verifica

			log.println("\nStarting CMSSignedData verification ... ");
			// recupero dal CMS la lista dei certificati
			CertStore certs = s.getCertificatesAndCRLs("Collection", "BC");

			// Recupero i firmatari.
			SignerInformationStore signers = s.getSignerInfos();
			Collection c = signers.getSigners();

			log.println(c.size() + " signers found.");

			Iterator it = c.iterator();

			// ciclo tra tutti i firmatari
			int i = 0;
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
				Collection certCollection = certs.getCertificates(signer
						.getSID());

				if (certCollection.size() == 1) {
					// Iterator certIt = certCollection.iterator();
					// X509Certificate cert = (X509Certificate)
					// certIt.next();

					X509Certificate cert = (X509Certificate) certCollection
							.toArray()[0];
					log.println(i + ") Verifiying signature from:\n"
							+ cert.getSubjectDN());
					/*
					 * log.println("Certificate follows:");
					 * log.println("====================================");
					 * log.println(cert);
					 * log.println("====================================");
					 */
					if (signer.verify(cert, "BC")) {

						log.println("SIGNATURE " + i + " OK!");
					} else
						log.println("SIGNATURE " + i + " Failure!");
				} else
					log
							.println("There is not exactly one certificate for this signer!");
				i++;
			}
		}

		return s;
	}

	/**
	 * The "control center" of the class, mandatory to satisfy the
	 * java.awt.event.ActionListener interface contract.
	 * 
	 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
	 */
	public void actionPerformed(java.awt.event.ActionEvent e) {
		try {

			// sign action
			if (e.getSource() == pwd) {
				if ("".equals(dataArea.getText()))
					return;
				// disable text area modification.
				this.f.setEnabled(false);
				this.dataArea.setEditable(false);

				if (detectCardAndCriptoki()) {

					openSignature(CMSSignedDataGenerator.DIGEST_SHA256,
							CMSSignedDataGenerator.ENCRYPTION_RSA,
							this.makeDigestOnToken);
					// this launches the signing thread (see task above)
					sign();

				}// end of if( detect...

			}

			if (e.getSource() == f) {

				log.println("Loading file...");

				String filePath = System.getProperty("user.home")
						+ System.getProperty("file.separator");

				JFileChooser fc = new JFileChooser(new File(filePath));

				// Show dialog; this method does not return until dialog is
				// closed
				if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {

					// Get the selected file
					File file = fc.getSelectedFile();

					String typeDesc = fc.getTypeDescription(file);

					try {
						if (isTextFile(file)) {
							FileInputStream fis= new FileInputStream(file);
							
							ByteArrayOutputStream baos = new ByteArrayOutputStream();
							byte[] buffer = new byte[1024];
							int bytesRead = -1;
							
							while ((bytesRead = fis.read(buffer, 0, buffer.length)) >= 0) {
				                baos.write(buffer, 0, bytesRead);
				            }
							
							fis.close();
							log.println("File: '" + file.getAbsolutePath()
									+ "' loaded.");
							
							dataArea.setText(baos.toString());
							
							this.setFileToSign(file);
							
							if (!"".equals(dataArea.getText()) && getCertificate() != null)
								pwd.setEnabled(true);
							else
								pwd.setEnabled(false);

						} else {
							JOptionPane.showMessageDialog(null,
									"This does not appears as a text file!",
									"Error loading file.",
									JOptionPane.ERROR_MESSAGE);
							log
									.println("This does not appears as a text file!");
						}
					} catch (IOException ioe) {
						System.err.println(ioe);
					}

				}
			}

			if (e.getSource() == c) {
				log.println("Saving signer certificate");
				String filePath = System.getProperty("user.home")
						+ System.getProperty("file.separator");

				JFileChooser fc = new JFileChooser(new File(filePath));

				// Show dialog; this method does not return until dialog is
				// closed
				fc.showSaveDialog(this);

				// Get the selected file
				File file = fc.getSelectedFile();

				FileOutputStream fos = new FileOutputStream(file);
				fos.write(getCertificate());
				fos.flush();
				fos.close();

				log.println("Signer certificate saved to: "
						+ file.getAbsolutePath());
			}

			if (e.getSource() == s) {

				log.println("Building  CMSSignedData...");

				CMSSignedData cms = buildCMSSignedData();

				log.println("Saving signed message");

				String dirPath = System.getProperty("user.home");
				if (this.getFileToSign() != null) {
					dirPath = this.getFileToSign().getParent();
				}

				dirPath = dirPath + System.getProperty("file.separator");

				JFileChooser fc = new JFileChooser(new File(dirPath));

				String p7mFilePath = (this.getFileToSign() != null) ? this
						.getFileToSign().getAbsolutePath()
						+ ".p7m" : dirPath + "guitest.txt.p7m";

				fc.setSelectedFile(new File(p7mFilePath));

				// Show dialog; this method does not return until dialog is
				// closed
				fc.showSaveDialog(this);

				// Get the selected file
				File file = fc.getSelectedFile();

				FileOutputStream fos = new FileOutputStream(file);
				fos.write(cms.getEncoded());
				fos.flush();
				fos.close();

				log.println("Signed message saved to: "
						+ file.getAbsolutePath());
			}

		} catch (Exception ex) {
			log.println(ex.toString());

		} finally {
			pwd.setText("");
		}
	}

	/**
	 * Tests if a file is a text file; this method probably works only in a
	 * unicode system (fixme).
	 * 
	 * @param f
	 * @return
	 * @throws IOException
	 */
	private boolean isTextFile(File f) throws IOException {
		// Used for its canDisplay(char) method;
		Font testFont = new Font("Courier", Font.PLAIN, 10);
		FileReader fr = new FileReader(f.getAbsolutePath());

		int charRead = 0;
		boolean isText = true;
		while (((charRead = fr.read()) != -1) && isText)
			isText = Character.isISOControl((char) charRead)
					|| testFont.canDisplay((char) charRead);
		fr.close();

		return isText;
	}

	/**
	 * Takes text from data area and digests it.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	private void prepareDigestFromTextArea() throws NoSuchAlgorithmException,
			UnsupportedEncodingException {
		log.println("\nCalculating digest ...\n");
		java.security.MessageDigest md5 = java.security.MessageDigest
				.getInstance("MD5");
		md5.update(dataArea.getText().getBytes("UTF8"));
		byte[] digest = md5.digest();
		log.println("digest:\n" + formatAsHexString(digest));
		log.println("Done.");
		setEncodedDigest(encodeFromBytes(digest));
	}

	/**
	 * Decodes a base64 String in a normal Unicode string.
	 * 
	 * @param s
	 * @return
	 */
	public String decode(String s) {
		try {
			byte[] bytes = decodeToBytes(s);
			if (bytes != null)
				return new String(bytes, "UTF8");
		} catch (java.io.UnsupportedEncodingException e) {
			log.println("Errore di encoding: " + e);
		}
		return null;
	}

	/**
	 * Converts a base64 String in a byte array.
	 * 
	 * @param s
	 * @return
	 */
	public byte[] decodeToBytes(String s) {
		byte[] stringBytes = null;
		try {
			sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
			stringBytes = decoder.decodeBuffer(s);
		} catch (java.io.IOException e) {
			log.println("Errore di io: " + e);
		}
		return stringBytes;
	}

	/**
	 * Enables GUI controls.
	 * 
	 * @param enable
	 *            boolean
	 */

	private void enableControls(boolean enable) {

		pwd.setEnabled(enable);

	}

	/**
	 * Encodes a String into its base64 encoding version.
	 * 
	 * @param s
	 * @return
	 */
	public String encode(String s) {
		try {
			return encodeFromBytes(s.getBytes("UTF8"));
		} catch (java.io.UnsupportedEncodingException e) {
			log.println("Errore di encoding: " + e);
		}
		return null;
	}

	/**
	 * Creates the base64 encoding of a byte array.
	 * 
	 * @param bytes
	 * @return
	 */
	public String encodeFromBytes(byte[] bytes) {
		String encString = null;

		sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
		encString = encoder.encode(bytes);

		return encString;
	}

	/**
	 * Returns information about this applet.
	 * 
	 * @return a string of information about this applet
	 */
	public String getAppletInfo() {
		return "SignApplet\n" + "\n" + "This type was created in VisualAge.\n"
				+ "";
	}

	/**
	 * Returns the signer's certificate.
	 * 
	 * @return byte
	 */
	public byte[] getCertificate() {
		return certificate;
	}

	public java.security.cert.X509Certificate getJavaCertificate()
			throws CertificateException {

		// get Certificate
		java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
				.getInstance("X.509");
		java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(
				getCertificate());
		java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
				.generateCertificate(bais);

		return javaCert;
	}

	/**
	 * Returns the cryptoki library name.
	 * 
	 * @return java.lang.String
	 */
	private java.lang.String getCryptokiLib() {
		return cryptokiLib;
	}

	/**
	 * Returns the base64 encoding of the digest.
	 * 
	 * @return the base64 encoding.
	 */
	public String getEncodedDigest() {

		return this.encodedDigest;
	}

	/**
	 * Gets the digest encrypted with the private key of the signer.
	 * 
	 * @return
	 */
	public byte[] getEncryptedDigest() {
		return encryptedDigest;
	}

	/**
	 * Returns the label identifiyng the signer objects on the token.
	 * 
	 * @return
	 */
	private java.lang.String getSignerLabel() {
		return signerLabel;
	}

	/**
	 * Resets the progress bar status.
	 * 
	 * @param min
	 * @param max
	 */
	private void initStatus(int min, int max) {
		progressBar.setMinimum(min);
		progressBar.setMaximum(max);
		setStatus(min, "");
	}

	/**
	 * Tests if the program is in debug mode
	 * 
	 * @return boolean
	 */
	private boolean isDebugMode() {
		return debug;
	}

	/**
	 * Sets the signer certificate
	 * 
	 * @param newCertificate
	 */
	private void setCertificate(byte[] newCertificate) {
		certificate = newCertificate;
	}

	/**
	 * Sets the cryptoki library name.
	 * 
	 * @param newCryptokiLib
	 */
	private void setCryptokiLib(java.lang.String newCryptokiLib) {
		cryptokiLib = newCryptokiLib;
	}

	/**
	 * Sets the base64 encoded digest.
	 * 
	 * @param data
	 */
	public void setEncodedDigest(String data) {
		this.encodedDigest = data;
	}

	/**
	 * Sets the private-key encrypted digest
	 * 
	 * @param newEncryptedDigest
	 */
	public void setEncryptedDigest(byte[] newEncryptedDigest) {
		encryptedDigest = newEncryptedDigest;
	}

	/**
	 * Sets the label identifiyng the signer objects on the token.
	 * 
	 * @param newSignerLabel
	 */
	private void setSignerLabel(java.lang.String newSignerLabel) {
		signerLabel = newSignerLabel;
	}

	/**
	 * Sets the current status of the program (shown in the progress bar and
	 * with alerts in case of error.
	 * 
	 * @param code
	 * @param statusString
	 */
	private void setStatus(int code, String statusString) {
		if (code == DigestSignTask.ERROR) {
			pwd.setText("");
			Toolkit.getDefaultToolkit().beep();
			JOptionPane.showMessageDialog(null, statusString, "Errore!",
					JOptionPane.ERROR_MESSAGE);
			code = 0;
			statusString = "";
		}
		progressBar.setValue(code);
		progressBar.setString(statusString);
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
	 * Converts a byte array in its exadecimal representation.
	 * 
	 * @param bytes
	 * @return
	 */
	String formatAsHexString(byte[] bytes) {
		int n, x;
		String w = new String();
		String s = new String();
		for (n = 0; n < bytes.length; n++) {

			x = (int) (0x000000FF & bytes[n]);
			w = Integer.toHexString(x).toUpperCase();
			if (w.length() == 1)
				w = "0" + w;
			s = s + w + ((n + 1) % 16 == 0 ? "\n" : " ");
		}
		return s;
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

		PCSCHelper pcsc = new PCSCHelper(true);
		java.util.List cards = pcsc.findCards();
		cardPresent = !cards.isEmpty();
		if (!isForcingCryptoki()) {
			log.println("\n\n========= DETECTING CARD ===========");
			log.println("Trying to detect card via PCSC ...");
			log.println("Resetting cryptoki name");
			setCryptokiLib(null);
			if (cardPresent) {
				ci = (CardInfo) cards.get(0);
				setCryptokiLib(ci.getProperty("lib"));

				log.println("\n\nFor signing we will use card: '"
						+ ci.getProperty("description") + "' with criptoki '"
						+ ci.getProperty("lib") + "'");

			} else
				log.println("Sorry, no card detected!");
		} else
			System.out
					.println("\n\nFor signing we are forcing use of cryptoki: '"
							+ getCryptokiLib() + "'");

		log.println("=================================");

		return (getCryptokiLib() != null);
	}

	public File getFileToSign() {
		return fileToSign;
	}

	public void setFileToSign(File fileToSign) {
		this.fileToSign = fileToSign;
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



public void changedUpdate(DocumentEvent e) {
	// never fired for a plain text document
}


public void insertUpdate(DocumentEvent e) {
	// dataArea action
		if (!"".equals(dataArea.getText()) && getCertificate() != null)
			pwd.setEnabled(true);
		else
			pwd.setEnabled(false);
	
}

public void removeUpdate(DocumentEvent e) {
	// dataArea action
		if (!"".equals(dataArea.getText()) && getCertificate() != null)
			pwd.setEnabled(true);
		else
			pwd.setEnabled(false);
	
}

}