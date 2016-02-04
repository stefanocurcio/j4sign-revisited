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
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/examples/SimpleSignApplet.java,v 1.8 2014/08/13 12:41:49 resoli Exp $
 * $Revision: 1.8 $
 * $Date: 2014/08/13 12:41:49 $
 */

package it.trento.comune.j4sign.examples;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import it.trento.comune.j4sign.pcsc.CardInfo;
import it.trento.comune.j4sign.pcsc.PCSCHelper;
import it.trento.comune.j4sign.pkcs11.PKCS11Signer;

import java.awt.*;

import javax.swing.*;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

import java.security.cert.CertificateException;
import java.util.List;

/**
 * @deprecated This is old code not more maintained; see {@link PKCS11SignApplet} for
 * replacement.<br/>
 * <br/>
 * This is the client side part of the j4sign usage example in a web
 * environment.<br/>
 * <code>SimpleSignApplet</code> is <i>simple</i> in the sense that refined
 * GUI features are avoided (like multiple threads used to correctly implement
 * the progress bar), in favor to a clear exposition of specific signature
 * procedures.
 * <p>
 * The goal was to illustrate an approach in which the client side 
 * encryption, involving cryptographic token management via JNI, is completely
 * separated from server side CMS message building. This lightens the applet,
 * which has not to bear the weight of the BouncyCastle classes.
 * <p>
 * Note that in actual implementation of <code>SimpleSignApplet</code>
 * digesting is done on the server, and encapsulated in a digestInfo. Only digestInfo
 * is sent to the applet.
 * <p>
 * Another feature is the encapsulation of the JNI part (the excellent pkcs11
 * wrapper developed by IAIK of Graz University of Technology, and the pcsc
 * wrapper taken from Open Card Framework project), along with the corresponding
 * native libraries, in a standard Java Extension, named
 * <code>SmartCardAccess</code>. See {@link it.trento.comune.j4sign.installer}
 * and <a href="http://java.sun.com/j2se/1.4.2/docs/guide/plugin/developer_guide/extensions.html"
 * > Deploying Java Extensions<a>.<br>
 * The extension is deployed automatically the first time the applet is loaded.<br>
 * The ultimate dependency for the applet is the cryptoki library, which has to
 * be provided from the PKCS11 token manufacturer. The
 * {@link it.trento.comune.j4sign.pcsc.PCSCHelper} class uses the pcsc wrapper
 * trying to infer the correct library from the ATR string returned from the
 * token.
 * <p>
 * Some words about security; all downloaded jars, including the
 * <code>SmartCardAccess</code> extension, has to be signed in order to work;
 * this is needed for tho reasons:
 * <ul>
 * <li>the applet loads native libraries</li>
 * <li>the applet deploys a java extension.</li>
 * </ul>
 * This gives more confidence about signing software integrity.
 * <p>
 * The entire example, with the
 * {@link it.trento.comune.j4sign.examples.CMSServlet} server side counterpart,
 * is designed to permit the use of the standard JDK tools. The applet can be
 * executed with applet viewer tool (no HttpSession in the servlet, nor HTML
 * forms on the client side are used).<br>
 * This eases the use of an IDE for test and debugging; we use, and recommend,
 * the <a href="http://www.eclipse.org">Eclipse</a>) IDE.
 * <p>
 * N.B.: IN A REAL WORLD WEB APPLICATION SCENARIO, YOU CAN (AND SHOULD) TAKE
 * ADVANTAGE OF THE FULL SERVLET API, AND HTTP/HTML FEATURES.
 * <p>
 * 
 * Here are the <code>SimpleSignApplet</code> operations in detail; the applet
 * talks with the server (servlet) in HTTP:
 * <ol>
 * <li>The applet initialization method (init()) builds the GUI layout: a text
 * area in the center, and, in the bottom, a button to load data from server and
 * a password field.<br>
 * A detailed log is shown on System out (Java Plugin console).</li>
 * <li>When the "Load data" button is pressed, the non repudiation certificate is 
 * searched on the PKCS11 token. If such certificate is found a GET request is generated,
 * specifiying a <code>retrieve</code> parameter with value <code>DATA</code>;
 * the server returns the message to sign.<br>
 * Immediately after, another GET request is sent, specifiying a
 * <code>retrieve</code> parameter with value
 * <code>ENCODED_AUTHENTICATED_ATTRIBUTES</code>, and a <code>retrieve</code> parameter 
 * with the certificate as value; the server calculates (using also the certificate) 
 * the Authenticated Attributes data, SHA-256 digests and encapsulates them in a digestInfo.<br>
 * The digestInfo is returned to the applet.<br>
 * The message and a textual representation of the authenticated attributes are
 * presented in the text area.<br>
 * Note that authenticated attributes includes a timestamp, then even if the
 * message is the same, the digestInfo to encrypt change every time the
 * user loads the data from server.</li>
 * <li>When the user insert the password in the field and press return, the
 * signing process starts:<br>
 * <ol type="a">
 * <li>the PCSC layer is invoked to query for an inserted token, and if one is
 * found the relative PKCS#11 cryptoki is (hopefully) detected and loaded.</li>
 * <li>Then the token is checked for the required signature algorithm
 * (RSA_PKCS), and queried for a suitable (non repudiation) certificate - private key pair.</li> 
 * <li>Then the digestInfo is sent to the token for the encryption procedure.</li>
 * </ol>
 * <li>The signature is sent to the server via HTTP POST, along with the signer
 * certificate extracted from the token (The same that was already sent before).</li>
 * <li>The server acknowledges confirming signature verification and CMS
 * building and saving.</li>
 * </ol>
 * <p>
 * <b>N.B. note that in this example signature verification only ensures
 * integrity; a complete verification to ensure non-repudiation requires
 * checking the full certification path including the CA root certificate, and
 * CRL verification on the CA side. (Good stuff for a next release ...)</b>
 * 
 * @see it.trento.comune.j4sign.examples.CMSServlet
 * @author Roberto Resoli
 */
public class SimpleSignApplet extends JApplet implements
		java.awt.event.ActionListener {

	private JTextArea dataArea = null;

	private JButton loadButton = new JButton("Load Data");

	private JPasswordField pwd = new JPasswordField();

	private java.io.PrintStream log = null;

	private JProgressBar progressBar = null;

	private String textToSign = null;

	private String attrPrintout = null;

	private byte[] digestInfo = null;

	private byte[] encryptedDigest = null;

	private java.lang.String cryptokiLib = null;

	private java.lang.String signerLabel = null;

	private java.lang.String baseHttpUrl = null;

	private byte[] certificate = null;

	private static final short SEARCH_BY_PRIVATE_KEY = 0;

	private static final short SEARCH_BY_CERTIFICATE_KEY_USAGE = 1;

	private short OBJECT_SEARCH_CRITERION = SEARCH_BY_CERTIFICATE_KEY_USAGE;

	public static final int ERROR = -1;

	public static final int RESET = 0;

	public static final int DATA_LOADED = 1;

	public static final int SIGN_DONE = 2;

	public static final int POST_ERROR = -1;

	public static final int POST_OK_VERIFY_OK = 0;

	public static final int POST_OK_VERIFY_ERROR = 1;

	public static final String DEFAULT_BASE_HTTP_URL = "http://localhost:8080/sc/cmsservlet";

	/**
	 * The implementation of the callback method for ActionListener. Entry point
	 * for all applet operations: data loading, signature, data sending.
	 * 
	 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
	 */
	public void actionPerformed(java.awt.event.ActionEvent e) {
		try {
			if (e.getSource() == this.loadButton) {
				if (detectCardAndCriptoki()) {
					log
							.println("\n============= FIND CERTIFICATE START =============\n");
					findCertificate();
					log
							.println("\n=============  FIND CERTIFICATE END  =============\n");

					if (getCertificate() != null)
						if (loadData()) {
							this.pwd.setEnabled(true);
							this.loadButton.setEnabled(false);
							setStatus(DATA_LOADED,
									"Read carefully the text above. Type pin and press RETURN to sign.");
						} else
							setStatus(ERROR, "Cannot Load data from server");
				}
			}
			if (e.getSource() == this.pwd) {
				if (detectCardAndCriptoki()) {

					log
							.println("\n============= PKCS11 SIGNATURE START =============\n");
					sign();
					log
							.println("\n=============  PKCS11 SIGNATURE END  =============\n");

					int rc = sendSignatureAndCertificate();
					switch (rc) {
					case POST_ERROR:
						setStatus(SIGN_DONE,
								"Signature done - error sending data to server.");
						break;
					case POST_OK_VERIFY_OK:
						setStatus(SIGN_DONE,
								"Signature done - data sent to server and verified.");
						break;
					case POST_OK_VERIFY_ERROR:
						setStatus(SIGN_DONE,
								"Signature done - data sent to server but NOT verified!");
						break;
					default:
						break;
					}

					pwd.setEnabled(false);
					this.loadButton.setEnabled(true);
				} else
					setStatus(ERROR,
							"No token or no suitable objects on token.");

			}
		} catch (Exception ex) {
			log.println(ex.toString());
			setStatus(ERROR, ex.toString());

		} finally {
			pwd.setText("");

		}
	}

	/**
	 * Cleans up whatever resources are being held. If the applet is active it
	 * is stopped. Forces a system garbage collection to reclaim memory.
	 * 
	 * @see #init
	 * @see #start
	 * @see #stop
	 */
	public void destroy() {
		super.destroy();
		log.println("Destroying applet and garbage collecting...");
		// task = null;
		System.gc();
		log.println("Garbage collection done.");
		// insert code to release resources here
	}

	/**
	 * Gets the signer certificate.
	 * 
	 * @return byte the certificate bytes as extracted from the pkcs11 token.
	 */
	public byte[] getCertificate() {
		return certificate;
	}

	/**
	 * Gets the native cryptoki library name; this is the library provided by
	 * the token manufacturer that implements the PKCS#11 standard API.
	 * 
	 * @return java.lang.String
	 */
	private java.lang.String getCryptokiLib() {
		return cryptokiLib;
	}

	/**
	 * Returns the digest of the bytes to sign.
	 * 
	 * @return byte[] data to be sento to the token for encryption.
	 */
	public byte[] getDigestInfo() {
		return digestInfo;
	}

	/**
	 * The result of encryption of data obtained from {@link #getDigest()};
	 * Encryption is done on the token.
	 * 
	 * @return iaik.pkcs.pkcs7.SignedData
	 */
	public byte[] getEncryptedDigest() {
		return encryptedDigest;
	}

	/**
	 * The textual identifier of the objects related to the signer on a PKCS#11
	 * token; do not rely only on this to find objects; labels are manufacturer
	 * dependent.
	 * 
	 * @return java.lang.String
	 */
	private java.lang.String getSignerLabel() {
		return signerLabel;
	}

	/**
	 * Triggers three different HTTP GET requests against the server:
	 * <ol>
	 * <li>The first for retrieving the textual content to sign (the message)</li>
	 * <li>The second for retrieving the time-dependent bytes to sign (the
	 * authenticated attributes)</li>
	 * <li>The third for retrieving a textual rapresentetion of the bytes to
	 * sign (the authenticated attributes printout)</li>
	 * </ol>
	 * 
	 * The local digest value is updated according with the new bytes to sign.
	 * 
	 * @return true if all data retrieval operations were successful.
	 */
	private boolean loadData() {
		boolean dataLoaded = false;

		log.println("Retrieving data from server...");
		this.textToSign = retrieveTextToSign();
		byte[] bytesReceived = retrieveDigestInfo();
		if ((this.textToSign != null) && (bytesReceived != null)) {
			setDigestInfo(bytesReceived);
			this.attrPrintout = retrieveAuthenticatedAttributesPrintout();
			displayDataToSign();
			dataLoaded = true;
		}

		return dataLoaded;
	}

	/**
	 * Implements the HTTP GET request that returns the message to sign.
	 * 
	 * @return the message content to sign.
	 */
	private String retrieveTextToSign() {

		// StringBuffer buf = null;
		String result = null;
		try {
			// Create a URL for the desired page
			String base = (getBaseHttpUrl() != null) ? getBaseHttpUrl()
					: DEFAULT_BASE_HTTP_URL;
			String parms = "?" + URLEncoder.encode("retrieve", "UTF-8") + "="
					+ URLEncoder.encode("DATA", "UTF-8");

			URL url = new URL(base + parms);
			result = httpGet(url);
		} catch (MalformedURLException e) {
			log.println(e);
		} catch (IOException e) {
			log.println(e);
		}

		return result;

	}

	/**
	 * Implements the HTTP GET request that returns the data to digest and
	 * encrypt..
	 * 
	 * @return the "authenticated attributes" bytes.
	 */
	private byte[] retrieveDigestInfo() {

		// StringBuffer buf = null;
		byte[] result = null;
		try {
			// Create a URL for the desired page

			String base = (getBaseHttpUrl() != null) ? getBaseHttpUrl()
					: DEFAULT_BASE_HTTP_URL;
			
			//Patch from Alessandro (thanks!)
			//Send encoded cert to server
			sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder(); 
			String encodedCertificate = encoder.encode(getCertificate());
			
			String parms = "?"
					+ URLEncoder.encode("retrieve", "UTF-8")
					+ "="
					+ URLEncoder.encode("ENCODED_AUTHENTICATED_ATTRIBUTES",
							"UTF-8")+"&" + URLEncoder.encode("certificate", "UTF-8") + "=" + URLEncoder.encode(encodedCertificate, "UTF-8");

			URL url = new URL(base + parms);

			String data = httpGet(url);
			if (data != null) {
				log.println("Decoding...");
				String base64Bytes = data;
				sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
				result = decoder.decodeBuffer(base64Bytes);
				log.println("Data decoded.");
			}
		} catch (MalformedURLException e) {
			log.println(e);
		} catch (IOException e) {
			log.println(e);
		}

		return result;

	}

	/**
	 * Implements the HTTP GET request that returns the textual representation
	 * of the current "authenticated attributes". This is requested to the
	 * server because the applet is not equipped with the BouncyCastle classes
	 * required to decode the "authenticated attributes". The current digest is
	 * used as on the server a key to retrive the printout.
	 * 
	 * @return the authenticated attributes textual dump.
	 */
	private String retrieveAuthenticatedAttributesPrintout() {

		// StringBuffer buf = null;
		String result = null;
		try {
			// Create a URL for the desired page
			sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
			String base64Hash = encoder.encode(getDigestInfo());

			String base = (getBaseHttpUrl() != null) ? getBaseHttpUrl()
					: DEFAULT_BASE_HTTP_URL;
			String parms = "?"
					+ URLEncoder.encode("retrieve", "UTF-8")
					+ "="
					+ URLEncoder.encode("AUTHENTICATED_ATTRIBUTES_PRINTOUT",
							"UTF-8");
			parms += "&" + URLEncoder.encode("encodedhash", "UTF-8") + "="
					+ URLEncoder.encode(base64Hash, "UTF-8");
			URL url = new URL(base + parms);

			log.println(this.getDocumentBase().getHost());
			log.println(this.getDocumentBase().getPath());

			result = httpGet(url);

		} catch (MalformedURLException e) {
			log.println(e);
		} catch (IOException e) {
			log.println(e);
		}

		return result;

	}

	/**
	 * Generic implementation of a HTTP GET; used from the data retrieval
	 * methods.
	 * 
	 * @param url
	 *            the url to GET.
	 * @return the result of the GET method.
	 * @throws IOException
	 * 
	 * @see #retrieveTextToSign()
	 * @see #retrieveBytesToSign()
	 * @see #retrieveAuthenticatedAttributesPrintout()
	 */
	private String httpGet(URL url) throws IOException {
		String result = null;
		if ("http".equals(url.getProtocol())) {
			log.println("Getting attributes printout from: " + url);

			InputStream in = url.openStream();
			byte[] buffer = new byte[1024];
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int bytesRead,totalBytes = 0;
			while ((bytesRead = in.read(buffer, 0, buffer.length)) >= 0) {
				baos.write(buffer, 0, bytesRead);
				totalBytes += bytesRead;
			}
			in.close();

			result = baos.toString();
			log.println("Got "+ totalBytes + " bytes.");
		}

		return result;
	}

	
	/**
	 * Generic implementation of a HTTP POST; used from the data sending and retrieval
	 * methods.
	 * 
	 * @param url
	 *            the url to POST to.
	 * @param data
	 *            the data to POST.
	 * @return the result of the POST method.
	 * @throws IOException
	 * 
	 */
	private String httpPOST(URL url, String data) throws IOException {
		String result = null;
		if ("http".equals(url.getProtocol())) {
			URLConnection conn = url.openConnection();
			conn.setDoOutput(true);
			OutputStreamWriter wr = new OutputStreamWriter(conn
					.getOutputStream());
			wr.write(data);
			wr.flush();
			log.println("Data sent.");
			
			// Get the response
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn
					.getInputStream()));
			String line;
			if ((line = rd.readLine()) != null)
				result = line;
			
			wr.close();
			rd.close();
		}

		return result;
	}

	
	/**
	 * Implements of the HTTP POST that sends the encrypted digest and the
	 * signer certificate to the server.
	 * 
	 * @return an <code>int</code> result code of
	 *         {@link SimpleSignApplet#POST_ERROR} if the POST was not
	 *         completed, {@link SimpleSignApplet#POST_OK_VERIFY_ERROR} if the
	 *         POST was ok but there was a signature verification error,
	 *         {@link SimpleSignApplet#POST_OK_VERIFY_OK} if all was ok and the
	 *         CMS message file was written on the server filesystem.
	 */
	private int sendSignatureAndCertificate() {

		int resultCode = POST_ERROR;
		try {
			log.println("POSTing certificate and signature...");
			sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
			String base64Certificate = encoder.encode(getCertificate());
			String base64Signature = encoder.encode(getEncryptedDigest());

			// Construct data
			String data = URLEncoder.encode("certificate", "UTF-8") + "="
					+ URLEncoder.encode(base64Certificate, "UTF-8");
			data += "&" + URLEncoder.encode("signature", "UTF-8") + "="
					+ URLEncoder.encode(base64Signature, "UTF-8");

			// Send data
			URL url = new URL((getBaseHttpUrl() != null) ? getBaseHttpUrl()
					: DEFAULT_BASE_HTTP_URL);

			String result = httpPOST(url, data);
			if (result!=null) {
				// Process line...
				log.println("POST result: " + result);
				if (result.startsWith("OK"))
					resultCode = POST_OK_VERIFY_OK;
				else if (result.startsWith("ERROR"))
					resultCode = POST_OK_VERIFY_ERROR;
			}

		} catch (Exception e) {
			log.println("Error POSTing data: " + e);
		}

		return resultCode;

	}

	/**
	 * Initializes the applet; the applet accepts as optional parameters the
	 * label of the signer on the token, and the url of the running servlet to
	 * use for CMS operations. Another parameter can force the cryptoki library
	 * to use.
	 * 
	 * @see #start
	 * @see #stop
	 * @see #destroy
	 */
	public void init() {
		super.init();

		// card detected when signing.
		// detectCardAndCriptoki();

		if (getParameter("signerlabel") != null)
			setSignerLabel(getParameter("signerlabel"));

		if (getParameter("dataurl") != null)
			setBaseHttpUrl(getParameter("dataurl"));

		getContentPane().setLayout(new BorderLayout());

		log = System.out;

		log.println("Initializing PKCS11TestApplet ...");

		dataArea = new JTextArea();
		// dataArea.setText();

		JScrollPane dataScrollPane = new JScrollPane(dataArea);

		getContentPane().add(dataScrollPane, BorderLayout.CENTER);

		pwd.setPreferredSize(new Dimension(50, 20));
		pwd.addActionListener(this);
		pwd.setEnabled(false);

		loadButton = new JButton("Load Data");
		loadButton.addActionListener(this);

		JPanel southPanel = new JPanel();
		southPanel.setLayout(new BoxLayout(southPanel, BoxLayout.Y_AXIS));
		JPanel controlsPanel = new JPanel();
		JPanel statusPanel = new JPanel();

		statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.X_AXIS));

		controlsPanel.add(loadButton);
		controlsPanel.add(pwd);

		/*
		 * if (debug) { controlsPanel.add(enc); controlsPanel.add(dec);
		 * 
		 * controlsPanel.add(vff); controlsPanel.add(v); }
		 */

		progressBar = new JProgressBar();
		progressBar.setStringPainted(true);

		initStatus(RESET, SIGN_DONE);
		setStatus(RESET, "Press 'Load Data' to retrieve data from server.");

		statusPanel.add(progressBar);

		southPanel.add(controlsPanel);
		southPanel.add(statusPanel);

		getContentPane().add(southPanel, BorderLayout.SOUTH);

		/*
		 * getContentPane().add( southPanel, debug ? BorderLayout.SOUTH :
		 * BorderLayout.CENTER);
		 */
		// retrive data to sign from html form.
		// retriveEncodedDigestFromForm();
	}

	/**
	 * Shows on the text area of the applet the message content and the current
	 * authenticated attributes dump (that includes the timestamp that will be
	 * signed).
	 * 
	 */
	private void displayDataToSign() {

		String contentText = "The text you are about to sign is between 'START' and 'END' lines:\n"
				+ "================START============\n"
				+ this.textToSign
				+ "\n================ END ============\n";

		String attrText = "You are also about to sign a set informations (Authenticated Attributes),\n"
				+ "including UTC time taken from server. These informations are detailed below:\n\n"
				+ this.attrPrintout;

		this.dataArea.setText(contentText + attrText);
	}

	/**
	 * Initializes the status bar, extabilishing the value range.
	 * 
	 * @param min
	 *            minimum value for the status bar.
	 * @param max
	 *            maximum value for the status bar.
	 */
	private void initStatus(int min, int max) {
		progressBar.setMinimum(min);
		progressBar.setMaximum(max);
		setStatus(min, "");
	}

	/**
	 * Manages status messages displayed on the status bar. And error messages
	 * shown on a MessageBox.
	 * 
	 * @param code
	 * @param statusString
	 */
	private void setStatus(int code, String statusString) {
		if (code == ERROR) {
			pwd.setText("");
			Toolkit.getDefaultToolkit().beep();
			JOptionPane.showMessageDialog(null, statusString, "Error!",
					JOptionPane.ERROR_MESSAGE);
			code = 0;
			statusString = "";
		}
		progressBar.setValue(code);
		progressBar.setString(statusString);
	}

	/**
	 * This triggers the PCSC wrapper stuff; a {@link PCSCHelper} class is used
	 * to detect reader and token presence, trying also to provide a candidate
	 * PKCS#11 cryptoki for it; detection is bypassed if an applet parameter
	 * forcing cryptoki selection is provided.
	 * 
	 * @return true if a token with corresponding candidate cryptoki was
	 *         detected.
	 * @throws IOException
	 */
	private boolean detectCardAndCriptoki() throws IOException {
		CardInfo ci = null;
		boolean cardPresent = false;
		log.println("\n\n========= DETECTING CARD ===========");

		log.println("Resetting cryptoki name");
		setCryptokiLib(null);

		if (getParameter("cryptokilib") != null) {
			log
					.println("Getting cryptoki name from Applet parameter 'cryptokilib': "
							+ getParameter("cryptokilib"));
			setCryptokiLib(getParameter("cryptokilib"));
		} else {
			log.println("Trying to detect card via PCSC ...");
			// JNIUtils jni = new JNIUtils();
			// jni.loadLibrary("OCFPCSC1");
			// jni.loadLibrary("pkcs11wrapper");

			PCSCHelper pcsc = new PCSCHelper(true);
			List cards = pcsc.findCards();
			cardPresent = !cards.isEmpty();
			if (cardPresent) {
				ci = (CardInfo) cards.get(0);
				log.println("\n\nFor signing we will use card: '"
						+ ci.getProperty("description") + "' with criptoki '"
						+ ci.getProperty("lib") + "'");
				setCryptokiLib(ci.getProperty("lib"));

			} else
				log.println("Sorry, no card detected!");
		}
		log.println("=================================");
		return ((ci != null) || (getCryptokiLib() != null));
	}

	/**
	 * Inserire qui la descrizione del metodo. Data di creazione: (10.05.01
	 * 14.28.07)
	 * 
	 * @param newCertificate
	 *            byte
	 */
	private void setCertificate(byte[] newCertificate) {
		certificate = newCertificate;
	}

	/**
	 * Sets the native PKCS#11 implementation to use.
	 * 
	 * @param newCryptokiLib
	 *            java.lang.String name of the native library
	 */
	private void setCryptokiLib(java.lang.String newCryptokiLib) {
		cryptokiLib = newCryptokiLib;
		log.println("Using cryptoki:\t" + getCryptokiLib());
	}

	/**
	 * Sets the digest.
	 * 
	 * @param newDigest
	 *            byte[] containing the digest value to set.
	 */
	public void setDigestInfo(byte[] newDigestInfo) {
		digestInfo = newDigestInfo;
	}

	/**
	 * Sets the encrypted digest.
	 * 
	 * @param newEncryptedDigest
	 *            byte[] containing the encrypted digest value to set..
	 */
	public void setEncryptedDigest(byte[] newEncryptedDigest) {
		encryptedDigest = newEncryptedDigest;
	}

	/**
	 * The label to use to retrieve signer - related objects on the token.
	 * 
	 * @param newSignerLabel
	 *            java.lang.String the signer identifier on the token.
	 */
	private void setSignerLabel(java.lang.String newSignerLabel) {
		signerLabel = newSignerLabel;
		log.println("Using signer:\t" + getSignerLabel() + "\n");
	}


	/**
	 * Triggers the digest encryption on the token, using services provided by
	 * {@link PKCS11Signer} class. Different criteria can be used to find
	 * relevant objects on the key: the default implementation here tries to act
	 * in order to build an italian legal-value document. A Certificate carrying
	 * an KeyUsage extension of non-repudiation marked critical is searched; if
	 * found the corresponding private key is used to sign. A real-world
	 * application should consent the user the certificate for signing.
	 * 
	 * @throws CertificateException
	 */
	public void sign() throws CertificateException {
		if (getDigestInfo() == null)
			log.println("ERRORE, DigestInfo non impostato");
		else {
			PKCS11Signer helper = null;
			String signerLabel = getSignerLabel();
			try {

				helper = new PKCS11Signer(getCryptokiLib(),
						PKCS11Constants.CKM_RSA_PKCS, log);

				helper.openSession(pwd.getPassword());

				long privateKeyHandle = -1L;
				long certHandle = -1;

				byte[] encDigestBytes = null;
				byte[] certBytes = null;

				switch (OBJECT_SEARCH_CRITERION) {
				case SEARCH_BY_PRIVATE_KEY:
					log.println("Searching objects from signature key ...");

					if (signerLabel != null)
						// using labels for searching objects.
						privateKeyHandle = helper
								.findSignatureKeyFromLabel(signerLabel);
					else
						// Using first private key found
						privateKeyHandle = helper.findSignatureKey();

					if (privateKeyHandle > 0) {
						encDigestBytes = helper.signDataSinglePart(
								privateKeyHandle, getDigestInfo());

						certHandle = helper
								.findCertificateFromSignatureKeyHandle(privateKeyHandle);
						certBytes = helper.getDEREncodedCertificate(certHandle);
					} else
						log.println("\nNo private key found on token!");
					break;

				case SEARCH_BY_CERTIFICATE_KEY_USAGE:
					log
							.println("Searching objects from certificate key usage ...");
					certHandle = helper
							.findCertificateWithNonRepudiationCritical();
					if (certHandle > 0) {
						privateKeyHandle = helper
								.findSignatureKeyFromCertificateHandle(certHandle);
						if (privateKeyHandle > 0)
							encDigestBytes = helper.signDataSinglePart(
									privateKeyHandle, getDigestInfo());
						else
							log
									.println("\nNo private key corrisponding to certificate found on token!");

						certBytes = helper.getDEREncodedCertificate(certHandle);

					} else
						log
								.println("\nNo certificate with required extension found on token!. ");

					break;

				default:
					log.println("Object search criterion not found.");
					break;
				}

				log.println("\nEncrypted digest:\n"
						+ formatAsHexString(encDigestBytes));

				log.println("\nDER encoded Certificate:\n"
						+ formatAsHexString(certBytes));

				setEncryptedDigest(encDigestBytes);
				setCertificate(certBytes);

			} catch (TokenException e) {
				log.println("sign() Error: " + e);
				// log.println(PKCS11Helper.decodeError(e.getCode()));
				// log.println(PKCS11Helper.decodeError(e.getCode()));

			} catch (IOException ioe) {
				log.println(ioe);
			} catch (UnsatisfiedLinkError ule) {
				log.println(ule);
			} finally {
				if (helper != null) {
					try {
						helper.closeSession();
						log.println("Sign session Closed.");
					} catch (PKCS11Exception e2) {
						log.println("Error closing session: " + e2);
					}

					try {
						helper.libFinalize();
						log.println("Lib finalized.");
					} catch (Throwable e1) {
						// TODO Auto-generated catch block
						log.println("Error finalizing criptoki: " + e1);
					}

				}
				helper = null;
				System.gc();
			}

		}
	}

	private void findCertificate() throws CertificateException {

		PKCS11Signer helper = null;
		String signerLabel = getSignerLabel();
		try {

			helper = new PKCS11Signer(getCryptokiLib(), log);

			log.println("Finding a token supporting required mechanism and "
					+ "containing a suitable" + "certificate...");

			long t = helper.findSuitableToken(PKCS11Constants.CKM_RSA_PKCS);
			if (t != -1L) {

				helper.setMechanism(PKCS11Constants.CKM_RSA_PKCS);
				helper.setTokenHandle(t);

				helper.openSession();

				long certHandle = -1;

				byte[] certBytes = null;

				switch (OBJECT_SEARCH_CRITERION) {

				case SEARCH_BY_CERTIFICATE_KEY_USAGE:
					log
							.println("Searching objects from certificate key usage ...");
					certHandle = helper
							.findCertificateWithNonRepudiationCritical();

					if (certHandle >= 0)
						certBytes = helper.getDEREncodedCertificate(certHandle);
					else
						log
								.println("\nCannot find any non-Repudiation certificate on token!. ");

					break;

				default:
					log.println("Object search criterion not found.");
					break;
				}
				if (certBytes != null)
					log.println("\nDER encoded Certificate:\n"
							+ formatAsHexString(certBytes));

				setCertificate(certBytes);

			}

		} catch (TokenException e) {
			log.println("sign() Error: " + e);

		} catch (IOException ioe) {
			log.println(ioe);
		} catch (UnsatisfiedLinkError ule) {
			log.println(ule);
		} finally {
			if (helper != null) {
				try {
					helper.closeSession();
					log.println("Sign session Closed.");
				} catch (PKCS11Exception e2) {
					log.println("Error closing session: " + e2);
				}

				try {
					helper.libFinalize();
					log.println("Lib finalized.");
				} catch (Throwable e1) {
					log.println("Error finalizing criptoki: " + e1);
				}

			}
			helper = null;
			System.gc();
		}

	}

	/**
	 * Called to start the applet. You never need to call this method directly,
	 * it is called when the applet's document is visited.
	 * 
	 * @see #init
	 * @see #stop
	 * @see #destroy
	 */
	public void start() {
		super.start();
		log.println("Starting applet ...");

		// insert any code to be run when the applet starts here
	}

	/**
	 * Called to stop the applet. It is called when the applet's document is no
	 * longer on the screen. It is guaranteed to be called before destroy() is
	 * called. You never need to call this method directly.
	 * 
	 * @see #init
	 * @see #start
	 * @see #destroy
	 */
	public void stop() {
		super.stop();
		log.println("stopping...");
		// insert any code to be run when the applet is stopped here
	}

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

	public java.lang.String getBaseHttpUrl() {
		return baseHttpUrl;
	}

	public void setBaseHttpUrl(java.lang.String baseHttpUrl) {
		this.baseHttpUrl = baseHttpUrl;
	}
}