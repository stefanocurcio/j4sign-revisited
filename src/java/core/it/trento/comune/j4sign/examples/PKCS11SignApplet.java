/**
 *  j4sign - an open, multi-platform digital signature solution
 *  Copyright (c) 2004 Roberto Resoli - Servizio Sistema Informativo - Comune di Trento.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
/*
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/examples/PKCS11SignApplet.java,v 1.15 2014/11/04 12:28:04 resoli Exp $
 * $Revision: 1.15 $
 * $Date: 2014/11/04 12:28:04 $
 */
package it.trento.comune.j4sign.examples;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import it.trento.comune.j4sign.pcsc.CardInfo;
import it.trento.comune.j4sign.pcsc.PCSCHelper;
import netscape.javascript.JSObject;

import javax.net.ssl.HttpsURLConnection;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;


/**
 * <p>
 * This is an implementation of a full-featured signing applet in a web
 * environment.<br/>
 * <code>PKCS11SignApplet</code> sequence of operation follows:</p>
 * <ol>
 * <li>Detects insertion of PKCS11 tokens (using pkcs11 api only)</li>
 * <li>Extracts signature certificates from the token, sending it to the server.</li>
 * <li>Receives from the server data to be signed, along with signature time; at the same time,
 * triggers streaming and visualization of the document to be signed via javascript.</li>
 * <li>Asks PIN to the user and starts a signature session on the token</li>
 * <li>Receives raw signature from the token and sends it to the server which creates the CMS envelope.</li>
 * </ol>
 *  <br/>
 * All the communication between the applet and the server is done using HTTP GET and POST methods.<br/>
 * <br/>
 * The applet can also expose some data via javascript to the embedding HTML page.
 * <br/>
 * <p>
 * <strong>!!! BE CAREFUL !!!</strong><br/>
 * THE APPLET RELIES HEAVILY ON BINARY DIGEST RECEIVED FROM THE SERVER, AND DOES NOT COMPUTE ITSELF THE DIGEST. <br/>
 * THIS CAN EXPOSE THE CLIENT TO THE RISK OF SIGNING DATA DIFFERENT FROM WHAT HE INTENDED, IF THE SERVER IS COMPROMISED. <br/>
 * HENCE YOU SHOULD USE THE APPLET ONLY IN A VERY WELL CONTROLLED ENVIRONMENT, AND THE SERVER SHOULD BE AUTHENTICATED <br/> 
 * IN A STRONG MANNER (USE OF SSL/TLS IS <strong>STRONGLY</strong> SUGGESTED).<br/>
 * FURTHERMORE, THE PROBLEM OF DISPLAYING THE DOCUMENT TO BE SIGNED (THE "TRUSTED VIEWER" PROBLEM) IS ENTIRELY LEFT <br/>
 * TO THE WEB APPLICATION; WE REMIND THAT A CORRECT PRESENTATION OF THE DOCUMENT IS MANDATORY FOR THE LEGAL VALUE <br/>
 * OF THE SIGNATURE, ACCORDING TO ITALIAN DIGITAL SIGNATURE LAW.<br/>
 * </p>
 * <p>
 * Trying to approach these issues, and for dealing with CMS enveloping, j4sign provides a server side companion for the applet, 
 * <strong>{@link it.trento.comune.j4sign.cms.utils.CMSBuilder}</strong>.<br/>
 * It is designed for answering to applet requests, an in particular for streaming content to be signed<br/>
 * in a synchronized way with digest generation, checking correctness on the fly.
 * </p>
 * <p>
 * The native library requirements for dealing with the tokens (the JNI part, 
 * such as the excellent pkcs11 wrapper developed by IAIK of Graz University of Technology, <br/>
 * and the pcsc wrapper taken from Open Card Framework project), along with the corresponding
 * native libraries, are encapsulated in a standard Java Extension, named<br/>
 * <code>SmartCardAccess</code>. See {@link it.trento.comune.j4sign.installer}
 * and <a href="http://docs.oracle.com/javase/tutorial/ext/basics/index.html">Creating and Using Extensions</a>.
 * <br/>
 * The extension is deployed automatically the first time the applet is loaded.<br/>
 * The ultimate dependency for the applet is the cryptoki library, which <strong>has</strong> to
 * be provided by the PKCS11 token manufacturer. The
 * {@link it.trento.comune.j4sign.pcsc.PCSCHelper} class uses the pcsc wrapper<br/>
 * trying to infer the correct library from the ATR string returned from the
 * token.
 * </p>
 * <p>
 * Some words about security; all downloaded jars, including the
 * <code>SmartCardAccess</code> extension, has to be signed in order to work;
 * this is needed for many reasons:
 * <ul>
 * <li>the applet loads native libraries</li>
 * <li>the applet deploys a java extension.</li>
 * </ul>
 * <br/>
 * This should give also more confidence about signing software integrity.<br/>
 * </p>
 * <p>
 * Note that recent java 7 JVMs have stricter policies about Applets running outside the sandbox,<br/>
 * and many jar manifest attributes are now mandatory.
 * </p>
 * <p>
 * The applet "may script" and is "scriptable", that is it exposes its public
 * methods to java script on the page it is embedded into, and can call java
 * script functions defined in that page.<br/>
 * Special-named java script functions are indeed used to:
 * <li>Asking visualization of the document to be signed: <code>viewDocument()</code></li>
 * <li>Return to the page the data to be signed: <code>setDigest()</code></li>
 * <li>Return to the page the encryptedDigest: <code>setDigestFirmato()</code></li>
 * <li>Return to the page the signer certificate extracted from the card: <code>setCertificato()</code></li>
 * <li>Submitting the page right after signature is completed: <code>eseguiSubmit()</code></li><br/>
 * Here is a fragment of a suitable page:<code><br/>
 *
 * <pre>
 *  &lt;head&gt;
 *   &lt;script language=&quot;JavaScript&quot;&gt;
 *        function eseguiSubmit(){
 *           document.firmaform.submit();
 *        }
 *        function setDigest(aString){
 *           document.firmaform.digestDomandaBASE64.value=aString;
 *        }
 *        function setDigestFirmato(aString){
 *           document.firmaform.digestDomandaFirmatoBASE64.value=aString;
 *        }
 *        function setCertificato(aString){
 *           document.firmaform.certificatoBASE64.value=aString;
 *        }
 *        
 *        //IE insists to cache requests, add viewcount parameter for changing url 
 *        //at each view request.
 *        var viewcount=0;
 *        
 *        function viewDocument(hash){
 *		   	document.getElementById('doctosign').src="viewdocument?datahash="+hash+"&vc="+viewcount++;
 *        }
 *   &lt;/script&gt;
 *   &lt;/head&gt;
 *   &lt;body&gt;
 *  &lt;div align=center&gt;
 *  
 *  &lt;iframe id="doctosign" src="about:blank" width="100%" height="500"&gt;
 *      &lt;p&gt;Your browser does not support iframes&lt;/p&gt;  
 *	&lt;/iframe&gt;
 *  
 *  &lt;strong&gt;Tutti i dati nei campi della form sono codificati BASE64&lt;/strong&gt;
 *  
 *  &lt;form action=&quot;.&quot; name=&quot;firmaform&quot; method=&quot;POST&quot; &gt;
 *  &lt;strong&gt;Digest&lt;/strong&gt;&lt;br&gt;
 *  &lt;input type=&quot;test&quot; name=&quot;digestDomandaBASE64&quot; value=&quot;&quot;  size=&quot;68&quot; /&gt;&lt;br&gt;
 *  &lt;strong&gt;Digest crittato&lt;/strong&gt;&lt;br&gt;
 *  &lt;textarea name=&quot;digestDomandaFirmatoBASE64&quot;  rows=&quot;5&quot; cols=&quot;64&quot; &gt;&lt;/textarea&gt;&lt;br&gt;
 *  &lt;strong&gt;Certificato&lt;/strong&gt;&lt;br&gt;
 *  &lt;textarea name=&quot;certificatoBASE64&quot; rows=&quot;5&quot; cols=&quot;64&quot;  &gt;&lt;/textarea&gt;&lt;br&gt;
 *  &lt;/form&gt;
 *  
 *  &lt;applet height=&quot;150&quot; width=&quot;600&quot; code=&quot;dummy&quot;&gt;
 *  &nbsp;&nbsp;&lt;param name=&quot;jnlp_href&quot; value=&quot;https://my.web.site//my-application/j4sign-pkcs11-applet.jnlp&quot;&gt;
 *  &nbsp;&nbsp;&lt;param name=&quot;singleSignature&quot; value=&quot;&lt;%=(session.getAttribute(&quot;doclist&quot;) == null)%&gt;&quot;&gt;
 *  &nbsp;&nbsp;&lt;param name=&quot;digestPath&quot; value=&quot;digest&quot;&gt;
 *  &nbsp;&nbsp;&lt;param name=&quot;encryptedDigestPath&quot; value=&quot;encrypteddigest&quot;&gt;
 *  &nbsp;&nbsp;&lt;param name=&quot;datahash&quot; value=&quot;${pi.contentHash}&quot;&gt;
 *  &lt;/applet&gt;
 *  &lt;/div&gt;
 * </pre>
 * </code>
 * <p>Some parameters are to be generated dinamically, in this case (taken form a JSP) via Java and JSTL expressions. <br/>
 * In the above example, the applet is deployed via JNLP, using an xml descriptor (the j4sign-pkcs11-applet.jnlp) that provides all<br/>
 * the standard parameters in the deployment scenario. In particular, you can provide a central location <br/>
 * for the applet, avoiding to embed it in all applications.</p> <br/>
 * Here follows an example:<code><br/>
 *
 * <pre>
 * &lt;?xml version="1.0" encoding="UTF-8"?&gt;
 * &lt;jnlp spec="1.0+" codebase="" href=""&gt;
 *     &lt;information&gt;
 *         &lt;title&gt;j4sign signature Applet&lt;/title&gt;
 *         &lt;vendor&gt;My firm name&lt;/vendor&gt;
 *     &lt;/information&gt;
 *     &lt;resources&gt;
 *         &lt;!-- Application Resources --&gt;
 *         &lt;j2se version="1.7+"/&gt;
 *         &lt;jar href="https://my.web.site/signature/SignatureApplet-signed.jar" main="true" /&gt;
 *     &lt;/resources&gt;
 *     &lt;applet-desc
 *          name="Signer"
 *          main-class="it.trento.comune.j4sign.examples.PKCS11SignApplet"
 *          width="600"
 *          height="150"&gt;
 *    	&lt;param name="mayscript" value="true" /&gt;
 *    	&lt;param name="scriptable" value="true" /&gt;
 *     &lt;/applet-desc&gt;
 *     &lt;security&gt;
 *     	&lt;all-permissions/&gt;
 *     &lt;/security&gt;
 * &lt;/jnlp&gt;
 * </pre>
 * </code><br/>
 * A note about applet parameters:
 * <h3>Inside applet tag</h3>
 * <ul>
 * <li><code>jnlp_href</code>: URI of the jnlp descriptor.</li>
 * <li><code>singleSignature</code>: boolean, whether this applet is going to sign one document or iterate over many ones.</li>
 * <li><code>digestPath</code>: path for POSTing certificate and receiving data to sign.</li>
 * <li><code>encryptedDigestPath</code>: path for POSTing raw signature.</li>
 * <li><code>datahash</code>: hash of the content to be signed. It is displayed by the applet, and checked server side when applet triggers document streaming.</li>
 * </ul>
 * <h3>Inside jnlp descriptor</h3>
 * <ul>
 * <li><code>mayscript</code>: if true, the applet may call javascript functions on the embedding page.</li>
 * <li><code>scriptable</code>: if true, the applet may have public method called by javascript functions on the embedding page.</li>
 * </ul>
 * <h3>Optional parameters:</h3>
 * <ul>
 * <li><code>submitAfterSigning</code>: if true, automatically submits the form after a successful
 * signature, calling the <code>eseguiSubmit()</code> javascript function.<br/>
 * Default value: <code>true</code></li>
 * <li><code>debug</code> adds a scroll panel for viewing debug informations; set applet height to more than 200 to see the content.<br/>
 * Default value: <code>false</code></li>
 * <li><code>cryptokilib</code> name of the cryptoki library to load. It has to be inside PATH. This bypasses detection mechanism via ATR.</li>
 * 
 * </ul>
 * 
 * @see it.trento.comune.j4sign.examples.SimpleSignApplet
 * @author Roberto Resoli
 */

public class PKCS11SignApplet extends JApplet implements
		java.awt.event.ActionListener {

	private JPasswordField pwd = null;
	
	private JTextArea certLabelArea = null;
	private JTextArea certValueArea = null;
	
	private JButton sd = null;

	private JButton s = null;

	private JTextArea logArea = null;

	private DigestSignTask dsTask = null;

	private FindCertTask certTask = null;

	private Timer findTimer = null;

	private JTextField signingTimeGMT = null;

	private JTextField hashField = null;

	private Timer timer = null;

	

	private JProgressBar progressBar = null;

	boolean debug = false;

	boolean singleSignature = true;

	boolean submitAfterSigning = true;

	private String encodedDigest = null;

	private byte[] encryptedDigest;

	private java.io.PrintStream log = null;

	public final static int ONE_SECOND = 1000;

	public final static String VERSION = "0.0.0.1";

	private java.lang.String cryptokiLib = null;

	private java.lang.String digestPath = null;

	private java.lang.String encryptedDigestPath = null;

	private byte[] certificate = null;

	private boolean makeDigestOnToken = false;

	private final static String DIGEST_MD5 = "1.2.840.113549.2.5";

	private final static String DIGEST_SHA1 = "1.3.14.3.2.26";

	private final static String DIGEST_SHA256 = "2.16.840.1.101.3.4.2.1";

	private final static String ENCRYPTION_RSA = "1.2.840.113549.1.1.1";

	private String digestAlg = DIGEST_SHA256;

	private String encAlg = ENCRYPTION_RSA;

	private String encodedContentHash = null;

	private HashMap<String,String> labels;

	public String getEncodedContentHash() {
		return encodedContentHash;
	}

	public void setEncodedContentHash(String encodedContentHash) {
		this.encodedContentHash = encodedContentHash;
		if (this.hashField != null)
			this.hashField.setText(this.encodedContentHash);
	}

	private short iteration = 1;

	/**
	 * Initializes the applet.<br/>
	 * Note that it is possible to force the cryptoki library to load, using the<br/>
	 * <code>cryptokilib</code> applet parameter.<br/>
	 * 
	 * @see #start
	 * @see #stop
	 * @see #destroy
	 */
	public void init() {

		super.init();

		System.out.println("Initializing PKCS11SignApplet ...");

		labels = new HashMap<String, String>();
		labels.put("GIVENNAME","Nome");
		labels.put("SURNAME","Cognome");
		labels.put("DNQ","ID unico presso il certificatore");
		labels.put("O","Ragione sociale");
		labels.put("SERIALNUMBER","Codice Fiscale/Partita IVA");

		/*
		 * System.out.println("Version: "+this.VERSION);
		 * 
		 * iaik.security.provider.IAIK.addAsProvider(true);
		 */

		/*if (getParameter("debug") != null)
			debug = Boolean.valueOf(getParameter("debug")).booleanValue();*/
		debug = false;

	/*	if (getParameter("singleSignature") != null)
			singleSignature = Boolean.valueOf(getParameter("singleSignature"))
					.booleanValue();*/
		singleSignature = true;

		/*if (getParameter("submitAfterSigning") != null)
			submitAfterSigning = Boolean.valueOf(
					getParameter("submitAfterSigning")).booleanValue();*/
		submitAfterSigning = false;

		// relative path on server for CAdES digest
		if (getParameter("digestPath") != null)
			setDigestPath(getParameter("digestPath"));

		// relative path on server for returning encrypted digest/retrieving
		// next digest
		if (getParameter("encryptedDigestPath") != null)
			setEncryptedDigestPath(getParameter("encryptedDigestPath"));

		if (getParameter("cryptokilib") != null)
			setCryptokiLib(getParameter("cryptokilib"));

		if (getParameter("datahash") != null)
			this.encodedContentHash = getParameter("datahash");

		System.out.println("\nUsing cryptoki:\t" + getCryptokiLib());

		getContentPane().setLayout(new BorderLayout());

		if (false)
			log = System.out;
		else {
			logArea = new JTextArea();
			logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

			log = new PrintStream(new JTextAreaOutputStream(logArea), true);

			JScrollPane logScrollPane = new JScrollPane(logArea);
			logScrollPane.setPreferredSize(new Dimension(600, 200));

			//if debug, log is at CENTER, and controls at SOUTH (see after)
			getContentPane().add(logScrollPane, BorderLayout.CENTER);
		}

		UIManager.put("ProgressBar.background", Color.WHITE); //colour of the background
		UIManager.put("ProgressBar.foreground", Color.DARK_GRAY);  //colour of progress bar
		UIManager.put("ProgressBar.selectionBackground", Color.DARK_GRAY);  //colour of percentage counter on black background
		UIManager.put("ProgressBar.selectionForeground", Color.WHITE);
		UIManager.put("ProgressBar.border", BorderFactory.createLineBorder(Color.DARK_GRAY));
		UIManager.put("PasswordField.border", BorderFactory.createLineBorder(Color.DARK_GRAY));

		JPanel southPanel = new JPanel();
		southPanel.setBackground(Color.WHITE);
		southPanel.setForeground(Color.GRAY);
		southPanel.setLayout(new BoxLayout(southPanel, BoxLayout.Y_AXIS));


		JPanel controlsPanel = new JPanel();
		controlsPanel.setBackground(Color.WHITE);
		controlsPanel.setForeground(Color.DARK_GRAY);

		JPanel statusPanel = new JPanel();
		statusPanel.setBackground(Color.WHITE);
		statusPanel.setForeground(Color.DARK_GRAY);
		statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.Y_AXIS));



		JPanel hashPanel = new JPanel();
		hashPanel.setLayout(new BoxLayout(hashPanel, BoxLayout.X_AXIS));

		JPanel certPanel = new JPanel();
		certPanel.setLayout(new BoxLayout(certPanel, BoxLayout.X_AXIS));


		pwd = new JPasswordField();
		pwd.setPreferredSize(new Dimension(100, 20));
		pwd.addActionListener(this);
		pwd.setEnabled(false);


		JLabel pwdLabel = new JLabel();
		pwdLabel.setText("PIN:");
		pwdLabel.setBackground(Color.WHITE);
		pwdLabel.setForeground(Color.DARK_GRAY);
		pwdLabel.setHorizontalAlignment(SwingConstants.CENTER);
		pwdLabel.setHorizontalTextPosition(SwingConstants.CENTER);
		pwdLabel.setLabelFor(pwd);


		controlsPanel.add(pwdLabel);
		controlsPanel.add(pwd);

		if (!isSingleSignature()) {
			s = new JButton("Firma");
			s.addActionListener(this);
			s.setPreferredSize(new Dimension(100, 20));
			s.setVisible(false);
			controlsPanel.add(s);
		}

		certLabelArea = new JTextArea();
		certLabelArea.setPreferredSize(new Dimension(100, 100));
		certLabelArea.setEditable(false);
		certLabelArea.setAlignmentX(Component.RIGHT_ALIGNMENT);
		certLabelArea.setLineWrap(true);
		certLabelArea.setFont(new Font("Sans-serif", Font.PLAIN, 12));
		certLabelArea.setForeground(Color.DARK_GRAY);

		certValueArea = new JTextArea();
		certValueArea.setPreferredSize(new Dimension(100, 100));
		certValueArea.setEditable(false);
		certValueArea.setLineWrap(true);
		certValueArea.setFont(new Font("Sans-serif", Font.BOLD, 12));
		certValueArea.setForeground(Color.DARK_GRAY);

		JPanel datePanel = new JPanel();
		datePanel.setLayout(new BoxLayout(datePanel, BoxLayout.X_AXIS));

		signingTimeGMT = new JTextField();
		signingTimeGMT.setEditable(false);
		signingTimeGMT.setFont(new Font("Sans-serif", Font.BOLD, 12));
		signingTimeGMT.setForeground(Color.DARK_GRAY);

		datePanel.add(new JLabel("Ora della firma (sarà firmata): "));
		datePanel.add(signingTimeGMT);

		sd = new JButton("Aggiorna");
		sd.addActionListener(this);
		sd.setEnabled(false);
		datePanel.add(sd);

//		JLabel titleLabel = new JLabel();
//		titleLabel.setText("CERTIFICATO PER LA FIRMA QUALIFICATA");
//		titleLabel.setBackground(Color.WHITE);
//		titleLabel.setForeground(Color.DARK_GRAY);
//		titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
//		titleLabel.setHorizontalTextPosition(SwingConstants.CENTER);


//		certPanel.add(titleLabel);
		certPanel.add(certLabelArea);
		certPanel.add(certValueArea);



		JPanel digestPanel = new JPanel();
		digestPanel.setLayout(new BoxLayout(digestPanel, BoxLayout.Y_AXIS));



		progressBar = new JProgressBar();
		progressBar.setStringPainted(false);
		progressBar.setStringPainted(true);
		progressBar.setBackground(Color.WHITE);
		progressBar.setForeground(Color.DARK_GRAY);
		progressBar.setBorderPainted(false);
		progressBar.setBorderPainted(true);


		statusPanel.add(progressBar);

		hashField = new JTextField(this.encodedContentHash);
		hashField.setEditable(false);
		hashField.setFont(new Font("Sans-serif", Font.BOLD, 12));
		hashField.setForeground(Color.BLUE);

		hashPanel.add(new JLabel("Hash Documento: "));
		hashPanel.add(hashField);


		TitledBorder titledBorder = BorderFactory.createTitledBorder("CERTIFICATO PER LA FIRMA DIGITALE");
		titledBorder.setTitleFont(new Font("Sans-serif", Font.BOLD, 14));
		titledBorder.setTitlePosition(TitledBorder.CENTER);
		titledBorder.setBorder(BorderFactory.createLineBorder(Color.GRAY));

		southPanel.setBorder(titledBorder);

		//southPanel.add(datePanel);
		southPanel.add(certPanel);
//		southPanel.add(hashPanel);
		southPanel.add(statusPanel);
		southPanel.add(controlsPanel);

		getContentPane().add(southPanel, BorderLayout.CENTER);

		getContentPane().setBackground(Color.WHITE);
		getContentPane().setForeground(Color.DARK_GRAY);


		// retrive data to sign from html form.
		// retriveEncodedDigestFromForm();

		//viewDocument();
		findCert();

	}

	public java.lang.String getDigestPath() {
		return digestPath;
	}

	public void setDigestPath(java.lang.String digestPath) {
		this.digestPath = digestPath;
	}

	public java.lang.String getEncryptedDigestPath() {
		return encryptedDigestPath;
	}

	public void setEncryptedDigestPath(java.lang.String encryptedDigestPath) {
		this.encryptedDigestPath = encryptedDigestPath;
	}

	/**
	 * GUI event management<br/>
	 * The most important source of events is the pwd field, that triggers the
	 * creation of the signing task. The task is a {@link DigestSignTask}
	 * carried in a separate thread, avoiding to lock the gui; a
	 * <code>Timer</code> is used to refresh a progress bar every second,
	 * querying the task status.
	 * 
	 * @param e
	 *            The event to deal with.
	 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
	 */

	public void actionPerformed(java.awt.event.ActionEvent e) {
		try {
			setStatus(DigestSignTask.RESET, "");

			if (e.getSource() == sd) {
				enableControls(false);

				if (retrieveEncodedDigestFromServer(true)) {
					enableControls(true);
					setAboutToSignStatus();
					//returnEncodedDigestToForm();
				}
			}

			if (e.getSource() == pwd || e.getSource() == s) {
				initStatus(0, DigestSignTask.SIGN_MAXIMUM);

				if (detectCardAndCriptoki()) {

					// Create a new sign task.
					dsTask = new DigestSignTask(getCryptokiLib(),
							null, log);
					// Create a timer.
					timer = new Timer(ONE_SECOND,
							new java.awt.event.ActionListener() {

								public void actionPerformed(
										java.awt.event.ActionEvent evt) {

									String alertMsg = null;
									if (dsTask.getCurrent() == DigestSignTask.ERROR) {
										if (dsTask.getErrorCode() == PKCS11Constants.CKR_PIN_INCORRECT)
											alertMsg = "Tentativi ulteriori con pin errato possono bloccare il dispositivo di firma!";
									}
									setStatus(dsTask.getCurrent(),
											dsTask.getMessage(), alertMsg);

									if (dsTask.done()) {
										timer.stop();
										progressBar.setValue(progressBar
												.getMinimum());
										if (dsTask.getCurrent() == DigestSignTask.SIGN_DONE) {
											Toolkit.getDefaultToolkit().beep();
											setEncryptedDigest(dsTask
													.getEncryptedDigest());

											setStatus(
													DigestSignTask.VERIFY_DONE,
													"Invio firma ...");

											boolean hasNext = returnEncryptedDigestToServer();

											//returnEncryptedDigestToForm();
											setCertificate(dsTask
													.getCertificate());
											//returnCertificateToForm();
											
											/*if (hasNext){
													//&& (retrieveEncodedDigestFromServer(true))) {
												iteration++;

												enableControls(true);
												setAboutToSignStatus();
											} else {
												if (submitAfterSigning) {
													//submitForm();
												}else {
													appletSucccess();
												}
											}*/

											appletSucccess();

										}
									}
								}
							});

					sign();
				}
			}
			

		} catch (Exception ex) {
			log.println(ex.toString());

		} finally {
			if (isSingleSignature())
				pwd.setText("");
		}
	}

	private void appletSucccess(){
		try {
			JSObject win = sun.plugin.javascript.JSObject.getWindow(this);
			JSObject doc = (JSObject) win.getMember("document");
			doc.eval("appletSuccess();");
		} catch (netscape.javascript.JSException e) {
			setStatus(DigestSignTask.ERROR, "Errore JSO: " + e);
		}
	}

	private void appletError(String message){
		try {
			JSObject win = sun.plugin.javascript.JSObject.getWindow(this);
			JSObject doc = (JSObject) win.getMember("document");
			doc.eval("appletError('"+message+"');");
		} catch (netscape.javascript.JSException e) {
			System.out.println(e.getMessage());
		}
	}

	void setAboutToSignStatus() {

		System.out.println("Iteration: " + iteration);

		if (isSingleSignature())
			setStatus(DigestSignTask.RESET,
					"Inserire il pin e battere INVIO per firmare.");
		else {
			if (iteration == 1)
				setStatus(DigestSignTask.RESET, "Documento " + iteration
						+ ": Inserire il pin e battere INVIO per firmare.");
			else
				setStatus(DigestSignTask.RESET, "Documento " + iteration
						+ ": Premere FIRMA per firmare usando lo stesso pin.");
		}
	}

	/**
	 * <code>Base64</code> String to String decoding function. Relies on
	 * {@link #decodeToBytes(String)} method.
	 * 
	 * @param s
	 *            The <code>Base64</code> string to decode. 
	 * @return The decoded string, in UTF-8 charset.
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
	 * <code>Base64</code> String to byte[] decoding function. Warning: this
	 * method relies on <code>sun.misc.BASE64Decoder</code>
	 * 
	 * @param s
	 *            The <code>Base64</code> string to decode.
	 * @return the decoded string as a <code>byte[]</code>
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
	 * Cleans up whatever resources are being held. If the applet is active it
	 * is stopped.
	 * 
	 * @see #init
	 * @see #start
	 * @see #stop
	 */
	public void destroy() {

		super.destroy();
		System.out.println("Destroying applet and garbage collecting...");
		dsTask = null;
		System.gc();
		System.out.println("Garbage collection done.");
		// insert code to release resources here
	}

	/**
	 * Enables GUI controls (depending on debug mode).
	 * 
	 * @param enable
	 *            if <code>true</code>, controls will be enabled.
	 */
	private void enableControls(boolean enable) {

		if (this.iteration > 1) {
			pwd.setEnabled(false);
			s.setVisible(true);
			s.setEnabled(enable);
		} else {
			pwd.setEnabled(enable);
		}

		sd.setEnabled(enable);

	}

	/**
	 * <code>Base64</code> String to String encoding function. Relies on
	 *  method.
	 * 
	 * @param s
	 *            The string to encode; UTF-8 charset is assumed.
	 * @return The <code>Base64</code> encoded string.
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
	 * <code>Base64</code> <code>byte[]</code> to <code>String</code> encoding
	 * function. Warning: this method relies on
	 * <code>sun.misc.BASE64Encoder</code>
	 * 
	 * @return The <code>Base64</code> encoded string.
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
		return "PKCS11SignApplet\n" + "\n"
				+ "This applet is based on http://j4sign.sf.net project.\n";
	}

	/**
	 * Gets the <code>x509 </code>certificate as a <code>byte[]</code>.
	 * 
	 * @return the <code>x509 </code>certificate as a <code>byte[]</code>.
	 */
	public byte[] getCertificate() {
		return certificate;
	}

	/**
	 * Gets name of the cryptoki library in use
	 * 
	 * @return a <code>String</code> specifiyng the cryptoki library name.
	 */
	private java.lang.String getCryptokiLib() {
		return cryptokiLib;
	}

	/**
	 * Gets the digest <code>Base64</code> encoded.
	 * 
	 * @return <code>Base64</code> encoding of the digest.
	 */
	public String getEncodedDigest() {

		return this.encodedDigest;
	}

	/**
	 * Gets the raw encryptedDigest-
	 * 
	 * @return the encrypted digest as <code>byte[]</code>.
	 */
	public byte[] getEncryptedDigest() {
		return encryptedDigest;
	}

	/**
	 * Is the form inside the embedding page to be submitted after signing?
	 * 
	 * @return <code>true</code> if the applet has to submit the form.
	 */
	private boolean isSingleSignature() {
		return singleSignature;
	}

	public void setSingleSignature(boolean single) {
		this.singleSignature = single;
	}

	/**
	 * Initializes minimum and maximum status values for progress bar
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
	 * Interfaces via javascript with the embedding page for setting the
	 * certificate field on the form.
	 */
//	public void returnCertificateToForm() {
//		try {
//
//			// BASE64 encode certificate bytes
//
//			String encodedCert = encodeFromBytes(getCertificate());
//			BufferedReader br = new BufferedReader(
//					new StringReader(encodedCert));
//
//			JSObject win = sun.plugin.javascript.JSObject.getWindow(this);
//			JSObject doc = (JSObject) win.getMember("document");
//
//			String aBlock = null;
//			StringBuffer allText = new StringBuffer();
//			while ((aBlock = br.readLine()) != null)
//				allText.append(aBlock);
//
//			doc.eval("setCertificato('" + allText + "')");
//
//			// win.eval("eseguiSubmit();");
//
//		} catch (netscape.javascript.JSException e) {
//			log.println("Errore JSO: " + e);
//			setStatus(DigestSignTask.ERROR, "Errore JavaScript");
//		} catch (IOException ioe) {
//			log.println("Errore restituendo il certificato alla form");
//			log.println(ioe);
//			setStatus(DigestSignTask.ERROR,
//					"Errore restituendo il certificato alla form");
//		}
//	}

	/**
	 * Interfaces via javascript with the embedding page for setting the
	 * encrypted digest field on the form.
	 */
	/*public void returnEncryptedDigestToForm() {
		try {

			// BASE64 encode signedDigest

			String encodedEncryptedDigest = encodeFromBytes(getEncryptedDigest());
			BufferedReader br = new BufferedReader(new StringReader(
					encodedEncryptedDigest));

			JSObject win = sun.plugin.javascript.JSObject.getWindow(this);
			JSObject doc = (JSObject) win.getMember("document");

			String aBlock = null;
			StringBuffer allText = new StringBuffer();
			while ((aBlock = br.readLine()) != null)
				allText.append(aBlock);

			// win.eval("eseguiSubmit();");

		} catch (netscape.javascript.JSException e) {
			log.println("Errore JSO: " + e);
			setStatus(DigestSignTask.ERROR, "Errore JavaScript");
		} catch (IOException ioe) {
			log.println("Errore restituendo encryptedDigest alla form");
			log.println(ioe);
			setStatus(DigestSignTask.ERROR,
					"Errore restituendo encryptedDigest alla form");
		}
	}*/

	/**
	 * Interfaces via javascript with the embedding page for setting the digest
	 * field on the form (useful only for testing purpose in debug mode).
	 */
//	public void returnEncodedDigestToForm() {
//		try {
//
//			// BASE64 encode signedDigest
//
//			BufferedReader br = new BufferedReader(new StringReader(
//					getEncodedDigest()));
//
//			JSObject win = sun.plugin.javascript.JSObject.getWindow(this);
//			JSObject doc = (JSObject) win.getMember("document");
//
//			String aBlock = null;
//			StringBuffer allText = new StringBuffer();
//			while ((aBlock = br.readLine()) != null)
//				allText.append(aBlock);
//
//			doc.eval("setDigest('" + allText + "')");
//
//			// win.eval("eseguiSubmit();");
//
//		} catch (netscape.javascript.JSException e) {
//			log.println("Errore JSO: " + e);
//			setStatus(DigestSignTask.ERROR, "Errore JavaScript");
//		} catch (IOException ioe) {
//			log.println("Errore restituendo digest alla form");
//			log.println(ioe);
//			setStatus(DigestSignTask.ERROR,
//					"Errore restituendo digest alla form");
//		}
//	}

	/**
	 * Setter method
	 * 
	 * @param newCertificate
	 */
	private void setCertificate(byte[] newCertificate) {
		certificate = newCertificate;
	}

	/**
	 * Setter method
	 * 
	 * @param newCryptokiLib
	 */
	private void setCryptokiLib(java.lang.String newCryptokiLib) {
		cryptokiLib = newCryptokiLib;
	}

	/**
	 * Setter method
	 * 
	 * @param data
	 */
	public void setEncodedDigest(String data) {
		this.encodedDigest = data;
	}

	/**
	 * Setter method
	 * 
	 * @param newEncryptedDigest
	 */
	public void setEncryptedDigest(byte[] newEncryptedDigest) {
		encryptedDigest = newEncryptedDigest;
	}

	/**
	 * Updates progress bar value and displays error alerts
	 * 
	 * @param code
	 *            The status value
	 * @param statusString
	 *            The status description
	 */
	void setStatus(int code, String statusString, String alertMessage) {
		if (code == DigestSignTask.ERROR) {
			pwd.setText("");
			if((statusString==null || "".equals(statusString.trim())) ){
				statusString="Errore nella firma digitale";
			}

			if(alertMessage==null){
				alertMessage = "";
			}

			appletError(statusString + " " + alertMessage);
			code = 0;
		}
		progressBar.setValue(code);
		progressBar.setString(statusString);
	}

	void setStatus(int code, String statusString) {
		setStatus(code, statusString, null);
	}

	/**
	 * Initializes and starts the sign task.
	 */
	public void sign() {

		if (getEncodedDigest() == null)
			setStatus(ERROR, "Digest non impostato");
		else {
			long mechanism = -1L;
			if (ENCRYPTION_RSA.equals(this.encAlg))
				if (this.makeDigestOnToken) {
					if (DIGEST_MD5.equals(this.digestAlg))
						mechanism = PKCS11Constants.CKM_MD5_RSA_PKCS;
					else if (DIGEST_SHA1.equals(this.digestAlg))
						mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
					else if (DIGEST_SHA256.equals(this.digestAlg))
						mechanism = PKCS11Constants.CKM_SHA256_RSA_PKCS;
				} else
					mechanism = PKCS11Constants.CKM_RSA_PKCS;

			if (mechanism == -1L) {
				setStatus(DigestSignTask.ERROR,
						"Impossibile determinare il meccanismo!");

			}else {
				dsTask.setMechanism(mechanism);
				enableControls(false);
				dsTask.setCertificate(getCertificate());
				dsTask.setDigest(decodeToBytes(getEncodedDigest()));
				dsTask.setPassword(pwd.getPassword());
				dsTask.go();
				timer.start();
			}
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
		System.out.println("Starting applet ...");
		try {
			JSObject win = sun.plugin.javascript.JSObject.getWindow(this);
			JSObject doc = (JSObject) win.getMember("document");
			doc.eval("appletStart();");
		} catch (netscape.javascript.JSException e) {
			setStatus(DigestSignTask.ERROR, "Errore JSO: " + e);
		}
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
		System.out.println("stopping...");

	}

	/**
	 * Calls the javascript submit function on the embedding page.
	 * 
	 */
//	private void submitForm() {
//		try {
//			JSObject win = sun.plugin.javascript.JSObject.getWindow(this);
//			JSObject doc = (JSObject) win.getMember("document");
//			doc.eval("eseguiSubmit();");
//		} catch (netscape.javascript.JSException e) {
//			setStatus(DigestSignTask.ERROR, "Errore JSO: " + e);
//		}
//
//	}

	/**
	 * Calls the javascript "viewDocument" function on the embedding page.
	 * 
	 */
	/*private void viewDocument() {
		try {
			JSObject win = sun.plugin.javascript.JSObject.getWindow(this);
			JSObject doc = (JSObject) win.getMember("document");

			String jscall = "viewDocument('"
					+ URLEncoder.encode(this.encodedContentHash, "UTF-8")
					+ "')";

			System.out.println("Invoking jscript: '" + jscall + "'");

			// setStatus(DigestSignTask.VERIFY_DONE,
			// "Caricamento Documento ...");
		} catch (netscape.javascript.JSException jse) {
			setStatus(DigestSignTask.ERROR, "Errore JSO: " + jse);
		} catch (UnsupportedEncodingException e) {
			setStatus(DigestSignTask.ERROR, "Errore Encoding: " + e);
		}

	}*/

	/**
	 * returns an hex dump of the supplied <code>byte[]</code>
	 * 
	 * @param bytes
	 *            the data to show
	 * @return a String containing the dump
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
			log.println("Getting cryptoki name from Applet parameter 'cryptokilib': "
					+ getParameter("cryptokilib"));
			setCryptokiLib(getParameter("cryptokilib"));
		} else {
			log.println("Trying to detect card via PCSC ...");

			PCSCHelper pcsc = new PCSCHelper(true);
			
			List<?> cards = pcsc.findCards();
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

	private long algToMechanism(boolean digestOnToken, String digestAlg,
			String encryptionAlg) {

		long mechanism = -1L;

		if (ENCRYPTION_RSA.equals(encryptionAlg))
			if (digestOnToken) {
				if (DIGEST_MD5.equals(digestAlg))
					mechanism = PKCS11Constants.CKM_MD5_RSA_PKCS;
				else if (DIGEST_SHA1.equals(digestAlg))
					mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
				else if (DIGEST_SHA256.equals(digestAlg))
					mechanism = PKCS11Constants.CKM_SHA256_RSA_PKCS;
			} else
				mechanism = PKCS11Constants.CKM_RSA_PKCS;

		return mechanism;
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
	 * Starts the background task that scans the token looking for a suitable
	 * certificate. A Timer is set for updating the progress bar.
	 * 
	 */
	private void findCert() {

		long mechanism = algToMechanism(this.makeDigestOnToken, this.digestAlg,
				this.encAlg);

		if (mechanism == -1L) {
			setStatus(DigestSignTask.ERROR,
					"Impossibile determinare il meccanismo!");
		}else {

			// find certificate action
			initStatus(0, FindCertTask.FIND_MAXIMUM);

			// Create a new sign task.
			certTask = new FindCertTask(getCryptokiLib(), null, log);
			// Create a timer.
			// NOTE: we define an action listener on the fly while
			// passing an instance of it to the Timer constructor.
			findTimer = new Timer(ONE_SECOND,
					new java.awt.event.ActionListener() {

						public void actionPerformed(
								java.awt.event.ActionEvent evt) {

							setStatus(certTask.getCurrent(),
									certTask.getMessage());

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
										X509Certificate x509cert =getJavaCertificate();

										// Get subject
										Principal principal = x509cert.getSubjectDN();
										String subjectDn = principal.getName();

										String[] splittedPrincipal = subjectDn.split(",");

										String nome="";
										String cognome="";
										String ragioneSociale="";
										String codFiscPartIva="";
										String identificativo="";
										String validoFinoAl="";
										String rilasciatoDa="";

										for(String property : splittedPrincipal){

											String[] splittedProperty = property.split("=");
											String label = splittedProperty[0];
											String value = splittedProperty[1];

											if("GIVENNAME".equals(label.trim())){

												nome = value;

											}else if("SURNAME".equals(label.trim())){

												cognome = value;

											}else if("O".equals(label.trim())){

												ragioneSociale = value;

											}else if("SERIALNUMBER".equals(label.trim())){

												codFiscPartIva = value;

											}else if("DNQ".equals(label.trim())){

												identificativo = value;

											}


										}

										// Get issuer
										principal = x509cert.getIssuerDN();
										String issuerDn = principal.getName();

										splittedPrincipal = issuerDn.split(",");

										String OValue="";
										String OUValue="";
										String CNValue="";



										for(String property : splittedPrincipal){

											String[] splittedProperty = property.split("=");
											String label = splittedProperty[0];
											String value = splittedProperty[1];

											if("O".equals(label.trim())){

												OUValue = value;

											}else if("OU".equals(label.trim())){

												OUValue = value;


											}else if("CN".equals(label.trim())){

												CNValue = value;

											}


										}

										rilasciatoDa = OUValue+" "+OUValue+" "+CNValue;

										SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");


										String validoAl = dateFormat.format(x509cert.getNotAfter());


										certLabelArea.append("\n Nome: ");
										certLabelArea.append("\n Cognome: ");
										certLabelArea.append("\n Ragione sociale: ");
										certLabelArea.append("\n Codice fiscale/Partita IVA: ");
										certLabelArea.append("\n ID unico presso il certificatore: ");
										certLabelArea.append("\n Valido fino al: ");
										certLabelArea.append("\n Rilasciato da: ");

										certValueArea.append("\n"+nome);
										certValueArea.append("\n"+cognome);
										certValueArea.append("\n"+ragioneSociale );
										certValueArea.append("\n"+codFiscPartIva);
										certValueArea.append("\n"+identificativo);
										certValueArea.append("\n"+validoAl);
										certValueArea.append("\n"+rilasciatoDa);







									} catch (CertificateException e) {
										log.println("Error getting certificate Subject DN");
									}
								}

								if (retrieveEncodedDigestFromServer(false)) {
									enableControls(true);
									setAboutToSignStatus();
									//returnEncodedDigestToForm();
								}
							}
						}// end of actionPerformed definition
					});// end of ActionListener definition and Timer
			// constructor call.
		}

		certTask.setMechanism(mechanism);
		certTask.go();
		findTimer.start();
	}

	private boolean retrieveEncodedDigestFromServer(boolean reloadDocument) {

		boolean retrieved = false;


		URL url = null;

		try {
			if (reloadDocument) {
				// load document
				log.println("Loading document for viewing ...");
				//viewDocument();
			}

			log.println("POSTing contenthash, certificate and getting Digest...");
			String base64Certificate = encodeFromBytes(getCertificate());

			// Construct data
			String data = URLEncoder.encode("datahash", "UTF-8") + "="
					+ URLEncoder.encode(encodedContentHash, "UTF-8") + "&"
					+ URLEncoder.encode("certificate", "UTF-8") + "="
					+ URLEncoder.encode(base64Certificate, "UTF-8");

			// Send data
			url = new URL(getDigestPath());

			log.println("POSTing to: " + url);
			String result = httpPOST(url, data);

			if (result == null) {
				log.println("No data received from server");
				setStatus(DigestSignTask.ERROR,
						"Errore nell'invio dei dati al server!" + url);
			} else {
				// Process line...
				log.println("POST result: " + result);

				StringTokenizer st = new StringTokenizer(result, ",");
				if (st.hasMoreTokens()) {
					String receivedEncoding = st.nextToken();

					if ("ERROR".equals(receivedEncoding) || "null".equals(receivedEncoding)) {
						
						String errorMsg = st.nextToken();
						log.println(errorMsg);
						setStatus(DigestSignTask.ERROR, errorMsg);
						
					} else {
						if (decode(receivedEncoding) == null) {
							log.println("Errore nella decodifica del digest ricevuto dal server!");
							setStatus(DigestSignTask.ERROR,
									"Errore nella decodifica del digest ricevuto dal server!");

						} else {
							setEncodedDigest(receivedEncoding);

							if (st.hasMoreTokens()) {
								String receivedTime = decode(st.nextToken());

								if (receivedTime == null)
									setStatus(ERROR,
											"Errore nella decodifica dell'ora ricevuta dal server!");
								else {
									this.signingTimeGMT.setText(receivedTime);
									retrieved = true;
								}
							}
						}
					}

				}
			}

		} catch (Exception e) {
			log.println("Error POSTing data: " + e);
			setStatus(DigestSignTask.ERROR,
					"Errore nell'invio dei dati al server!" + url);

		}

		return retrieved;

	}

	private boolean returnEncryptedDigestToServer() {

		boolean hasNext = false;

		URL url = null;

		try {

			log.println("POSTing encryptedDigest and getting new hash...");
			String base64encDigest = encodeFromBytes(getEncryptedDigest());

			// Construct data
			String data = URLEncoder.encode("datahash", "UTF-8") + "="
					+ URLEncoder.encode(encodedContentHash, "UTF-8") + "&"
					+ URLEncoder.encode("encrypteddigest", "UTF-8") + "="
					+ URLEncoder.encode(base64encDigest, "UTF-8");

			// Send data
			url = new URL(getEncryptedDigestPath());
			log.println("POSTing to: " + url);
			String receivedContentHash = httpPOST(url, data);

			if (receivedContentHash == null) {
				log.println("No data received from server");
				// setStatus(DigestSignTask.ERROR,
				// "Nessun dato ricevuto dal server");
			} else {
				// Process line...
				log.println("POST result: " + receivedContentHash);

				if (decode(receivedContentHash) == null)
					setStatus(ERROR,
							"Errore nella decodifica del content hash ricevuto dal server!");
				else {
					setEncodedContentHash(receivedContentHash);
					hasNext = true;
				}

			}

		} catch (Exception e) {
			log.println("Error POSTing data: " + e);
			setStatus(DigestSignTask.ERROR,
					"Errore nell'invio dei dati al server!" + url);

		}

		return hasNext;
	}

	private String httpPOST(URL url, String data) throws IOException {

		String result = null;

		URLConnection conn = null;

		if ("http".equals(url.getProtocol()))
			conn = (HttpURLConnection) url.openConnection();

		if ("https".equals(url.getProtocol()))
			conn = (HttpsURLConnection) url.openConnection();

		if (conn != null) {
			log.println("Connection opened.");
			conn.setDoOutput(true);
			OutputStreamWriter wr = new OutputStreamWriter(
					conn.getOutputStream());
			wr.write(data);
			wr.flush();
			log.println("Data sent.");

			// Get the response
			BufferedReader rd = new BufferedReader(new InputStreamReader(
					conn.getInputStream()));
			String line;
			if ((line = rd.readLine()) != null)
				result = line;

			wr.close();
			rd.close();
		}

		return result;
	}

}
