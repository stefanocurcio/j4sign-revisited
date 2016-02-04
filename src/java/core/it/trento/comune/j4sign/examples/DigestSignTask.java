package it.trento.comune.j4sign.examples;


import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.Arrays;


import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import it.trento.comune.j4sign.pkcs11.PKCS11Signer;

/** Uses a SwingWorker to perform signing task. */

public class DigestSignTask {
	private int lengthOfTask;

	private int current = 0;

	private String statMessage;

	private long errorCode;

	private java.io.PrintStream log = null;

	private char[] password = null;

	private byte[] digest = null;

	private InputStream dataStream = null;

	private byte[] encryptedDigest;

	private byte[] certificate = null;

	private String cryptoki = null;

	private String signerLabel = null;

	long mechanism = -1;

	public static final int SIGN_MAXIMUM = 4;

	public static final int SIGN_INIT_SESSION = 1;

	public static final int SIGN_CERTIFICATE_INITDATA = 3;

	public static final int SIGN_ENCRYPT_DIGEST = 2;

	public static final int SIGN_DONE = 4;

	public static final int VERIFY_MAXIMUM = 2;

	public static final int VERIFY_INIT = 1;

	public static final int VERIFY_DONE = 2;

	public static final int RESET = 0;

	public static final int ERROR = -1;

	/**
	 * The actual long running task. This runs in a SwingWorker thread.
	 */
	class DigestSigner {
		DigestSigner() {
			PKCS11Signer helper = null;
			log.println("Helper Class Loader: "
					+ PKCS11Signer.class.getClassLoader());
			try {
				SecurityManager sm = System.getSecurityManager();
				if (sm != null)
					log.println("SecurityManager: " + sm);
				else
					log.println("no SecurityManager.");

				setStatus(SIGN_INIT_SESSION, "Accesso alla carta...", 0);

				helper = new PKCS11Signer(cryptoki, log);

				log
						.println("Finding a token supporting required mechanism and "
								+ "containing a suitable" + "certificate...");

				long t = helper.findSuitableToken(getMechanism());
				if (t != -1L) {
					helper.setMechanism(getMechanism());
					helper.setTokenHandle(t);

					encryptDigestAndGetCertificate(signerLabel, helper);

					setPassword(null);
				}

			} catch (TokenException te) {
				// setStatus(ERROR, PKCS11Helper.decodeError(te.getCode()));
				// log.println(PKCS11Helper.decodeError(te.getCode()));
				// setStatus(ERROR, PKCS11Helper.decodeError(-1));

				log.println(te);
				setStatus(ERROR, "Errore" + te, 0);

				/*
				 * catch (UnsatisfiedLinkError ule) { setStatus(ERROR, "Occorre
				 * chiudere il browser\nprima di firmare nuovamente");
				 * log.println(ule);
				 */
			} catch (Exception e) {
				log.println(e);
				setStatus(ERROR, "Eccezione: " + e, 0);
			}

		}

		protected void encryptDigestAndGetCertificate(String signerLabel,
				PKCS11Signer helper) throws CertificateException {

			byte[] encrypted_digest = null;

			setStatus(SIGN_ENCRYPT_DIGEST, "Generazione della firma ...", 0);
			try {

				helper.openSession(password);
				log.println("User logged in.");

				long privateKeyHandle = -1L;
				long certHandle = -1;

				byte[] encDigestBytes = null;
				byte[] certBytes = null;

				log.println("Searching objects from certificate key usage ...");

				certHandle = helper.findCertificateWithNonRepudiationCritical();

				if (certHandle > 0) {

					certBytes = helper.getDEREncodedCertificate(certHandle);

					// When doing CAdES signature, certificate is already set;
					// checking consistency...
					if ((getCertificate() == null)
							|| Arrays.equals(getCertificate(), certBytes)) {

						privateKeyHandle = helper
								.findSignatureKeyFromCertificateHandle(certHandle);

						if (privateKeyHandle > 0) {
							if (getDigest() != null)
								encDigestBytes = helper.signDataSinglePart(
										privateKeyHandle, getDigest());
							else
								encDigestBytes = helper.signDataMultiplePart(
										privateKeyHandle, getDataStream());

							// log.println("\nEncrypted digest:\n" +
							// formatAsHexString(encDigestBytes));

							// log.println("\nDER encoded Certificate:\n" +
							// formatAsHexString(certBytes));

							if ((encDigestBytes != null) && (certBytes != null)) {
								setEncryptedDigest(encDigestBytes);
								setCertificate(certBytes);
								setStatus(SIGN_DONE, "Firma completata.", 0);
							}

						} else
							// privateKeyHandle <= 0
							log
									.println("\nNo private key corrisponding to certificate found on token!");
					} else
						// cert previously set is different from current one.
						log
								.println("Found cert is different form that Digest is based on (CAdES)!");
				} else
					// certHandle <= 0
					log.println("\nFound cert has handle <= 0 !");

			} catch (PKCS11Exception pkcs11_e) {
				
				log.println("sign() PKCS11 Error: " + pkcs11_e);
				
				long p11Error = pkcs11_e.getErrorCode();
				
				if ( p11Error == PKCS11Constants.CKR_PIN_INCORRECT) {
					setStatus(ERROR, "PIN ERRATO",p11Error);
				} else if (p11Error == PKCS11Constants.CKR_PIN_INVALID) {
					setStatus(ERROR, "PIN NON VALIDO",p11Error);
				} else if (p11Error == PKCS11Constants.CKR_PIN_LEN_RANGE) {
					setStatus(ERROR, "PIN DI LUNGHEZZA NON CORRETTA",p11Error);
				} else if (p11Error == PKCS11Constants.CKR_PIN_LOCKED) {
					setStatus(ERROR, "PIN BLOCCATO",p11Error);
				} else if (p11Error == PKCS11Constants.CKR_PIN_EXPIRED) {
					setStatus(ERROR, "PIN SCADUTO",p11Error);
				} else {
					setStatus(ERROR, "ERRORE PKCS11: " + pkcs11_e, p11Error);
				}
				
			} catch (TokenException e) {
				log.println("sign() Error: " + e);
				setStatus(ERROR, "Errore: " + e, 0);
			} catch (IOException ioe) {
				log.println(ioe);
				setStatus(ERROR, "Errore: " + ioe, 0);
			} catch (UnsatisfiedLinkError ule) {
				log.println(ule);
				setStatus(ERROR, "Errore: " + ule, 0);
			} finally {
				if (helper != null) {
					try {
						helper.closeSession();
						log.println("Sign session Closed.");
					} catch (PKCS11Exception e2) {
						log.println("Error closing session: " + e2);
						setStatus(ERROR, "Errore: " + e2, 0);
					}

					try {
						helper.libFinalize();
						log.println("Lib finalized.");
					} catch (Throwable e1) {
						// TODO Auto-generated catch block
						log.println("Error finalizing criptoki: " + e1);
						setStatus(ERROR, "Errore: " + e1, 0);
					}

				}
				helper = null;
				System.gc();
			}
		}
		/*
		 * protected void getCertificateFromSmartCard(String signerLabel,
		 * PKCS11Helper helper) throws TokenException {
		 * 
		 * byte[] signerCert = null;
		 * 
		 * log.println("Finding certificate...");
		 * 
		 * helper.login(String.valueOf(password)); log.println("User logged
		 * in.");
		 * 
		 * setStatus(SIGN_CERTIFICATE_INITDATA, "Recupero certificato ...");
		 * 
		 * signerCert = helper.getCertificateBytes(signerLabel);
		 * 
		 * helper.logout(); log.println("User logged out.");
		 * 
		 * if (signerCert == null) { setStatus(ERROR, "Certificato non
		 * trovato!"); log.println("Certificate not found!"); }
		 * 
		 * setCertificate(signerCert); }
		 */

	}// end of nested class

	DigestSignTask(String aCriptoki, String aSignerLabel,
			java.io.PrintStream aLog) {
		lengthOfTask = SIGN_MAXIMUM;
		this.log = aLog;
		this.cryptoki = aCriptoki;
		this.signerLabel = aSignerLabel;
	}

	/**
	 * Called from ProgressBarDemo to find out if the task has completed.
	 */
	boolean done() {
		if ((current >= lengthOfTask) || (current == ERROR))
			return true;
		else
			return false;
	}

	/**
	 * Inserire qui la descrizione del metodo. Data di creazione: (10.05.01
	 * 14.16.36)
	 * 
	 * @return int
	 */
	public byte[] getCertificate() {
		return this.certificate;
	}

	/**
	 * Called from ProgressBarDemo to find out how much has been done.
	 */
	int getCurrent() {
		return current;
	}

	/**
	 * This method was created in VisualAge.
	 * 
	 * @param e
	 *            java.awt.event.ActionEvent
	 */
	public byte[] getDigest() {

		return this.digest;
	}

	/**
	 * Inserire qui la descrizione del metodo. Data di creazione: (03/10/00
	 * 18.44.20)
	 * 
	 * @param newSignedData
	 *            iaik.pkcs.pkcs7.SignedData
	 */
	public byte[] getEncryptedDigest() {
		return this.encryptedDigest;
	}

	/**
	 * Called from ProgressBarDemo to find out how much work needs to be done.
	 */
	int getLengthOfTask() {
		return lengthOfTask;
	}

	String getMessage() {
		return statMessage;
	}
	
	public long getErrorCode() {
		return errorCode;
	}

	/**
	 * Called from Signer Application to start the task.
	 */
	void go() {
		current = 0;

		final SwingWorker worker = new SwingWorker() {
			public Object construct() {
				return new DigestSigner();
			}
		};
		worker.start();

	}

	/**
	 * Inserire qui la descrizione del metodo. Data di creazione: (10.05.01
	 * 14.16.36)
	 * 
	 * @param newCertificate
	 *            int
	 */
	public void setCertificate(byte[] newCertificate) {
		certificate = newCertificate;
	}

	/**
	 * Inserire qui la descrizione del metodo. Data di creazione: (13/02/01
	 * 11.02.28)
	 * 
	 * @param newData
	 *            byte[]
	 */
	public void setDigest(byte[] newDigest) {
		this.digest = newDigest;
	}

	/**
	 * Inserire qui la descrizione del metodo. Data di creazione: (03/10/00
	 * 18.44.20)
	 * 
	 * @param newSignedData
	 *            iaik.pkcs.pkcs7.SignedData
	 */
	private void setEncryptedDigest(byte[] newEncryptedDigest) {
		encryptedDigest = newEncryptedDigest;
	}

	/**
	 * Inserire qui la descrizione del metodo. Data di creazione: (13/02/01
	 * 17.14.37)
	 * 
	 * @param pwd
	 *            char[]
	 */
	public void setPassword(char[] pwd) {
		this.password = pwd;
	}

	/**
	 * Inserire qui la descrizione del metodo. Data di creazione: (13/02/01
	 * 10.32.33)
	 * 
	 * @param message
	 *            java.lang.String
	 */
	private void setStatus(int status, String message, long ec) {
		this.current = status;
		this.statMessage = message;
		this.errorCode = ec;
	}

	void stop() {
		current = lengthOfTask;
	}

	public InputStream getDataStream() {
		return dataStream;
	}

	public void setDataStream(InputStream dataStream) {
		this.dataStream = dataStream;
	}

	/**
	 * @return Returns the mechanism.
	 */
	public long getMechanism() {
		return mechanism;
	}

	/**
	 * @param mechanism
	 *            The mechanism to set.
	 */
	public void setMechanism(long mechanism) {
		this.mechanism = mechanism;
	}

}