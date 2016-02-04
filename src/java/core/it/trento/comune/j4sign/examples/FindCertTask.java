package it.trento.comune.j4sign.examples;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import it.trento.comune.j4sign.pcsc.CardInfo;
import it.trento.comune.j4sign.pcsc.PCSCHelper;
import it.trento.comune.j4sign.pkcs11.PKCS11Signer;

/** Uses a SwingWorker to perform signing task. */

public class FindCertTask {
	private int lengthOfTask;

	private int current = 0;

	private String statMessage;

	private java.io.PrintStream log = null;

	private byte[] digest = null;

	private InputStream dataStream = null;

	private byte[] encryptedDigest;

	private String cryptoki = null;

	private String signerLabel = null;

	long mechanism = -1;

	public static final int FIND_MAXIMUM = 4;

	public static final int FIND_INIT_SESSION = 1;

	public static final int FIND_CERTIFICATE_INITDATA = 3;

	public static final int FIND_START = 2;

	public static final int FIND_DONE = 4;

	public static final int RESET = 0;

	public static final int ERROR = -1;

	private boolean tokenPresent = false;

	private PCSCHelper pcscHelper = null;

	public boolean isTokenPresent() {
		return tokenPresent;
	}

	/**
	 * The actual long running task. This runs in a SwingWorker thread.
	 */
	class CertFinder {
		CertFinder() {

			try {

				waitForTokenPresent();

			} catch (IOException e1) {
				log.println(e1);
				setStatus(ERROR, "Errore durante la rilevazione del token.");
			} catch (InterruptedException e1) {
				log.println(e1);
				setStatus(ERROR, "Errore durante la rilevazione del token.");
			}

			if (!tokenPresent)
				setStatus(ERROR, "Impossibile rilevare il token.");
			else {
				PKCS11Signer helper = null;
				log.println("Helper Class Loader: "	+ PKCS11Signer.class.getClassLoader());
				try {
					SecurityManager sm = System.getSecurityManager();
					if (sm != null)
						log.println("SecurityManager: " + sm);
					else
						log.println("no SecurityManager.");

					setStatus(FIND_INIT_SESSION, "Accesso alla carta...");

					helper = new PKCS11Signer(cryptoki, log);

					log
							.println("Finding a token supporting required mechanism and "
									+ "containing a suitable"
									+ "certificate...");

					long t = helper.findSuitableToken(getMechanism());
					if (t != -1L) {
						helper.setMechanism(getMechanism());
						helper.setTokenHandle(t);

						findCertificate(signerLabel, helper);

						setStatus(FIND_DONE, "Certificato trovato.");

					}

				} catch (TokenException te) {
					// setStatus(ERROR, PKCS11Helper.decodeError(te.getCode()));
					// log.println(PKCS11Helper.decodeError(te.getCode()));
					// setStatus(ERROR, PKCS11Helper.decodeError(-1));
					setStatus(ERROR, "Errore");
					log.println(te);

					/*
					 * catch (UnsatisfiedLinkError ule) { setStatus(ERROR,
					 * "Occorre chiudere il browser\nprima di firmare
					 * nuovamente"); log.println(ule);
					 */
				} catch (Exception e) {
					setStatus(ERROR, "Eccezione: " + e);
					log.println(e);
				}
			}

		}

		protected void findCertificate(String signerLabel, PKCS11Signer helper)
				throws CertificateException {

			byte[] encrypted_digest = null;

			setStatus(FIND_START, "Inizio ricerca ...");
			try {

				helper.openSession();

				log.println("Anonymous session opened.");

				long certHandle = -1;

				byte[] certBytes = null;

				log.println("Searching objects from certificate key usage ...");

				certHandle = helper.findCertificateWithNonRepudiationCritical();

				if (certHandle > 0) {

					certBytes = helper.getDEREncodedCertificate(certHandle);

					setCertificate(certBytes);

				} else
					log
							.println("\nNo private key corrisponding to certificate found on token!");

			} catch (TokenException e) {
				log.println("findCertificate() Error: " + e);
				// log.println(PKCS11Helper.decodeError(e.getCode()));
				// log.println(PKCS11Helper.decodeError(e.getCode()));

			} catch (UnsatisfiedLinkError ule) {
				log.println(ule);
			} finally {
				if (helper != null) {
					try {
						helper.closeSession();
						log.println("Find session Closed.");
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

	}// end of nested class

	private byte[] certificate = null;

	FindCertTask(String aCriptoki, String aSignerLabel, java.io.PrintStream aLog) {
		lengthOfTask = FIND_MAXIMUM;
		this.log = aLog;
		this.cryptoki = aCriptoki;
		this.signerLabel = aSignerLabel;

		this.pcscHelper = new PCSCHelper(true);
	}

	public void waitForTokenPresent() throws IOException, InterruptedException {

		while (true) {
			if (true == detectCardAndCriptoki()) {
				tokenPresent = true;
				setStatus(RESET, "Token rilevato!");
				return;
			} else {
				tokenPresent = false;
				setStatus(RESET, "Inserire un token di firma");
			}

			Thread.sleep(1000);
		}
	}

	private boolean detectCardAndCriptoki() throws IOException {
		CardInfo ci = null;
		boolean cardPresent = false;

		java.util.List cards = pcscHelper.findCards();
		cardPresent = !cards.isEmpty();
		if (this.cryptoki == null) {
			if (cardPresent) {
				ci = (CardInfo) cards.get(0);
				this.cryptoki = ci.getProperty("lib");
			} else {
				setStatus(RESET, "Inserire un token di firma.");
			}
		} else
			System.out.println("\n\nFor signing we will use cryptoki: '"
					+ this.cryptoki + "'");

		return (this.cryptoki != null);
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
		return certificate;
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

	/**
	 * Called from Signer Application to start the task.
	 */
	void go() {
		current = 0;

		final SwingWorker worker = new SwingWorker() {
			public Object construct() {
				return new CertFinder();
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
	private void setCertificate(byte[] newCertificate) {
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
	 * 10.32.33)
	 * 
	 * @param message
	 *            java.lang.String
	 */
	private void setStatus(int status, String message) {
		this.current = status;
		this.statMessage = message;
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