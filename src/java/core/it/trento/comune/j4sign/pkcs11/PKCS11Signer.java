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
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/pkcs11/PKCS11Signer.java,v 1.8 2013/03/21 13:58:33 resoli Exp $
 * $Revision: 1.8 $
 * $Date: 2013/03/21 13:58:33 $
 */
package it.trento.comune.j4sign.pkcs11;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;

import iaik.pkcs.pkcs11.TokenException;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_SLOT_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Connector;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import java.util.Collection;

/**
 * This class uses the PKCS#11 Java api provieded by <a
 * href="http://jce.iaik.tugraz.at/products/14_PKCS11_Wrapper/index.php">IAIK
 * pkcs11 wrapper </a> to perform PKCS#11 digital signature operations. <br>
 * The IAIK wrapper is released in open source under an Apache-style license.
 * <br>
 * Here we use only a low-level subset of the wrapper's api (distributed in the
 * j4sign installer package), so to minimize the weight of the relative jar
 * files in an applet signing environment.
 * <p>
 * Several methods are designed to ease object retrieval during an italian style
 * digital signature process. See
 * {@link PKCS11Signer#findCertificateWithNonRepudiationCritical()}for details.
 *
 *
 * @author Roberto Resoli
 */
public class PKCS11Signer {

    /**
     * The <code>cryptokiLibrary</code> is the native library implementing the
     * <code>PKCS#11</code> specification.
     */
    private java.lang.String cryptokiLibrary = null;
    
    /**
     * The finalization state of <code>cryptokiLibrary</code>?
     */
    private boolean libFinalized = false;
   


	/**
     * The PKCS#11 session identifier returned when a session is opened. Value
     * is -1 if no session is open.
     */
    private long sessionHandle = -1L;

    /**
     * The PKCS#11 token identifier. Value is -1 if there is no current token.
     */
    private long tokenHandle = -1L;
    ;

    /**
     * The java object wrapping criptoki library functionalities.
     */
    private PKCS11 pkcs11Module = null;

    /**
     * PKCS#11 identifier for the signature algorithm.
     */
    private CK_MECHANISM signatureMechanism = null;

    /**
     * The <code>PrintStream</code> where logging messages are written.
     *
     */
    private java.io.PrintStream log = null;

    public PKCS11Signer(String cryptokiLib, long mechanism,
                        java.io.PrintStream out) throws IOException,
            TokenException {

        this(cryptokiLib, out);

        initializeTokenAndMechanism(mechanism);

    }

    public PKCS11Signer(String cryptokiLib, long mechanism, String reader,
                        java.io.PrintStream out) throws IOException,
            TokenException {

        this(cryptokiLib, out);
        setMechanism(mechanism);
        initializeTokenInReader(reader);

    }


    public PKCS11Signer(String cryptokiLib, java.io.PrintStream out) throws
            IOException, TokenException {
        super();

        log = out;
        cryptokiLibrary = cryptokiLib;

        log.println("\n\nInitializing PKCS11Signer...\n");

        log.println("Trying to connect to PKCS#11 module: '" + cryptokiLibrary
                    + "' ...");

        pkcs11Module = PKCS11Connector.connectToPKCS11Module(cryptokiLibrary);
        log.println("connected.\n");

        initializeLibrary();
    }

    /**
     * Initializes cryptoki library operations.
     *
     * @throws PKCS11Exception
     */
    private void initializeLibrary() throws PKCS11Exception {
        log.println("\ninitializing module ... ");
        pkcs11Module.C_Initialize(null);
        log.println("initialized.\n");
    }



    private void initializeTokenAndMechanism(long mechanism) throws
            PKCS11Exception {
        tokenHandle = getTokenSupportingMechanism(mechanism);

        if (tokenHandle >= 0) {
            log.println("\nSetting signing token handle: " + tokenHandle);
            log.println("\nSetting signing  mechanism id: " + mechanism
                        + " -> " + Functions.mechanismCodeToString(mechanism));

            setMechanism(mechanism);
        }
    }

    private void initializeTokenInReader(String reader) throws
            PKCS11Exception {
        long[] tokens = pkcs11Module.C_GetSlotList(true);
        for (int i = 0; i < tokens.length; i++) {

            String readerFromPKCS11 = getSlotDescription((long)
                    tokens[i]);
            String readerFromPKCS112 = readerFromPKCS11.replaceAll(" ", "");
            String readerFromCiR2 = reader.replaceAll(" ", "");
            readerFromPKCS11 = readerFromPKCS11.substring(0,
                    readerFromPKCS11.length() - 1);
            //log.println(readerFromCiR + " = " + readerFromPKCS11 + "?");
            // log.println(readerFromCiR2 + " = " + readerFromPKCS112 + "?");

            //riconoscimento lettore tramite name reader
            if ((readerFromPKCS11.startsWith(reader)) ||
                (readerFromCiR2.endsWith(readerFromPKCS112))) {
                log.println("Settato token " +
                            getSlotDescription((long) tokens[i]));
                tokenHandle = tokens[i];

            }

        }

        if (tokenHandle >= 0) {
            log.println("\nSetting signing token handle: " + tokenHandle);

        }
    }


    public void setMechanism(long mechanism, Object pParameter) {
        this.signatureMechanism = new CK_MECHANISM();

        this.signatureMechanism.mechanism = mechanism;
        this.signatureMechanism.pParameter = pParameter;

    }

    public void setMechanism(long mechanism) {
        this.setMechanism(mechanism, null);

    }

    /**
     * Closes the default PKCS#11 session.
     *
     * @throws PKCS11Exception
     */
    public void closeSession() throws PKCS11Exception {

        if (getSession() == -1L) {
            return;
        }
        log.println("\nClosing session ...");
        pkcs11Module.C_CloseSession(getSession());
        setSession( -1L);

    }

    /**
     * Closes a specific PKCS#11 session.
     *
     * @param sessionHandle
     *            handle of the session to close.
     * @throws PKCS11Exception
     */
    public void closeSession(long sessionHandle) throws PKCS11Exception {

        log.println("\nClosing session with handle: " + sessionHandle + " ...");
        pkcs11Module.C_CloseSession(sessionHandle);

    }

    /**
     * Error decoding function. Currently not implemented (returns 'Unknown
     * error' everytime).
     *
     *
     * @param errorCode
     *            id of the error.
     * @return the decription corresponding to error code.
     */
    public static String decodeError(int errorCode) {
        String errorString = "Unknown error.";
        /*
         * switch (errorCode) { case PKCS11Exception. : errorString = "PIN
         * errato."; break; case PKCS11Exception.PIN_INVALID : errorString =
         * "PIN non valido."; break; case PKCS11Exception.TOKEN_NOT_PRESENT :
         * errorString = "Inserire la carta."; break; }
         */
        return errorString;
    }

    /**
     * Returns the private key handle, on current token, corresponding to the
     * given textual label.
     *
     * @param label
     *            the string label to search.
     * @return the integer identifier of the private key, or -1 if no key was
     *         found.
     * @throws PKCS11Exception
     */
    public long findSignatureKeyFromLabel(String label) throws PKCS11Exception {

        long signatureKeyHandle = -1L;

        if (getSession() < 0) {
            return -1L;
        }

        log.println("finding signature key with label: '" + label + "'");
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];
        //CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_PRIVATE_KEY);

        attributeTemplateList[1] = new CK_ATTRIBUTE();

        attributeTemplateList[1].type = PKCS11Constants.CKA_LABEL;
        attributeTemplateList[1].pValue = label.toCharArray();

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList);
        long[] availableSignatureKeys = pkcs11Module.C_FindObjects(
                getSession(), 100);
        //maximum of 100 at once

        if (availableSignatureKeys == null) {
            log.println("null returned - no signature key found");
        } else {
            log.println("found " + availableSignatureKeys.length
                        + " signature keys, picking first.");
            for (int i = 0; i < availableSignatureKeys.length; i++) {
                if (i == 0) { // the first we find, we take as our signature key
                    signatureKeyHandle = availableSignatureKeys[i];
                    log
                            .println(
                                    "for signing we use signature key with handle: "
                                    + signatureKeyHandle);
                }

            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return signatureKeyHandle;
    }

    /**
     * Returns the private key handle, on current token, corresponding to the
     * given byte[]. ID is often the byte[] version of the label.
     *
     * @param id
     *            the byte[] id to search.
     * @return the integer identifier of the private key, or -1 if no key was
     *         found.
     * @throws PKCS11Exception
     * @see PKCS11Signer#findSignatureKeyFromLabel(String)
     */
    public long findSignatureKeyFromID(byte[] id) throws PKCS11Exception {

        long signatureKeyHandle = -1L;

        if (getSession() < 0) {
            return -1L;
        }

        log.println("finding signature key from id.");
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_PRIVATE_KEY);

        attributeTemplateList[1] = new CK_ATTRIBUTE();

        attributeTemplateList[1].type = PKCS11Constants.CKA_ID;
        attributeTemplateList[1].pValue = id;

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList);
        long[] availableSignatureKeys = pkcs11Module.C_FindObjects(
                getSession(), 100);
        //maximum of 100 at once

        if (availableSignatureKeys == null) {
            log
                    .println(
                            "null returned - no signature key found with matching ID");
        } else {
            log.println("found " + availableSignatureKeys.length
                        + " signature keys, picking first.");
            for (int i = 0; i < availableSignatureKeys.length; i++) {
                if (i == 0) { // the first we find, we take as our signature key
                    signatureKeyHandle = availableSignatureKeys[i];
                    log.println("returning signature key with handle: "
                                + signatureKeyHandle);
                }

            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return signatureKeyHandle;
    }

    /**
     * Returns the first private key handle found on current token.
     *
     * @return a private key handle, or -1 if no key is found.
     * @throws PKCS11Exception
     */
    public long findSignatureKey() throws PKCS11Exception {

        long signatureKeyHandle = -1L;

        if (getSession() < 0) {
            return -1L;
        }

        log.println("finding a signature key...");

        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_PRIVATE_KEY);

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList);
        long[] availableSignatureKeys = pkcs11Module.C_FindObjects(
                getSession(), 100);
        //maximum of 100 at once

        if (availableSignatureKeys == null) {
            log.println("null returned - no signature key found");
        } else {
            log.println("found " + availableSignatureKeys.length
                        + " signature keys, picking first.");
            for (int i = 0; i < availableSignatureKeys.length; i++) {
                if (i == 0) { // the first we find, we take as our signature key
                    signatureKeyHandle = availableSignatureKeys[i];
                    log
                            .println(
                                    "for signing we use signature key with handle: "
                                    + signatureKeyHandle);
                }

            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return signatureKeyHandle;
    }

    /**
     * Sign (here means encrypting with private key) the provided data with a
     * single operation. This is the only modality supported by the (currently
     * fixed) RSA_PKCS mechanism.
     *
     * @param signatureKeyHandle
     *            handle of the private key to use for signing.
     * @param data
     *            the data to sign.
     * @return a byte[] containing signed data.
     * @throws IOException
     * @throws PKCS11Exception
     */
    public byte[] signDataSinglePart(long signatureKeyHandle, byte[] data) throws
            IOException, PKCS11Exception {

        byte[] signature = null;
        if (getSession() < 0) {
            return null;
        }

        System.out.println("\nStart single part sign operation...");
        pkcs11Module.C_SignInit(getSession(), this.signatureMechanism,
                                signatureKeyHandle);

        if ((data.length > 0) && (data.length < 1024)) {
            System.out.println("Signing ...");
            signature = pkcs11Module.C_Sign(getSession(), data);
            System.out.println("FINISHED.");
        } else {
            System.out.println("Error in data length!");
        }

        return signature;

    }

    /**
     * Sign (here means digesting and encrypting with private key) the provided
     * data with a multiple-pass operation. This is the a modality supported by
     * CKM_SHA1_RSA_PKCS, for example, that digests and ecrypts data. Note that
     * some Infocamere card-cryptoki combinations does not supports this type of
     * mechanisms.
     *
     * @param signatureKeyHandle
     *            handle of the private key to use for signing.
     * @param dataStream
     *            an <code>InputStram</code> providing data to sign.
     * @return a byte[] containing signed data.
     * @throws IOException
     * @throws PKCS11Exception
     */
    public byte[] signDataMultiplePart(long signatureKeyHandle,
                                       InputStream dataStream) throws
            IOException, PKCS11Exception {

        byte[] signature = null;
        byte[] buffer = new byte[1024];
        byte[] helpBuffer;
        int bytesRead;

        System.out.println("\nStart multiple part sign operation...");
        pkcs11Module.C_SignInit(getSession(), this.signatureMechanism,
                                signatureKeyHandle);

        while ((bytesRead = dataStream.read(buffer, 0, buffer.length)) >= 0) {
            helpBuffer = new byte[bytesRead];
            // we need a buffer that only holds what to send for signing
            System.arraycopy(buffer, 0, helpBuffer, 0, bytesRead);
            System.out.println("Byte letti: " + bytesRead);

            pkcs11Module.C_SignUpdate(getSession(), helpBuffer);

            Arrays.fill(helpBuffer, (byte) 0);
        }

        Arrays.fill(buffer, (byte) 0);
        signature = pkcs11Module.C_SignFinal(getSession());

        return signature;
    }

    // look for a RSA key and encrypt ...
    public byte[] encryptDigest(String label, byte[] digest) throws
            PKCS11Exception, IOException {

        byte[] encryptedDigest = null;

        long sessionHandle = getSession();
        if (sessionHandle < 0) {
            return null;
        }

        long signatureKeyHandle = findSignatureKeyFromLabel(label);

        if (signatureKeyHandle > 0) {
            log.println("\nStarting digest encryption...");
            encryptedDigest = signDataSinglePart(signatureKeyHandle, digest);
        } else {
            //         we have not found a suitable key, we cannot contiue
        }

        return encryptedDigest;
    }

    /**
     * Queries the a specific token for a certificate suitable for a legal value
     * subscription. See
     * {@link PKCS11Signer#findCertificateWithNonRepudiationCritical()}.
     *
     * @see findCertificateWithNonRepudiationCritical()
     *
     * @param token
     *            ID of the token to query for the certificate.
     * @return the handle of the required certificate, if found; -1 otherwise.
     * @throws TokenException
     * @throws CertificateException
     */

    public long findCertificateWithNonRepudiationCritical(long token) throws
            TokenException, CertificateException {

        long certKeyHandle = -1L;

        long s = openSession(token);

        if (s == -1L) {
            log.println("Unable to open a session on token with handle: "
                        + token);
            return -1L;
        }

        log.println("finding a certificate with "
                    + "Critical KeyUsage including non repudiation\n"
                    + " on token with handle: " + token);

        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);

        pkcs11Module.C_FindObjectsInit(s, attributeTemplateList);
        long[] availableCertificates = pkcs11Module.C_FindObjects(s, 100);
        //maximum of 100 at once
        pkcs11Module.C_FindObjectsFinal(s);

        if (availableCertificates == null) {
            log.println("null returned - no certificate key found");
        } else {
            log.println("found " + availableCertificates.length
                        + " certificates");

            byte[] certBytes = null;
            java.security.cert.X509Certificate javaCert = null;
            java.security.cert.CertificateFactory cf = java.security.cert.
                    CertificateFactory
                    .getInstance("X.509");
            java.io.ByteArrayInputStream bais = null;
            for (int i = 0; (i < availableCertificates.length)
                         && (certKeyHandle < 0); i++) {
                log.println("Checking KeyUsage for certificate with handle: "
                            + availableCertificates[i]);
                certBytes = getDEREncodedCertificate(availableCertificates[i],
                        s);
                bais = new java.io.ByteArrayInputStream(certBytes);
                javaCert = (java.security.cert.X509Certificate) cf
                           .generateCertificate(bais);
                if (isKeyUsageNonRepudiationCritical(javaCert)) {
                    certKeyHandle = availableCertificates[i];
                    log.println("Check OK!");
                } else {
                    log.println("Check failed.");
                }
            }
        }

        closeSession(s);

        return certKeyHandle;
    }

    /**
     * Queries the current token for a certificate suitable for a legal value
     * subscription.
     * <p>
     * According to the italian law, if you want give to the digital signature
     * the maximum legal value (equivalent to a signature on paper), and also
     * for the sake of interoperability, the signer certificate has to satisfy
     * some costraints. See <a
     * href="http://www.cnipa.gov.it/site/_contentfiles/00127900/127910_CR%2024_2000.pdf">
     * the official document in PDF format <a>or <a
     * href="http://www.interlex.it/testi/interop.htm"> this html page <a>(only
     * in italian, sorry) for details.
     * <p>
     * In particular, the certificate has to carry a KeyUsage extension of 'non
     * repudiation' (OID: 2.5.29.15) marked as critical.
     *
     *
     * @return the handle of the required certificate, if found; -1 otherwise.
     * @throws TokenException
     * @throws CertificateException
     */
    public long findCertificateWithNonRepudiationCritical() throws
            TokenException, CertificateException {

        long certKeyHandle = -1L;

        if (getSession() < 0) {
            return -1L;
        }

        log
                .println(
                        "finding a certificate with Critical KeyUsage including non repudiation ...");

        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList);
        long[] availableCertificates = pkcs11Module.C_FindObjects(getSession(),
                100);
        //maximum of 100 at once
        pkcs11Module.C_FindObjectsFinal(getSession());

        if (availableCertificates == null) {
            log.println("null returned - no certificate key found");
        } else {
            log.println("found " + availableCertificates.length
                        + " certificates");

            byte[] certBytes = null;

            java.security.cert.X509Certificate javaCert = null;
            java.security.cert.CertificateFactory cf = java.security.cert.
                    CertificateFactory
                    .getInstance("X.509");
            java.io.ByteArrayInputStream bais = null;
            for (int i = 0; (i < availableCertificates.length)
                         && (certKeyHandle < 0); i++) {

                log.println("Checking KeyUsage for certificate with handle: "
                            + availableCertificates[i]);
                certBytes = getDEREncodedCertificate(availableCertificates[i]);
                bais = new java.io.ByteArrayInputStream(certBytes);
                javaCert = (java.security.cert.X509Certificate) cf
                           .generateCertificate(bais);
                if (isKeyUsageNonRepudiationCritical(javaCert)) {
                    certKeyHandle = availableCertificates[i];
                    log.println("Check OK!");
                } else {
                    log.println("Check failed.");
                }
            }

        }

        return certKeyHandle;
    }

    /**
     * Trova un'array di certHandle di tutti i certificati presenti sulla carta
     * senza che la sessione sia aperta (no password). La length dell'array corrisponde
     * al numero dei certificati
     *
     * @return the handle of the required certificate, if found; -1 otherwise.
     * @throws TokenException
     * @throws CertificateException
     */
    public long[] findCertificates() throws TokenException,
            CertificateException {

        long certKeyHandle = -1L;

        log.println("finding all certificates on token ...");

        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList);

        long[] availableCertificates = pkcs11Module.C_FindObjects(getSession(),
                100);
        //maximum of 100 at once

        pkcs11Module.C_FindObjectsFinal(getSession());

        if (availableCertificates == null) {
            log.println("null returned - no certificate key found");
        } else {
            log.println("found " + availableCertificates.length
                        + " certificates");

        }

        return availableCertificates;
    }


    /**
     * checks Key Usage constraints of a java certificate.
     *
     * @param javaCert
     *            the certificate to check as java object.
     * @return true if the given certificate has a KeyUsage extension of 'non
     *         repudiation' (OID: 2.5.29.15) marked as critical.
     * @see PKCS11Signer#findCertificateWithNonRepudiationCritical()
     */
    boolean isKeyUsageNonRepudiationCritical(
            java.security.cert.X509Certificate javaCert) {

        boolean isNonRepudiationPresent = false;
        boolean isKeyUsageCritical = false;

        Set oids = javaCert.getCriticalExtensionOIDs();
        if (oids != null) {
            // check presence between critical extensions of oid:2.5.29.15
            // (KeyUsage)
            isKeyUsageCritical = oids.contains("2.5.29.15");
        }

        boolean[] keyUsages = javaCert.getKeyUsage();
        if (keyUsages != null) {
            //check non repudiation (index 1)
            isNonRepudiationPresent = keyUsages[1];
        }

        return (isKeyUsageCritical && isNonRepudiationPresent);

    }

    /**
     * Finds a certificate matching the given byte[] id.
     *
     * @param id
     * @return the handle of the certificate, or -1 if not found.
     * @throws PKCS11Exception
     */
    public long findCertificateFromID(byte[] id) throws PKCS11Exception {

        long sessionHandle = getSession();
        long certificateHandle = -1L;

        if (sessionHandle < 0 || id == null) {
            return -1L;
        }

        log.println("find certificate from id.");

        // now get the certificate with the same ID as the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);
        attributeTemplateList[1] = new CK_ATTRIBUTE();
        attributeTemplateList[1].type = PKCS11Constants.CKA_ID;
        attributeTemplateList[1].pValue = id;

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList);
        long[] availableCertificates = pkcs11Module.C_FindObjects(getSession(),
                100);
        //maximum of 100 at once
        if (availableCertificates == null) {
            log.println("null returned - no certificate found");
        } else {
            log.println("found " + availableCertificates.length
                        + " certificates with matching ID");
            for (int i = 0; i < availableCertificates.length; i++) {
                if (i == 0) { // the first we find, we take as our certificate
                    certificateHandle = availableCertificates[i];
                    System.out.print("for verification we use ");
                }
                log.println("certificate " + i);
            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return certificateHandle;
    }

    /**
     * Finds a certificate matching the given textual label.
     *
     * @param label
     * @return the handle of the certificate, or -1 if not found.
     * @throws PKCS11Exception
     */
    public long findCertificateFromLabel(char[] label) throws PKCS11Exception {

        long sessionHandle = getSession();
        long certificateHandle = -1L;

        if (sessionHandle < 0 || label == null) {
            return -1L;
        }

        log.println("find certificate from label.");

        // now get the certificate with the same ID as the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[2];

        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        attributeTemplateList[0].pValue = new Long(
                PKCS11Constants.CKO_CERTIFICATE);
        attributeTemplateList[1] = new CK_ATTRIBUTE();
        attributeTemplateList[1].type = PKCS11Constants.CKA_LABEL;
        attributeTemplateList[1].pValue = label;

        pkcs11Module.C_FindObjectsInit(getSession(), attributeTemplateList);
        long[] availableCertificates = pkcs11Module.C_FindObjects(getSession(),
                100);
        //maximum of 100 at once
        if (availableCertificates == null) {
            log.println("null returned - no certificate found");
        } else {
            log.println("found " + availableCertificates.length
                        + " certificates with matching ID");
            for (int i = 0; i < availableCertificates.length; i++) {
                if (i == 0) { // the first we find, we take as our certificate
                    certificateHandle = availableCertificates[i];
                    System.out.print("for verification we use ");
                }
                log.println("certificate " + i);
            }
        }
        pkcs11Module.C_FindObjectsFinal(getSession());

        return certificateHandle;
    }

    /**
     * Searches the certificate corresponding to the private key identified by
     * the given handle; this method assumes that corresponding certificates and
     * private keys are sharing the same byte[] IDs.
     *
     * @param signatureKeyHandle
     *            the handle of a private key.
     * @return the handle of the certificate corrisponding to the given key.
     * @throws PKCS11Exception
     */
    public long findCertificateFromSignatureKeyHandle(long signatureKeyHandle) throws
            PKCS11Exception {

        long sessionHandle = getSession();
        long certificateHandle = -1L;

        if (sessionHandle < 0) {
            return -1L;
        }

        log.println("\nFind certificate from signature key handle: "
                    + signatureKeyHandle);

        // first get the ID of the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_ID;

        pkcs11Module.C_GetAttributeValue(getSession(), signatureKeyHandle,
                                         attributeTemplateList);

        byte[] keyAndCertificateID = (byte[]) attributeTemplateList[0].pValue;
        log.println("ID of signature key: "
                    + Functions.toHexString(keyAndCertificateID));

        return findCertificateFromID(keyAndCertificateID);
    }

    /**
     * Searches the private key corresponding to the certificate identified by
     * the given handle; this method assumes that corresponding certificates and
     * private keys are sharing the same byte[] IDs.
     *
     * @param certHandle
     *            the handle of a certificate.
     * @return the handle of the private key corrisponding to the given
     *         certificate.
     * @throws PKCS11Exception
     */
    public long findSignatureKeyFromCertificateHandle(long certHandle) throws
            PKCS11Exception {

        long sessionHandle = getSession();
        long keyHandle = -1L;

        if (sessionHandle < 0) {
            return -1L;
        }

        log.println("\nFind signature key from certificate with handle: "
                    + certHandle);

        // first get the ID of the signature key
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_ID;

        pkcs11Module.C_GetAttributeValue(getSession(), certHandle,
                                         attributeTemplateList);

        byte[] keyAndCertificateID = (byte[]) attributeTemplateList[0].pValue;

        log
                .println("ID of cert: "
                         + Functions.toHexString(keyAndCertificateID));

        return findSignatureKeyFromID(keyAndCertificateID);
    }

    /**
     * Returns the DER encoded certificate corresponding to the given label, as
     * read from the token.
     *
     * @param label
     *            the object label on the token.
     * @return the DER encoded certificate, as byte[]
     * @throws UnsupportedEncodingException
     * @throws TokenException
     */
    public byte[] getDEREncodedCertificateFromLabel(String label) throws
            TokenException {
        System.out.println("reading DER encoded certificate bytes");
        byte[] certBytes = null;

        long sessionHandle = getSession();
        if (sessionHandle < 0) {
            return null;
        }

        long certificateHandle = findCertificateFromLabel(label.toCharArray());
        certBytes = getDEREncodedCertificate(certificateHandle);

        return certBytes;
    }

    /**
     * Returns the DER encoded certificate identified by the given handle, as
     * read from the token.
     *
     * @param certHandle
     *            the handleof the certificate on the token.
     * @return the DER encoded certificate, as a byte array.
     * @throws UnsupportedEncodingException
     * @throws TokenException
     */
    public byte[] getDEREncodedCertificate(long certHandle) throws
            PKCS11Exception {

        System.out.println("reading certificate bytes");

        byte[] certBytes = null;
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
        template[0] = new CK_ATTRIBUTE();
        template[0].type = PKCS11Constants.CKA_VALUE;
        pkcs11Module.C_GetAttributeValue(getSession(), certHandle, template);
        certBytes = (byte[]) template[0].pValue;

        return certBytes;
    }
    
    /**
     * Returns the DER encoded certificate identified by the given handle, 
     * and its ID attribute.
     *
     * @param certHandle
     *            the handle of the certificate on the token, as a byte array.
     * @param id
     *            the ID of the Certificate as a ByteArrayOutputStream.
     * @return the DER encoded certificate, as a byte array (has to to be not Null) .
     * @throws IOException 
     * @throws UnsupportedEncodingException
     * @throws TokenException
     */
    public byte[] getDEREncodedCertificateAndID(long certHandle, ByteArrayOutputStream id) throws
            PKCS11Exception, IOException {

        System.out.println("reading certificate bytes");

        byte[] certBytes = null;
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[2];
        template[0] = new CK_ATTRIBUTE();
        template[0].type = PKCS11Constants.CKA_VALUE;
        template[1] = new CK_ATTRIBUTE();
        template[1].type = PKCS11Constants.CKA_ID;
        pkcs11Module.C_GetAttributeValue(getSession(), certHandle, template);
        
        certBytes = (byte[]) template[0].pValue;
        id.write((byte[]) template[1].pValue);

        return certBytes;
    }

    public byte[] getDEREncodedCertificate(long certHandle, long sessionHandle) throws
            PKCS11Exception {

        System.out.println("reading certificate bytes");

        byte[] certBytes = null;
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
        template[0] = new CK_ATTRIBUTE();
        template[0].type = PKCS11Constants.CKA_VALUE;
        pkcs11Module.C_GetAttributeValue(sessionHandle, certHandle, template);
        certBytes = (byte[]) template[0].pValue;

        return certBytes;
    }

    public String getSlotDescription(long slotID) {
        try {
            CK_SLOT_INFO slotInfo = pkcs11Module.C_GetSlotInfo(slotID);
            String s = new String(slotInfo.slotDescription);
            return s;
        } catch (PKCS11Exception ex) {
            return null;
        }
    }

    /**
     * Gets the cryptoki library name.
     *
     * @return the current cryptoki library name.
     */
    public java.lang.String getCryptokiLibrary() {
        return cryptokiLibrary;
    }

    /*
     * // look for a RSA key and try signature... currently not used //
     * MD5_RSA_PKCS dos not works as expected (MD5 + PKCS#1 encryption public
     * byte[] getEncryptedDigest(String label, byte[] data) {
     *
     * byte[] encryptedDigest = null;
     *
     * PKCS11Session s = getSession(); if (s == null) return null;
     *
     * //log.println(s.getInfo() + "\n"); log.println("Getting PKCS11 Private
     * key labeled '" + label + "'..."); int[] attrtypes = { PKCS11Object.CLASS,
     * PKCS11Object.KEY_TYPE, PKCS11Object.LABEL };
     *
     * Object[] attrvalues = { PKCS11Object.PRIVATE_KEY, // CLASS
     * PKCS11Object.RSA, // KEY_TYPE label //LABEL };
     *
     * s.findObjectsInit(attrtypes, attrvalues); PKCS11Object rsaPrivKey =
     * s.findObject(); s.findObjectsFinal();
     *
     * if (rsaPrivKey == null) log.println("sorry, no RSA private key on
     * token."); else { log.println("Private key Found."); //log.println("RSA
     * priv key:\n" + rsaPrivKey + "\n"); log.println("generating digest ...");
     *
     * //String msg = "message to sign "; // pad to multiple of 8 !!! //byte[]
     * plain = msg.getBytes();
     *
     * java.math.BigInteger dataLengthBI = java.math.BigInteger
     * .valueOf(data.length); int remainder =
     * dataLengthBI.mod(java.math.BigInteger.valueOf(8)) .intValue(); byte[]
     * plain = (remainder != 0) ? new byte[8 - remainder + data.length] : new
     * byte[data.length];
     *
     * for (int i = 0; i < data.length; i++) plain[i] = data[i];
     *
     * byte[] signature = new byte[256]; // sign...
     * s.signInit(PKCS11Mechanism.MD5_RSA_PKCS, null, rsaPrivKey);
     *
     * int n = s.sign(plain, 0, data.length, signature, 0); log.print("signature
     * (first " + n + " bytes):\n" + PKCS11Object.bytesToString(signature, 0) +
     * "\n"); encryptedDigest = new byte[n]; for (int i = 0; i <
     * encryptedDigest.length; i++) encryptedDigest[i] = signature[i]; }
     *
     * return encryptedDigest; }
     */

    /**
     * Gets the java wrapper for the cryptoki.
     *
     * @return the java wrapper for the cryptoki.
     */
    private PKCS11 getPkcs11() {
        return pkcs11Module;
    }

    /*
     * public void getPrivateKey(PKCS11Helper helper, String label) {
     *
     * PKCS11Session s = getSession(); if (s == null) return;
     *
     * //log.println(s.getInfo() + "\n"); log.println("Getting PKCS11 Private
     * key labeled '" + label + "'..."); int[] attrtypes = { PKCS11Object.CLASS,
     * PKCS11Object.KEY_TYPE //, PKCS11Object.LABEL //gives an error
     * sometimes!!!! , PKCS11Object.ID //better method };
     *
     * Object[] attrvalues = { PKCS11Object.PRIVATE_KEY, // CLASS
     * PKCS11Object.RSA // KEY_TYPE //,label //LABEL , label.getBytes() };
     *
     * s.findObjectsInit(attrtypes, attrvalues); PKCS11Object rsaPrivKey = null;
     * byte[] id = null; do { rsaPrivKey = s.findObject(); if (rsaPrivKey !=
     * null) { //log.println(rsaPrivKey); id = (byte[])
     * rsaPrivKey.getAttributeValue(PKCS11Object.ID); try { log
     * .println("Private key Found:\t" + new String(id, "UTF8")); } catch
     * (java.io.UnsupportedEncodingException ueo) { log.println(ueo); } } }
     * while (rsaPrivKey != null); s.findObjectsFinal(); }
     */

    /**
     * Gets the current session handle.
     *
     * @return the <code>long</code> identifying the current session.
     */
    private long getSession() {
        return sessionHandle;
    }

    /**
     * Finalizes PKCS#11 operations; note this NOT actually unloads the native
     * library.
     *
     * @throws Throwable
     */
    public void libFinalize() throws Throwable {
        log.println("\nfinalizing PKCS11 module...");
       // getPkcs11().finalize();
        pkcs11Module.C_Finalize(null);
        libFinalized = true;
        log.println("finalized.\n");
    }

    /**
     * Logs in to the current session; login is usually necessary to see and use
     * private key objects on the token. This method converts the given
     * <code>String</code> as a <code>char[]</code> and calls
     * {@link #login(char[])}.
     *
     * @param pwd
     *            password as a String.
     * @throws PKCS11Exception
     */
    public void login(String pwd) throws PKCS11Exception {
        login(pwd.toCharArray());
    }

    /**
     * Logs in to the current session; login is usually necessary to see and use
     * private key objects on the token.
     *
     * @param pwd
     *            password as a char[].
     * @throws PKCS11Exception
     */
    public void login(char[] pwd) throws PKCS11Exception {
        if (getSession() < 0) {
            return;
        }
        // log in as the normal user...

        pkcs11Module.C_Login(getSession(), PKCS11Constants.CKU_USER, pwd);
        log.println("\nUser logged into session.");
    }

    /**
     * Logs out the current user.
     *
     * @throws PKCS11Exception
     */
    public void logout() throws PKCS11Exception {
        if (getSession() < 0) {
            return;
        }
        // log in as the normal user...
        pkcs11Module.C_Logout(getSession());
        log.println("\nUser logged out.\n");
    }

    /**
     * Gets currently loaded cryptoky description.
     *
     * @throws PKCS11Exception
     */
    private void getModuleInfo() throws PKCS11Exception {
        log.println("getting PKCS#11 module info");
        CK_INFO moduleInfo = pkcs11Module.C_GetInfo();
        log.println(moduleInfo);
    }

    /**
     * Gets current reader infos.
     *
     * @throws PKCS11Exception
     */
    private long[] getSlotList() throws PKCS11Exception {
        log.println("getting slot list");
        long[] slotIDs = null;
        //get all slots
        slotIDs = pkcs11Module.C_GetSlotList(false);
        CK_SLOT_INFO slotInfo;
        for (int i = 0; i < slotIDs.length; i++) {
            log.println("Slot Info: ");
            slotInfo = pkcs11Module.C_GetSlotInfo(slotIDs[i]);
            log.println(slotInfo);
        }
        return slotIDs;
    }

    /**
     * Lists currently inserted tokens and relative infos.
     *
     * @throws PKCS11Exception
     */


    public long[] getTokenList() {
        log.println("\ngetting token list");
        long[] tokenIDs = null;
        //get only slots with a token present
        try {
            tokenIDs = pkcs11Module.C_GetSlotList(true);
        } catch (PKCS11Exception ex) {
            log.println("PKCS11Exception: " + ex);
        }
        CK_TOKEN_INFO tokenInfo;
        log.println(tokenIDs.length + " tokens found.");
        for (int i = 0; i < tokenIDs.length; i++) {
            log.println(i + ") Info for token with handle: " + tokenIDs[i]);
            tokenInfo = null;
            try {
                tokenInfo = pkcs11Module.C_GetTokenInfo(tokenIDs[i]);
            } catch (PKCS11Exception ex1) {
                log.println("PKCS11Exception: " + ex1);
            }
            log.println(tokenInfo);
        }

        return tokenIDs;
    }

    /**
     * Lists currently inserted tokens.
     * Questo metodo è public e utilizzato in ReadCertsTask
     *
     * @throws PKCS11Exception
     */

    public long[] getTokens() throws PKCS11Exception {

        long[] tokenIDs = null;
        //get only slots with a token present
        tokenIDs = pkcs11Module.C_GetSlotList(true);

        //log.println(tokenIDs.length + " tokens found.");

        return tokenIDs;
    }
    
    public String getTokenDescription() throws PKCS11Exception {
        CK_TOKEN_INFO tokenInfo;

        log.println("\ngetting token info...");

        tokenInfo= pkcs11Module.C_GetTokenInfo(this.tokenHandle);
        
        log.println(tokenInfo);
        
        String label = new String(tokenInfo.label);
        String serial = new String(tokenInfo.serialNumber);
        String maufacturer = new String(tokenInfo.manufacturerID);
        
        return label.trim() +" "+ maufacturer.trim()+" "+serial.trim();

    }

    /**
     * Gets informations on cryptographic operations supported by the tokens.
     *
     * @throws PKCS11Exception
     */
    public void getMechanismInfo() throws PKCS11Exception {
        CK_MECHANISM_INFO mechanismInfo;

        log.println("\ngetting mechanism list...");
        long[] slotIDs = getTokenList();
        for (int i = 0; i < slotIDs.length; i++) {
            log.println("getting mechanism list for slot " + slotIDs[i]);
            long[] mechanismIDs = pkcs11Module.C_GetMechanismList(slotIDs[i]);
            for (int j = 0; j < mechanismIDs.length; j++) {
                log.println("mechanism info for mechanism id "
                            + mechanismIDs[j] + "->"
                            + Functions.mechanismCodeToString(mechanismIDs[j])
                            + ": ");
                mechanismInfo = pkcs11Module.C_GetMechanismInfo(slotIDs[i],
                        mechanismIDs[j]);
                log.println(mechanismInfo);
            }
        }

    }

    public long findSuitableToken(long mechanismCode) throws PKCS11Exception {
        long token = -1L;

        ArrayList tokenList = findTokensSupportingMechanism(mechanismCode);
        String mechanismString = Functions.mechanismCodeToString(mechanismCode);

        if (tokenList == null) {
            log.println("\nSorry, no Token supports the required mechanism "
                        + mechanismString + "!");
            return -1L;
        }

        Iterator i = tokenList.iterator();
        long currToken = -1L;
        while (i.hasNext() && (token == -1L)) {
            currToken = ((Long) i.next()).longValue();
            log.println("\nToken with handle " + currToken
                        + " supports required mechanism " + mechanismString +
                        ".");
            try {
                if (findCertificateWithNonRepudiationCritical(currToken) != -1L) {
                    token = currToken;
                }
            } catch (CertificateException e) {
                log.println(e);
            } catch (TokenException e) {
                log.println(e);
            }
        }

        return token;
    }

    public ArrayList findTokensSupportingMechanism(long mechanismCode) throws
            PKCS11Exception {

        ArrayList tokenList = null;

        String mechanismString = Functions.mechanismCodeToString(mechanismCode);

        long[] tokenIDs = getTokenList();

        for (int i = 0; i < tokenIDs.length; i++) {
            if (isMechanismSupportedByToken(mechanismCode, tokenIDs[i])) {
                if (tokenList == null) {
                    tokenList = new ArrayList();
                }
                tokenList.add(new Long(tokenIDs[i]));
            }
        }

        return tokenList;
    }

    /**
     * Queries if there is a token that supporting a given cryptographic
     * operation.
     *
     * @param mechanismCode
     *            the ID of the required mechanism.
     * @return the handle if the token supporting the given mechanism, -1
     *         otherwise.
     * @throws PKCS11Exception
     */
    public long getTokenSupportingMechanism(long mechanismCode) throws
            PKCS11Exception {

        long token = -1L;

        String mechanismString = Functions.mechanismCodeToString(mechanismCode);

        long[] tokenIDs = getTokenList();

        for (int i = 0; (i < tokenIDs.length) && (token < 0); i++) {
            if (isMechanismSupportedByToken(mechanismCode, tokenIDs[i])) {
                token = tokenIDs[i];
            }
        }

        log.println((token >= 0) ? "\nToken with handle " + token
                    + " supports required mechanism " + mechanismString + "."
                    : "\nSorry, no Token supports the required mechanism "
                    + mechanismString + "!");

        return token;
    }

    /**
     * Tells if a given token supports a given cryptographic operation. Also
     * lists all supported mechanisms.
     *
     * @param mechanismCode
     *            the mechanism ID.
     * @param tokenID
     *            the token handla.
     * @return <code>true</code> if the token supports the mechanism.
     * @throws PKCS11Exception
     */
    public boolean isMechanismSupportedByToken(long mechanismCode, long tokenID) throws
            PKCS11Exception {

        boolean isSupported = false;

        long[] mechanismIDs = pkcs11Module.C_GetMechanismList(tokenID);

        log.println("listing  mechanisms:");
        for (int i = 0; i < mechanismIDs.length; i++) {
            log.println(mechanismIDs[i] + ": "
                        + Functions.mechanismCodeToString(mechanismIDs[i]));
        }

        Arrays.sort(mechanismIDs);
        isSupported = Arrays.binarySearch(mechanismIDs, mechanismCode) >= 0;

        return isSupported;
    }

    /**
     * Opens a session on a specific token.
     *
     * @param aTokenHandle
     *            the token ID.
     *
     * @throws TokenException
     */
    public long openSession(long aTokenHandle) throws TokenException {
        long sessionHandle = -1L;

        sessionHandle = pkcs11Module.C_OpenSession(aTokenHandle,
                PKCS11Constants.CKF_SERIAL_SESSION, null, null);

        log.println("\nSession with handle: " + sessionHandle
                    + " opened on token with handle: " + aTokenHandle + " .");

        return sessionHandle;
    }

    /**
     * Opens a session on the default token.
     *
     * @throws TokenException
     */
    public void openSession() throws TokenException {
        long sessionHandle = -1L;
        if (getTokenHandle() >= 0) {
            sessionHandle = pkcs11Module.C_OpenSession(getTokenHandle(),
                    PKCS11Constants.CKF_SERIAL_SESSION, null, null);

            setSession(sessionHandle);
            log.println("\nSession opened.");

        } else {
            log.println("No token found!");
        }
    }

    /**
     * Opens a session on the token, logging in the user.
     *
     * @throws TokenException
     */
    public void openSession(char[] password) throws TokenException, PKCS11Exception {
        openSession();
        login(password);
    }

    /**
     * Sets the cryptoky library
     *
     * @param newCryptokiLibrary
     *            the cryptoki name.
     */
    public void setCryptokiLibrary(java.lang.String newCryptokiLibrary) {
        cryptokiLibrary = newCryptokiLibrary;
    }

    /**
     * Sets the session handle.
     *
     * @param newSession
     */
    private void setSession(long newSession) {
        this.sessionHandle = newSession;
    }

    /**
     * Gets the current token.
     *
     * @return Returns the token handle
     */
    public long getTokenHandle() {
        return tokenHandle;
    }

    /**
     * Sets the current token handle.
     *
     * @param token
     *            the token handle to set.
     */
    public void setTokenHandle(long token) {
        this.tokenHandle = token;
    }
    
    /**
     * Is <code>cryptokiLibrary</code> finalized (unlinked) ?
     */
    
    public boolean isLibFinalized() {
		return libFinalized;
	}
}
