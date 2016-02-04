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

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.logging.Logger;
import java.util.zip.*;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

/**
 * CA (Certification Authorities) that issue digital certificates <BR>
 * (also called digital passports, X.509 certificates, or public-key
 * certificates).<BR>
 * This class allows you to add, delete and get information about CA.<BR>
 * It also puts in service a CRL manager that verifies and controls certificates
 * revocation lists.<BR>
 * <BR>
 * 
 * Rappresenta la lista delle CA (Certification Authorities) riconosciute dal
 * sistema<BR>
 * Fornisce i metodi di verifica dei certificati e di controllo delle CRL
 * 
 * @author Francesco Cendron
 */
public class CertificationAuthorities {
	private Logger log = Logger.getLogger(this.getClass().getName());
	
    private boolean debug;

    private boolean useproxy = false;

    private boolean alwaysCrlUpdate;

    private String auth = null;

    private HashMap authorities;

    private String message;

    static {
		org.bouncycastle.jce.provider.BouncyCastleProvider p = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		if (Security.getProvider(p.getName()) == null)
			Security.addProvider(p);
    }

    /**
     * Instatiate the class with an empty list of CA. If you need to add a CA,
     * use<BR>
     * the addCertificateAuthority method.<BR>
     * <BR>
     * Istanzia la classe con una lista delle CA vuota. Occorre usare
     * esplicitamente il metodo addCertificateAuthority per inserire nella lista
     * le CA volute.
     */
    public CertificationAuthorities() {
        authorities = new HashMap();
        debug = false;
        // debug = true;
        alwaysCrlUpdate = false;
    }

    /**
     * This loads CA certificates in the specified dir<BR>
     * <BR>
     * 
     * Carica i certificati delle CA dai file presenti nella directory
     * specificata
     * 
     * @param caDir
     *            dir containing CA certificates in DER o base64
     * @param debug
     *            if true, it showa debug messages during certificates reading
     * @throws GeneralSecurityException
     *             if no CA is loaded
     * @throws IOException
     */
    public CertificationAuthorities(File caDir, boolean debug)
            throws GeneralSecurityException, IOException {
        this();
        this.setDebug(debug);
        if (!caDir.isDirectory()) {
        	log.severe(caDir.getPath() + " non e' una directory");
            throw new IllegalArgumentException(caDir.getPath()
                    + " non e' una directory");
        } else if (!caDir.canRead()) {
        	log.severe(caDir.getPath() + " non e' leggibile");
            throw new IllegalArgumentException(caDir.getPath()
                    + " non e' leggibile");
        } else {
            String nome = null;
            File certFiles[] = caDir.listFiles();
            for (int i = 0; i < certFiles.length; i++) {
                nome = certFiles[i].getPath();
                log.fine("Lettura del file: " + nome);
                try {
                    addCertificateAuthority(getBytesFromPath(nome));
                } catch (GeneralSecurityException ge) {
                    log.severe("Certificato CA non valido: " + nome + " - "
                            + ge.getMessage());
                }
            }
        }
        if (authorities.isEmpty()) {
            log.severe("Nessuna CA caricata");
            throw new GeneralSecurityException("Nessuna CA caricata");
        }
        log.info("Inseriti " + authorities.size() + " certificati CA");
    }

    /**
     * This loads CA certificates in the specified dir<BR>
     * No debug message is shown<BR>
     * 
     * Carica i certificati delle CA dai file presenti nella directory
     * specificata.<br>
     * Non vengono visualizzati i messaggi di debug
     * 
     * @param caDir
     *            dir containing CA certificates in DER o base64
     * @throws GeneralSecurityException
     *             if no CA is loaded
     * @throws IOException
     * 
     */
    public CertificationAuthorities(File caDir)
            throws GeneralSecurityException, IOException {
        this(caDir, false);
    }

    /**
     * This loads CA certificates from a ZIP file<BR>
     * <BR>
     * 
     * Carica i certificati delle CA da file ZIP
     * 
     * @param is
     *            stream relative to ZIP file containing "valid" CA
     * @param debug
     *            if true, it shows debug messages during ZIP file parsing
     * @throws GeneralSecurityException
     *             if no CA is loaded
     * @throws IOException
     *             any error during ZIP file reading
     */
    public CertificationAuthorities(InputStream is, boolean debug)
            throws GeneralSecurityException, IOException {
        this();
        this.setDebug(debug);
        
        this.loadFromStream(is);
        
        if (authorities.isEmpty()) {
            log.severe("Nessuna CA caricata");
            throw new GeneralSecurityException("Nessuna CA caricata");
        }
        log.info("Inseriti " + authorities.size() + " certificati CA");
    }

    /**
     * This loads CA certificates from a ZIP file.<BR>
     * No debug message is shown.<BR>
     * 
     * Carica i certificati delle CA da file ZIP
     * 
     * @param is
     *            stream relative to ZIP file containing "valid" CA
     * @throws GeneralSecurityException
     *             if no CA is loaded
     * @throws IOException
     *             any error during ZIP file reading
     */

    public CertificationAuthorities(InputStream is)
            throws GeneralSecurityException, IOException {
        this(is, false);
    }

    
    //ROB aggiunto, carica direttamente da un url; non utilizzato al momento
    /**
     * This loads CA certificates from a ZIP file present at the specified URL.<BR>
     * No debug message is shown.<BR>
     * Carica i certificati delle CA da un file ZIP presente all'indirizzo
     * specificato
     * 
     * @param url
     *            URL where you can fin ZIP file containg CA
     * @param debug
     *            if true, it shows debug messages during ZIP file downloading
     *            and parsing
     * @throws IOException 
     * @throws GeneralSecurityException
     *             if no CA is loaded
     * @throws IOException
     *             any error during ZIP file reading
     */
 
    /*
    public CertificationAuthorities(URL url, boolean debug)
            throws GeneralSecurityException, IOException {
        // da testare!!
        // this(new ZipInputStream(url.openStream()), debug);

        this(getCmsInputStream(url), debug);

    }
    */
    
    private void loadFromStream(InputStream is) throws IOException{
    	
        byte[] bcer = new byte[4096];
        ZipEntry ze = null;
        ZipInputStream zis = null;
        ByteArrayOutputStream bais = null;
        try {
            zis = new ZipInputStream(is);
            log.info("Lettura ZIP stream");
            while ((ze = zis.getNextEntry()) != null) {
                // lettura singola entry dello zip
                log.finest("Lettura ZIP entry " + ze.getName());

                if (!ze.isDirectory()) {
                    bais = new ByteArrayOutputStream(4096);
                    int read;
                    while ((read = zis.read(bcer, 0, bcer.length)) > -1) {
                        bais.write(bcer, 0, read);
                    }
                    bais.flush();
                    try {
                        addCertificateAuthority(bais.toByteArray());
                    } catch (GeneralSecurityException ge) {
                    	log.finest("Certificato CA non valido: " + ze.getName()
                                + " - " + ge.getMessage());
                    }
                    bais.close();
                }
            }
        } catch (IOException ie) {
        	log.severe("Fallita lettura dello ZIP: " + ie.getMessage());
            throw ie;
        } finally {
            try {
                zis.close();
            } catch (IOException ie) {
            }
        }
    	
    }

    //ROB duplicato del metodo in VerifyTask, da fattorizzare
    /*
    private InputStream getCmsInputStream(URL url) {

        ByteArrayInputStream bais = null;
        try {
            CMSSignedData cms = new CMSSignedData(url.openStream());

            cms.getSignedContent();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            cms.getSignedContent().write(baos);
            bais = new ByteArrayInputStream(baos.toByteArray());
        } catch (CMSException e) {
            // TODO Auto-generated catch block
            log.
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return bais;

    }
*/


    /**
     * This loads CA certificates from a ZIP file present at the specified URL.<BR>
     * No debug message is shown.<BR>
     * Carica i certificati delle CA da un file ZIP presente all'indirizzo
     * specificato. <br>
     * Non vengono visualizzati i messaggi di debug
     * 
     * @param url
     *            URL where you can fin ZIP file containg CA
     * @throws GeneralSecurityException
     *             if no CA is loaded
     * @throws IOException
     *             any error during ZIP file reading
     * 
     */
    
    /*
     
    
    public CertificationAuthorities(URL url) throws GeneralSecurityException,
            IOException {
        this(url, false);
    }
*/
    /**
     * Returns the number of CA Restituisce il numero delle CA riconosciute
     * dall'applicazione
     * 
     * @return the number of CA
     */
    public int getCANumber() {
        return authorities.size();
    }

    /**
     * Returns the CA list as a Set of String Fornisce la lista delle CA
     * riconosciute sotto forma di Set di stringhe
     * 
     * @return the list of CA
     */
    public Set getCANames() {
        return authorities.keySet();
    }

    /**
     * Returns a Collection of CA Fornisce una Collection delle CA riconosciute
     * 
     * @return Collection of CA
     */
    public Collection getCA() {
        return authorities.values();
    }

    /**
     * Return the CA certificate specified as caName
     * 
     * Restituisce il certificato della CA specificata da <CODE>caName</CODE>
     * se presente nelle CA di root.
     * 
     * @param caName
     *            Principal DN of CA
     * @return certificate CA X.509 , null if CA is not present
     * @throws GeneralSecurityException
     */
    public X509Certificate getCACertificate(Principal caName)
            throws GeneralSecurityException {

        if (authorities.containsKey(caName)) {
            return (X509Certificate) authorities.get(caName);
        } else {
            String errMsg = "CA non presente tra le root: " + caName;
            setMessage(errMsg);
            throw new GeneralSecurityException(errMsg);

        }
    }

    /**
     * Return the CA certificate specified as caName
     * 
     * Restituisce il certificato della CA specificata da <CODE>caName</CODE>
     * se presente nelle CA di root.
     * 
     * @param caName
     *            String DN of CA
     * @return certificate CA X.509 , null if CA is not present
     * @throws GeneralSecurityException
     */

    public X509Certificate getCACertificate(String caName)
            throws GeneralSecurityException {
        Set s = authorities.keySet();
        Iterator it = s.iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if ((o.toString()).equals(caName)) {
                return (X509Certificate) authorities.get((Principal) o);
            }
        }
        return null;
    }

    /**
     * Verifies the the given certificate is issued by a CA Verifica se il
     * certificato e' stato emesso da una delle CA riconosciute
     * 
     * @param userCert
     *            certificate to verify
     * @return true if the given certificate is issued by a CA, false otherwise
     */
    public boolean isAccepted(X509Certificate userCert) {
        try {
            return authorities.containsKey((userCert).getIssuerX500Principal());
        } catch (Exception e) {
            log.info("isAccepted: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verifies that this certificate was signed using the private key that
     * corresponds to the public key of an accepted CA at the current date.
     * 
     * 
     * Verifica l'autenticita' del certificato alla data corrente.<br>
     * A differenza del metodo verify che ha come parametro signatureInfo, in
     * questo caso la verifica si ferma al primo step che fallisce: la
     * descrizione dell'errore si ricava con il metodo getMessage
     * 
     * @param userCert
     *            certficate to verify
     * @throws GeneralSecurityException
     * @return true certificate is OK
     */
    public boolean verify(X509Certificate userCert)
            throws GeneralSecurityException {
        return verify(userCert, new Date());
    }

    /**
     * Verifies that this certificate was signed using the private key that
     * corresponds to the public key of an accepted CA at the given date.
     * 
     * 
     * @param userCert
     *            certficate to verify
     * @param date
     *            Date the given date
     * @throws GeneralSecurityException
     * @return true certificate is OK
     */
    public boolean verify(X509Certificate userCert, Date date)
            throws GeneralSecurityException {
        String errMsg = "";
        if (!isAccepted(userCert)) {
        	errMsg = "Certificato non emesso da una CA accettata";
        	setMessage(errMsg);
            log.info(errMsg);
            return false;
        }

        try {
            // verifica temporale

            userCert.checkValidity(date);
            log.info((userCert.getSubjectDN()) + " valido fino al "
                    + userCert.getNotAfter());
        } catch (CertificateExpiredException e) {
        	errMsg = "Certificato scaduto il " + userCert.getNotAfter();
        	setMessage(errMsg);
            log.info(errMsg);
            return false;
        } catch (CertificateNotYetValidException e) {
        	errMsg = "Certificato valido dal " + userCert.getNotBefore();
        	setMessage(errMsg);
            log.info(errMsg);
            return false;
        } catch (CertificateException e) {
            errMsg = "Formato del certificato non valido: " + e.getMessage();
            setMessage(errMsg);
            log.info(errMsg);
            throw new GeneralSecurityException(errMsg);
        }
        try {
            // verifica di firma
            X509Certificate caCert = (X509Certificate) authorities.get(userCert
                    .getIssuerDN());
            userCert.verify(caCert.getPublicKey());
            log.info("Verifica validita' con il certificato di CA OK");
            return true;
        } catch (GeneralSecurityException gse) {
        	log.info(gse.toString());
        	errMsg = "Verifica di firma del certificato: "
                + gse.getClass().getName() + " " + gse.getMessage();
        	setMessage(errMsg);
        	log.info(errMsg);
            return false;
        }
    }

    /**
     * ****************** CRL VERIFY METHODS
     * *************************************
     */

    /**
     * Set CRL control and update mode. If flag is set to true, CRL is
     * downloaded at each verification.
     * 
     * Imposta la modalita' di controllo ed aggiornamento delle CRL. Se il flag
     * viene impostato a true la CRL viene scaricata ad ogni operazione di
     * verifica. <br>
     * Nel caso di verifica di un file firmato, la CRL viene scaricata una sola
     * volta anche se sono piu' certificati della stessa CA
     * 
     * @param b
     *            if true, CRL is downloaded at each verification.
     */
    public void setAlwaysCRLUpdate(boolean b) {
        alwaysCrlUpdate = b;
    }

    /**
     * Return the possible error message of the last CRL verification
     * Restituisce l'eventuale messaggio di errore relativo all'ultima
     * operazione di verifica effettuata
     * 
     * @return description of the last CRL verification error
     */
    public String getMessage() {
        return message;
    }

    /**
     * Set the possible error message Memorizza la descrizione dell'ultimo
     * errore registrato durante la verifica
     * 
     * @param message
     *            description of the last CRL verification error
     */
    protected void setMessage(String message) {
        this.message = message;
    }

    /**
     * Update CRL of specified CA Aggiorna la CRL relativa alla CA in oggetto
     * 
     * @param caName
     *            DN of CA
     */
    public void updateCRL(Principal caName) {
        // non ancora ....
        // if (crls == null) crls = new X509CRLs(this);
    }

    /**
     * Save certificates in authorities Salva i certificati in authorities
     * 
     * @throws Exception
     */
    public void save() throws Exception {
        try {
            BufferedInputStream origin = null;
            File dir1 = new File(".");
            String curDir = dir1.getCanonicalPath();
            // zip contenente le CA
            String CAfilePath =
            // System.getProperty("user.home")
            curDir + System.getProperty("file.separator") + "conf"
                    + System.getProperty("file.separator") + "cacerts_sv.zip";

            FileOutputStream dest = new FileOutputStream(CAfilePath);
            ZipOutputStream out = new ZipOutputStream(new BufferedOutputStream(
                    dest));
            // out.setMethod(ZipOutputStream.DEFLATED);
            byte data[] = new byte[4096];
            // get a list of files from current directory
            Collection c = authorities.values();
            Iterator it = c.iterator();
            X509Certificate cert = null;
            while (it.hasNext()) {
                cert = (X509Certificate) it.next();
                // log.info("Adding: " + cert.getIssuerDN());
                ByteArrayInputStream bais = new ByteArrayInputStream(cert
                        .getEncoded());

                origin = new BufferedInputStream(bais, 4096);
                String s = toCNNames("" + cert.getIssuerDN());
                ZipEntry entry = new ZipEntry(s + ".der");
                out.putNextEntry(entry);
                int count;
                while ((count = origin.read(data, 0, 4096)) != -1) {
                    out.write(data, 0, count);
                }
                origin.close();
            }
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e);
        }

    }

    /**
     * Convert DN to CN
     * 
     * @param DN
     *            String
     * @return String
     */
    private String toCNNames(String DN) {

        int offset = DN.indexOf("CN=");
        int end = DN.indexOf(",", offset);
        String CN;
        if (end != -1) {
            CN = DN.substring(offset + 3, end);
        } else {
            CN = DN.substring(offset + 3, DN.length());
        }
        CN = CN.substring(0, CN.length());
        return CN;

    }

    /**
     * Add the specified CA certificate to CA list: certificate can be coded
     * base64 or DER.
     * 
     * Aggiunge alla lista delle CA riconosciute la CA specificata dal
     * certificato cert il certificato pu� essere in base64 o in formato DER
     * 
     * @param cert
     *            CA certificate
     * @throws GeneralSecurityException
     *             if any error occurs during certificate parsing or if
     *             certificate is not issued by a valid CA
     */
    public void addCertificateAuthority(byte[] cert)
            throws GeneralSecurityException {
        X509Certificate caCert = null;
        Security.removeProvider("BC");
        try { // Estrazione certificato da sequenza byte
            caCert = (X509Certificate) readCert(cert);

            log.finest("Verifico " + caCert.getSubjectDN());
            if (authorities.containsKey((caCert.getIssuerDN()))) {
            	log.finest(caCert.getIssuerDN().getName()
                        + " gia' inserito nella lista delle CA");
                return;
            }

            int ext = caCert.getBasicConstraints();
            if (ext == -1) {
                throw new CertificateException(caCert.getSubjectDN().getName()
                        + ": flag CA uguale a false");
            }
            
            try {
                caCert.checkValidity();
            } catch (CertificateExpiredException cee) {
                throw new CertificateException(caCert.getSubjectDN().getName()
                        + ": certificato CA scaduto");
            }
            catch (CertificateNotYetValidException cnyve) {
                throw new CertificateException(caCert.getSubjectDN().getName()
                        + ": certificato CA non ancora valido");
            }
                
                
            if (caCert.getIssuerDN().equals(caCert.getSubjectDN())) {
                caCert.verify(caCert.getPublicKey());
                authorities.put((caCert.getIssuerX500Principal()), caCert);
                log.finest("Inserita CA: " + caCert.getIssuerDN());
            } else {
                throw new CertificateException(caCert.getSubjectDN().getName()
                        + ": non self-signed");
            }
        } catch (GeneralSecurityException ge) {
        	log.finest(ge.toString());
            //trace(ge);
            throw ge;
        }
    }

    /**
     * Add the specified CA certificate to CA list.
     * 
     * Aggiunge alla lista delle CA riconosciute la CA specificata dal
     * certificato cert il certificato pu� essere in base64 o in formato DER
     * 
     * @param cert
     *            CA certificate
     * @throws GeneralSecurityException
     *             if any error occurs during certificate parsing or if
     *             certificate is not issued by a valid CA
     * 
     */
    public void addCertificateAuthority(X509Certificate cert)
            throws GeneralSecurityException {
        X509Certificate caCert = cert;
        Security.removeProvider("BC");
        try {

        	log.finest("Verifico " + caCert.getSubjectDN());
            if (authorities.containsKey((caCert.getIssuerDN()))) {
            	log.finest(caCert.getIssuerDN().getName()
                        + " gia' inserito nella lista delle CA");
                return;
            }

            int ext = caCert.getBasicConstraints();
            if (ext == -1) {
                throw new CertificateException(caCert.getSubjectDN().getName()
                        + ": flag CA uguale a false");
            }

            if (caCert.getIssuerDN().equals(caCert.getSubjectDN())) {
                caCert.verify(caCert.getPublicKey());
                authorities.put((caCert.getIssuerX500Principal()), caCert);
                log.finest("Inserita CA: " + caCert.getIssuerDN());
            } else {
                throw new CertificateException(caCert.getSubjectDN().getName()
                        + ": non self-signed");
            }
        } catch (GeneralSecurityException ge) {
            log.severe(ge.toString());
            throw ge;
        }

    }

    /**
     * 
     * Reads and generates certificate from a sequence of bytes in DER or base64
     * 
     * Legge un certificato Certificate da una sequenza di bytes in DER o base64
     * e genera il certificato
     * 
     * @param certByte
     *            sequence of bytes
     * @throws GeneralSecurityException
     *             if any error occurs during certificate parsing
     * @return Certificate
     */
    public static Certificate readCert(byte[] certByte)
            throws GeneralSecurityException {
        Certificate cert = null;
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(certByte);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            while (bis.available() > 0) {
                cert = cf.generateCertificate(bis);
            }
        } catch (GeneralSecurityException ge) {
            // trace(ge);
            throw ge;
        }

        return cert;
    }

    
    //ROB modificato, il metodo originale troncava 
    /**
     * Returns a bytearray of the file at the given path fileName
     * 
     * Restituisce un array di byte corrispondenti al file nella posizione
     * fileName
     * 
     * @param fileName
     *            Path del file
     * @throws IOException
     *             if any error occurs while reading file
     * @return byte[]
     */
    public byte[] getBytesFromPath(String fileName) throws IOException {

        Certificate cert = null;
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

    /**
     * Remove the specified CA from the list of CA
     * 
     * Rimuove dalla lista delle CA riconosciute la CA specificata da caName
     * 
     * @param caName
     *            DN of thr CA to remove
     */
    public void removeCertificateAuthority(Principal caName) {
        try {
            authorities.remove((caName));
        } catch (Exception ce) {
            log.severe(ce.toString());
            throw new IllegalArgumentException("DN non valido: "
                    + caName.getName());
        }
    }

    /**
     * Activate or discactivate debug messages
     * 
     * Attiva o disattiva i messaggi di debug
     * 
     * @param debug
     *            if true, it shows debug messages
     */
    public void setDebug(boolean debug) {
        this.debug = debug;
    }

}
