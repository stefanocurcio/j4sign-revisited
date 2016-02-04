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

import it.trento.comune.j4sign.verification.utils.CertUtils;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Properties;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;


/**
 * This class is constructed with a certificate X509Certificate c and  CertificationAuthorities C
 * <br>Checks the validity of the certificate.<br><br>
 *
 * Questa classe si costruisce con il certificato X509Certificate c e le CertificationAuthorities C
 * <br>Vengono effettuate tutte le verifiche necessarie per la validità del certificato
 *
 *
 * @author Francesco Cendron
 */
class CertValidity {
    //verifiche di validità di un certificato
	
	private Logger log = Logger.getLogger(this.getClass().getName());
	
    private boolean isPathValid; //se la CA del cert è presente

    private String CRLerror = "";
    private String certPathError = "";
    
    public String getCertPathError() {
		return certPathError;
	}

	private boolean isRevoked;
    private boolean isDownloadCRLForced; //download forzato CRL (dal frame FreesignerCertFrame)
    private boolean isExpired;
    private boolean isInUse; //contrario di NotYetValid


    private boolean isPassed;
    private X509Certificate cert;
    private CertificationAuthorities CAroot;
    private X509CertRL CRL;
    
	private boolean hasQCStatements = false;
	private boolean qcCompliance = false;

	private ArrayList<String> qcStatementsStrings = null;


    /**Constructor of the class.<br><br>
     * Costrutture della classe: si richama la this.
     *
     * @param c certificate
     * @param C CertificationAuthorities
     */
    public CertValidity(Properties conf, X509Certificate c, CertificationAuthorities C) {
        this(conf, c, C, false, null);

    }

    /**
     * Constructor of the class. It forces CRL download if flag isDownloadCRLForced
     * <br>is true. It is useful to avoid forcing CRL download (isDownloadCRLForced = false)
     * <br>when offline situations occurs. It is anyway necessary to complete
     * <br> certificate validity check by verifying CRL.
     *
     * <br><br> Methods is.... don't perform action, methos get.... do perform action.
     *
     *<br><br>
     * Costrutture della classe che forza il download della CRL nel
     * <br> caso il flag isDownloadCRLForced sia settato a true.
     * <br> E' utile non forzare il download della CRL (ponendo
     * isDownloadCRLForced = false)
     * <br> nei casi di mancanza di connessione alla rete. La verifica della
     * revoca del certificato
     * <br> � infatti comunque necessaria per la verifica della validit� del
     * certificato. N.B. I metodi is... a differenza dei get... non perfomano
     * l'azione ma restituiscono solo il valore
     *
     * @param c certificate4
     * @param C CertificationAuthorities
     * @param isDownloadCRLForced if true CRL download is forced
     */
    public CertValidity(Properties conf, X509Certificate c, CertificationAuthorities C,
                        boolean isDownloadCRLForced, File crlDir) {
        cert = c;
        CAroot = C;
        CRL = new X509CertRL(CAroot, crlDir);
        
        CRL.setUseproxy("true".equals(conf.getProperty("useProxy")), conf.getProperty("user"), conf
				.getProperty("password"), conf.getProperty("host"), conf.getProperty("port"));
        
        isPathValid = false;
        isRevoked = true;
        isExpired = false;
        isInUse = true;
        isPassed = false;
        this.isDownloadCRLForced = isDownloadCRLForced;

    }
    
    
    

    public X509CRL getCRL() {
		return CRL.getCRL(cert.getIssuerX500Principal());
	}

	/**
     * Checks certification path by IssuerX500Principal keyed in CAroot<br><br>
     *  Risale il certification path attraverso IssuerX500Principal chiave in CAroot
     *
     *   @return true: if certification path is valid
     *
     */

    public boolean getPathValid() {
        isPathValid = true;
        X509Certificate certChild = cert;
        X509Certificate certParent = null;
        while (!certChild.getIssuerDN().equals(
                certChild.
                getSubjectDN())) {
            //finche' la CA non è autofirmata

            try {
                certParent = CAroot.getCACertificate(
                        certChild.getIssuerX500Principal());
            } catch (GeneralSecurityException ex) {
                //la CA non è presente nella root
                isPathValid = false;
                certPathError = CAroot.getMessage();
                return isPathValid;
            }
            certChild = certParent;
        }

        return isPathValid;
    }

    /**
     * Checks if certificate is revoked<br><br>
     *  Verifica che il certificato non sia stato revocato.
     *
     * @return true: if certificate is revoked
     *
     *
     */
    public boolean getRevoked() {

            isRevoked = !CRL.isNotRevoked(cert, isDownloadCRLForced);

        return isRevoked;
    }

    public boolean isCRLChecked() {
        return true || isDownloadCRLForced;
    }

    /**
     *  Returns ReasonCode
     * CRLReason ::= ENUMERATED {
     unspecified(0), keyCompromise(1), cACompromise(2), affiliationChanged(3),
     superseded(4), cessationOfOperation(5), certificateHold(6), removeFromCRL(8)
     }
     * and possibly the date of revokation. see X509CertRL<br><br>
     *
     * @return String: reason code
     *
     *
     */
    public String getReasonCode() {
        return CRL.getReasonCode();
    }

    /**
     * Returns error message during CRL download. see X509CertRL
     * NB call this method always after getPassed(), that calls X509crl.isrevoked()<br><br>
     *
     *  Restituisce una stringa contenente un messaggio di errore nella fase
     * di verifica o download della CRL. vedi X509CertRL
     *
     * //chiamare questo metodo sempre dopo aver chiamata getpassed che chiama a sua volta
     *  //x509crl.isrevoked!
     *
     * @return String: error
     *
     *
     */


    public String getCRLerror() {

        return CRLerror;
    }

    /**
     * Return the general result<br><br>
     *  Restituisce il risultato di tutte le verifiche
     *
     * @return true: if certificate is valid
     *
     *
     */

    public boolean getPassed() {

        isPathValid = this.getPathValid();
        isExpired = this.getExpired();
        isInUse = this.getInUse();
        isRevoked = this.getRevoked();
        isPassed = isPathValid && !isRevoked && !isExpired && isInUse;
        log.info("************************Verifica: " +
                           cert.getSubjectDN() + "\n Risultato getPassed: " +
                           isPassed);
        CRLerror = CRL.getCRLerror();

        return isPassed;
    }
    
    public boolean getPassed_noExpiredCheck() {

        isPathValid = this.getPathValid();

        
        isRevoked = this.getRevoked();
        isPassed = isPathValid && !isRevoked;
        log.info("************************Verifica: " +
                           cert.getSubjectDN() + "\n Risultato getPassed: " +
                           isPassed + "\nNB:VERIFICA SCADENZA DISABILITATA!");
        CRLerror = CRL.getCRLerror();

        return isPassed;
    }

    /**Return true if certificate is expired<br><br>
     *  Restituisce true se il certificato � scaduto
     *

     *
     * @return true: if certificate is expired
     *
     *
     */

    public boolean getExpired() {
        try {
            cert.checkValidity();
            isInUse = true;
            isExpired = false;
        } catch (CertificateNotYetValidException ex) {
            isInUse = false;
        } catch (CertificateExpiredException ex) {
            isExpired = true;
        }

        return isExpired;
    }

    /**
     * Return true if the certificate is active<br><br>
     *  Restituisce true se il certificato � ancora attivo
     *

     *
     * @return true: if the certificate is active
     *
     *
     */
    public boolean getInUse() {
        try {
            cert.checkValidity();
            isInUse = true;
            isExpired = false;
        } catch (CertificateNotYetValidException ex) {
            isInUse = false;
        } catch (CertificateExpiredException ex) {
            isExpired = true;
        }

        return isInUse;
    }


    public boolean isPathValid() {

        return isPathValid;
    }

    public boolean isRevoked() {

        return isRevoked;
    }

    public boolean isPassed() {

        return isPassed;
    }

    public boolean isExpired() {

        return isExpired;
    }

    public boolean isInUse() {

        return isInUse;
    }

    public void setPathValid(boolean b) {
        isPathValid = b;
    }

    public void setRevoked(boolean b) {
        isRevoked = b;
    }

    public void setPassed(boolean b) {
        isPassed = b;
    }

    public void setExpired(boolean b) {
        isExpired = b;
    }

    public void setInUse(boolean b) {
        isInUse = b;
    }

    public void setisDownloadCRLForced(boolean b) {
        isDownloadCRLForced = b;
    }

	public boolean getHasQcStatements() {

		try {

			hasQCStatements = it.trento.comune.j4sign.verification.utils.CertUtils.QCStatements.hasQcStatement(cert);
			qcCompliance = false;

			qcStatementsStrings = null;

			if (hasQCStatements) {
				qcStatementsStrings = new ArrayList<String>();

				ASN1Sequence qcStatements = CertUtils.QCStatements
						.getQcStatements(cert);

				Enumeration<?> qcStatementEnum = qcStatements.getObjects();

				while (qcStatementEnum.hasMoreElements()) {
					QCStatement qc = QCStatement.getInstance(qcStatementEnum
							.nextElement());

					DERObjectIdentifier statementId = qc.getStatementId();

					if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance
							.getId().equals(statementId.getId())) {
						qcCompliance = true;
						qcStatementsStrings.add(statementId.getId()
								+ " (etsi_qcs_QcCompliance)");
					} else if (ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue
							.getId().equals(statementId.getId())) {
						String qcLimit = CertUtils.QCStatements
								.getQcStatementValueLimit(cert);

						qcStatementsStrings.add(statementId.getId()
								+ " (id_etsi_qcs_LimiteValue): " + qcLimit);
					} else if (ETSIQCObjectIdentifiers.id_etsi_qcs_RetentionPeriod
							.getId().equals(statementId.getId())) {

						String qcRetentionPeriod = DERInteger.getInstance(
								qc.getStatementInfo()).toString();
						qcStatementsStrings.add(statementId.getId()
								+ " (etsi_qcs_RetentionPeriod): "
								+ qcRetentionPeriod);
					} else if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD
							.getId().equals(statementId.getId())) {
						qcStatementsStrings.add(statementId.getId()
								+ " (etsi_qcs_QcSSCD)");
					} else
						qcStatementsStrings.add(statementId.getId()
								+ " (Unknown)");
				}
			}

		} catch (IOException e) {

			hasQCStatements = false;

		}

		return hasQCStatements;
	}

	public ArrayList<String> getQcStatementsStrings() {
		return qcStatementsStrings;
	}
}
