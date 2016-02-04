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
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/examples/CertTest.java,v 1.1 2004/12/27 11:14:32 resoli Exp $
 * $Revision: 1.1 $
 * $Date: 2004/12/27 11:14:32 $
 */
package it.trento.comune.j4sign.examples;


import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

import java.security.cert.CertificateException;
import java.util.Iterator;
import java.util.Set;


/**
 * A class for testing KeyUsage extension of X509 certificates.
 * According to italian law technical directives, a digital signature
 * has legal value if the certificate corresponding to the key used for sign
 * has a Key Usage Extension of "non repudiation" marked as critical. 
 * <p>
 * This class checks this condition against a given certificate.
 *  
 * 
 *  @author Roberto Resoli
 *
 */
public class CertTest {

    public static void main(String[] args) {
        if (args.length < 1) {
            return;
        }

        CertTest ct = new CertTest();

        try {
            byte[] bytes = ct.readCertFromFile(args[0]);
            ct.printCert(bytes);
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    public byte[] readCertFromFile(String filePath) throws IOException {

        System.out.println("reading Cert from file: " + filePath);

        FileInputStream fis = new FileInputStream(filePath);

        byte[] buffer = new byte[1024];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int bytesRead = 0;
        while ((bytesRead = fis.read(buffer, 0, buffer.length)) >= 0) {
            baos.write(buffer, 0, bytesRead);
        }
        fis.close();
        System.out.println("FINISHED\n");
        return baos.toByteArray();
    }

    public void printCert(byte[] certBytes) throws CertificateException {

        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
                .getInstance("X.509");

        //java.io.ByteArrayInputStream bais1 = new
        // java.io.ByteArrayInputStream(
        //        signAgent.getDerEncodedCertificate_());

        java.io.ByteArrayInputStream bais1 = new java.io.ByteArrayInputStream(
                certBytes);

        java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
                .generateCertificate(bais1);

        /*
         * java.security.cert.CertificateFactory cfbouncy = null; try {
         * Security.addProvider(new BouncyCastleProvider()); cfbouncy =
         * java.security.cert.CertificateFactory .getInstance("X.509","BC"); }
         * catch (CertificateException e) { // TODO Auto-generated catch block
         * e.printStackTrace(); } catch (NoSuchProviderException e) { // TODO
         * Auto-generated catch block e.printStackTrace(); }
         * X509CertificateObject co = (X509CertificateObject)
         * cfbouncy.generateCertificate(bais1);
         */

        Set criticalOIDS = javaCert.getCriticalExtensionOIDs();
        System.out.println("KeyUsage is "
                + (criticalOIDS.contains("2.5.29.15") ? "CRITICAL"
                        : "NOT CRITICAL"));
        printKeyUsage(javaCert.getKeyUsage());

        System.out.println("Checking critical non repudiation: "
                + (isKeyUsageNonRepudiationCritical(javaCert) ? "OK" : "NOT OK"));

        System.out.println("=== Critical OIDS: ===");

        Iterator iter = criticalOIDS.iterator();
        String oid = null;
        byte[] value = null;
        while (iter.hasNext()) {
            oid = (String) iter.next();
            value = javaCert.getExtensionValue(oid);

            System.out.println(oid + ":" + formatAsHexString(value));

        }

        System.out.println("=== Inizio Certificato ===");
        System.out.println(javaCert);
        System.out.println("=== Fine Certificato ===");

    }

    void printKeyUsage(boolean[] flags) {

        if (flags == null)
            System.out.println("No key usage extension.");
        else
            System.out.print("Key usages: ");

        if (flags[0])
            System.out.print("digitalSignature ");
        if (flags[1])
            System.out.print("nonRepudiation ");
        if (flags[2])
            System.out.print("keyEncipherment ");
        if (flags[3])
            System.out.print("keyAgreement ");
        if (flags[4])
            System.out.print("keyCertSign ");
        if (flags[5])
            System.out.print("cRLSign ");
        if (flags[6])
            System.out.print("encipherOnly ");
        if (flags[7])
            System.out.print("decipherOnly ");
        
        System.out.println();

    }

    boolean isKeyUsageNonRepudiationCritical(
            java.security.cert.X509Certificate javaCert) {

        boolean isNonRepudiationPresent = false;
        boolean isKeyUsageCritical = false;

        Set oids = javaCert.getCriticalExtensionOIDs();
        if (oids != null)
            // check presence between critical extensions of oid:2.5.29.15
            // (KeyUsage)
            isKeyUsageCritical = oids.contains("2.5.29.15");

        boolean[] keyUsages = javaCert.getKeyUsage();
        if (keyUsages != null)
            //check non repudiation (index 1)
            isNonRepudiationPresent = keyUsages[1];

        return (isKeyUsageCritical && isNonRepudiationPresent);

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
}