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
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/examples/CMSServlet.java,v 1.8 2014/08/13 12:41:49 resoli Exp $
 * $Revision: 1.8 $
 * $Date: 2014/08/13 12:41:49 $
 */
package it.trento.comune.j4sign.examples;

import it.trento.comune.j4sign.cms.ExternalSignatureCMSSignedDataGenerator;
import it.trento.comune.j4sign.cms.ExternalSignatureSignerInfoGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSetParser;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @deprecated This is old code not more maintained; see the <code>SigneServlet</code> 
 * inside the <b>firma-digitale</b> web application for replacement.<br/>
 * <br/>
 * <code>CMSServlet</code> is the server side part of the j4sign usage example
 * in a web environment.<br>
 * <code>CMSServlet</code> is a <code>HttpServlet</code> that takes care of
 * generating and sending to the web client the content to sign and the
 * corresponding bytes to digest and encrypt. After receiving the signature and
 * the signer certificate, it encapsulates them, along with the signed content,
 * in a CMS signed data message.<br>
 * <p>
 * The entire example, with the
 * {@link it.trento.comune.j4sign.examples.SimpleSignApplet} counterpart, is
 * designed to permit the use of the standard JDK tools. The applet can be
 * executed with applet viewer tool (no HttpSession in the servlet, nor HTML
 * forms on the client side are used).<br>
 * <p>
 * N.B.: IN A REAL WORLD WEB APPLICATION SCENARIO, YOU CAN (AND SHOULD) TAKE
 * ADVANTAGE OF THE FULL SERVLET API.
 * <p>
 * Here are the <code>CMSServlet</code> operations in detail:
 * <ol>
 * <li>Upon a GET request from the client specifiying a <code>retrieve</code>
 * parameter with value <code>DATA</code>:<br>
 * Generates and sends as HTTP response, the message to sign (a simple text),
 * base64 encoded;</li>
 * <li>Upon a GET request from the client specifiying a <code>retrieve</code>
 * parameter with value <code>ENCODED_AUTHENTICATED_ATTRIBUTES</code>:<br>
 * Builds an {@link ExternalSignatureSignerInfoGenerator} object, using the
 * message to sign, and specifying MD5 with RSA encryption as signature
 * algoritm;<br>
 * Uses this object to calculate <code>bytesToSign</code>, the bytes to digest
 * and encrypt (ASN.1 Authenticated attributes);<br>
 * Stores the <code>ExternalSignatureSignerInfoGenerator</code>, and a textual
 * dump of authenticates attributes,<br>
 * using the md5 digest of <code>bytesToSign</code> as a key.<br>
 * Sends the base64 encoding of <code>bytesToSign</code> as HTTP response.<br>
 * </li>
 * <li>Upon a GET request from the client specifiying a <code>retrieve</code>
 * parameter with value <code>AUTHENTICATED_ATTRIBUTES_PRINTOUT</code> and a
 * <code>encodedHash</code> parameter with base64 encoded value:<br>
 * Retrieves using <code>encodedHash</code> as a key the textual dump of
 * Authenticates attributes, and sends it as HTTP responses.<br>
 * </li>
 * <li>Upon a POST request from the client specifiying a <code>signature</code>
 * parameter and a <code>certificate</code> parameter, both with base64 encoded
 * values:<br>
 * Decodes <code>signature</code> and <code>certificate</code>;<br>
 * Extracts from <code>certificate</code> the public key of the signer, and uses
 * it to decrypt, using RSA algorithm, the <code>signature</code>.<br>
 * Uses the decrypted value as a key to retrieve the
 * <code>ExternalSignatureSignerInfoGenerator</code>. If such an object is
 * found, the signature is verified.<br>
 * The <code>ExternalSignatureSignerInfoGenerator</code>, completed with
 * <code>signature</code> and <code>certificate</code> informations, is passed
 * to a
 * {@link it.trento.comune.j4sign.cms.ExternalSignatureCMSSignedDataGenerator}
 * for creating the CMS message.<br>
 * The CMS message is then stored on the server file system.<br>
 * Finally, a textual status message is returned as HTTP response.</li>
 * 
 * @author Roberto Resoli
 */
public class CMSServlet extends HttpServlet {

	/**
	 * <code>DATA</code> is the sample data contet to be signed; it's a text
	 * shortly explaining what is going to happen.
	 */
	private final static String DATA = "This text has been retrieved from cmsservlet via http GET.\n"
			+ "The non-repudiation certificate extracted from your SmartCard has been sent\n"
			+ "to cmsservlet with the same request.\n"
			+ "The applet has also retrived from the cmsservlet the so called 'authenticated attributes',\n"
			+ "a set of data comprising:\n"
			+ "\t- The SHA-256 digest of this text.\n"
			+ "\t- The ASN.1 ContentType of this text (pkcs7.data).\n"
			+ "\t- A timestamp, taken from the server clock.\n"
			+ "\t- A univoque reference to your non-repudiation certificate.\n"
			+ "When you will type the pin, and press return, the following will happen:\n"
			+ "The 'authenticated attributes', hashed with SHA-256, will be sent\n"
			+ "to the Smart Card and there encrypted using your private key.\n"
			+ "The encrypted hashing of 'authenticated attributes' are then sent to cmsservlet via http POST.\n"
			+ "Finally, cmsservlet builds the CMS (PKCS7) object and saves it\n"
			+ "on the server filesystem, if the signature is verified.";

	/**
	 * Class encapsulating a SignerInfoGenerator-related informations to be
	 * stored after a signature request.
	 * 
	 * @author Roberto Resoli
	 */
	private class SignerInfoGeneratorItem {
		private String attrPrintout = null;

		private ExternalSignatureSignerInfoGenerator sig = null;

		/**
		 * Constructor.
		 * 
		 * @param aSig
		 *            the {@link ExternalSignatureSignerInfoGenerator}
		 * @param aPrintOut
		 *            the authenticated attributes textual dump at the time of
		 *            the request.
		 */
		public SignerInfoGeneratorItem(
				ExternalSignatureSignerInfoGenerator aSig, String aPrintOut) {
			sig = aSig;
			attrPrintout = aPrintOut;
		}

		/**
		 * The attributes printout getter.
		 * 
		 * @return the authenticated attributes textual dump at the time of the
		 *         request.
		 */
		public String getAttrPrintout() {
			return attrPrintout;
		}

		/**
		 * The ExternalSignatureSignerInfoGenerator getter.
		 * 
		 * @return the ExternalSignatureSignerInfoGenerator for encapsulating
		 *         signer informations.
		 */
		public ExternalSignatureSignerInfoGenerator getSig() {
			return sig;
		}
	}

	/**
	 * The repository for {@link SignerInfoGeneratorItem} objects. Stores
	 * SignerInfoGenerator-related informations between HTTP requests.
	 * 
	 */
	private Hashtable signerInfoGeneratorTable = new Hashtable();

	/**
	 * Implementation of the GET method; returns informations to the client and
	 * stores SignerInfoGenerator-related informations; see {@link CMSServlet}
	 * for details.
	 * 
	 * @see CMSServlet
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		System.out
				.println("==================== DO GET METHOD START=========================");

		PrintWriter out = response.getWriter();

		String retrieve = (String) request.getParameter("retrieve");
		if (retrieve != null) {
			System.out.println("Retrieving: " + retrieve);
			if (retrieve.equals("DATA"))
				out.print(DATA);
			else if (retrieve.equals("ENCODED_AUTHENTICATED_ATTRIBUTES")) {
				ExternalSignatureSignerInfoGenerator gen = buildSignerInfoGenerator();

				// Patch from Alessandro (thanks!)
				// Decode and set certificate
				sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
				byte[] certificate = decoder.decodeBuffer(request
						.getParameter("certificate"));
				java.security.cert.CertificateFactory cf;
				try {
					cf = java.security.cert.CertificateFactory
							.getInstance("X.509");
					java.io.ByteArrayInputStream bais1 = new java.io.ByteArrayInputStream(
							certificate);
					java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
							.generateCertificate(bais1);

					gen.setCertificate(javaCert);

				} catch (CertificateException e1) {
					e1.printStackTrace();
				}
				// s.setAttribute("signerInfo", infoGen);

				byte[] bytesToSign = getAuthenticatedAttributesBytes(gen);
				String attrPrintout = getAuthenticatedAttributesPrintout(bytesToSign);
				System.out
						.println("Authenticated Attributes printout follows:\n"
								+ attrPrintout);

				byte[] digestBytes = null;
				// calculate digest
				java.security.MessageDigest md;
				try {
					md = java.security.MessageDigest
							.getInstance(CMSSignedDataGenerator.DIGEST_SHA256);
					md.update(bytesToSign);
					digestBytes = md.digest();

				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					System.out.println(e);
				}

				System.out.println("Encapsulating digest in digestInfo ...");
				byte[] digestInfoBytes = encapsulateInDigestInfo(
						CMSSignedDataGenerator.DIGEST_SHA256, digestBytes);
				System.out.println(formatAsString(digestInfoBytes, " "));

				String storeKey = formatAsString(digestInfoBytes, "");
				System.out.println("Saving SignerInfoGenerator with key: "
						+ storeKey);
				System.out.println("The key is the string representation of digestInfo!");

				SignerInfoGeneratorItem s = new SignerInfoGeneratorItem(gen,
						attrPrintout);
				// save generator and printout
				this.signerInfoGeneratorTable.put(storeKey, s);

				System.out.println("Returning digestInfo to  client ...");
				out.print(base64Encode(digestInfoBytes));

			} else if (retrieve.equals("AUTHENTICATED_ATTRIBUTES_PRINTOUT")) {
				String base64Hash = (String) request
						.getParameter("encodedhash");
				if (base64Hash != null) {
					sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
					byte[] hash = decoder.decodeBuffer(base64Hash);

					SignerInfoGeneratorItem s = (SignerInfoGeneratorItem) this.signerInfoGeneratorTable
							.get(formatAsString(hash, ""));

					out.print(s.getAttrPrintout());
				}
			} else
				out.println("Error: value '" + retrieve
						+ "' for required parameter 'retrive' not expected.");
		} else
			out.println("Error: required parameter 'retrive' not found.");
		out.flush();
		System.out
				.println("==================== DO GET METHOD END=========================");
	}

	/**
	 * Implementation of the POST method; builds the CMS message; see
	 * {@link CMSServlet} for details.
	 * 
	 * @see CMSServlet
	 */
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		System.out
				.println("==================== DO POST METHOD START =========================");

		String base64Certificate = (String) request.getParameter("certificate");
		String base64Signature = (String) request.getParameter("signature");

		PrintWriter out = response.getWriter();
		if ((base64Certificate != null) && (base64Signature != null)) {
			sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
			byte[] sigBytes = decoder.decodeBuffer(base64Signature);
			byte[] certBytes = decoder.decodeBuffer(base64Certificate);

			String storeKey = deriveStoreKey(sigBytes, certBytes);
			ExternalSignatureSignerInfoGenerator info = retriveSignerInfoGenerator(storeKey);

			if (info != null) {
				CMSSignedData signedData = buildCMSSignedData(info, sigBytes,
						certBytes);
				out.print("OK-SignedData built -");
				if (signedData != null) {
					String filePath = System.getProperty("java.io.tmpdir")
							+ System.getProperty("file.separator") + storeKey
							+ ".txt.p7m";
					saveFile(signedData, filePath);
					out.print(" saved to file: '" + filePath + "'");
				} else
					out.print("signedData not verified, file NOT saved!");

			}
		} else
			out.print("ERROR-certificate or signature not available.");
		out.flush();
		System.out
				.println("==================== DO POST METHOD END =========================");
	}

	/**
	 * DER decoding function for digest info data.
	 * 
	 * @param encoding
	 *            der encoded bytes
	 * @return the digest as byte[].
	 * @throws IOException
	 *             if encoding is not a DigestInfo
	 */
	
	/*
	private byte[] derDecode(byte[] encoding) throws IOException {
		if (encoding[0] != (DERTags.CONSTRUCTED | DERTags.SEQUENCE)) {
			throw new IOException("not a digest info object");
		}

		ASN1StreamParser a1p = new ASN1StreamParser(encoding);

		return new DigestInfo((ASN1Sequence) a1p.readObject()).getDigest();
	}
	*/
	
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
	public String formatAsString(byte[] bytes, String byteSeparator) {
		int n, x;
		String w = new String();
		String s = new String();

		for (n = 0; n < bytes.length; n++) {
			x = (int) (0x000000FF & bytes[n]);
			w = Integer.toHexString(x).toUpperCase();
			if (w.length() == 1)
				w = "0" + w;
			s = s + w + ((n + 1 == bytes.length) ? "" : byteSeparator);
		} // for
		return s;
	}

	/**
	 * Converts the provided <code>certBytes</code> in a
	 * <code>java.security.cert.X509Certificate</code>, gets from it the signer
	 * public key, and uses it to decrypt <code>sigBytes</code>. The decryption
	 * result is returned as a formatted exadecimal string; see
	 * {@link CMSServlet} for details.
	 * 
	 * @param sigBytes
	 *            signature bytes
	 * @param certBytes
	 *            certificate bytes
	 * @return the decryption of sigBytes using the RSA/ECB/PKCS1PADDING
	 *         Algorithm.
	 */
	private String deriveStoreKey(byte[] sigBytes, byte[] certBytes) {
		String key = null;
		java.security.cert.CertificateFactory cf;
		try {
			cf = java.security.cert.CertificateFactory.getInstance("X.509");
			java.io.ByteArrayInputStream bais1 = new java.io.ByteArrayInputStream(
					certBytes);

			java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
					.generateCertificate(bais1);

			PublicKey pubKey = javaCert.getPublicKey();

			try {
				System.out
						.println("Deriving store key from signature and certificate.");
				System.out
						.println("N.B.:This serves also as signature verification!");

				Cipher c = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "BC");

				c.init(Cipher.DECRYPT_MODE, pubKey);

				byte[] decBytes = null;

				/*
				if (false)
					decBytes = derDecode(c.doFinal(sigBytes));
				else
				*/
				
				decBytes = c.doFinal(sigBytes);

				key = formatAsString(decBytes, "");

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
			}catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return key;
	}

	/**
	 * Gets the <code>ExternalSignatureSignerInfoGenerator</code> generator
	 * which originally produced the given <code>storeKey</code>.
	 * 
	 * @param storeKey
	 * @return the {@link ExternalSignatureSignerInfoGenerator} associated with
	 *         the<code>storeKey</code>
	 */
	private ExternalSignatureSignerInfoGenerator retriveSignerInfoGenerator(
			String storeKey) {

		System.out.println("Retrieving signerInfoGenerator using key: "
				+ storeKey);

		ExternalSignatureSignerInfoGenerator info = ((SignerInfoGeneratorItem) this.signerInfoGeneratorTable
				.get(storeKey)).getSig();

		if (info != null)
			System.out.println("Generator found. Signature is verified.");
		else
			System.out
					.println("Generator not found! Signature is NOT verified!");
		// remove infos from store
		this.signerInfoGeneratorTable.remove(storeKey);

		return info;
	}

	/**
	 * Builds the CMS signed data message.
	 * 
	 * @param infoGen
	 *            the {@link ExternalSignatureSignerInfoGenerator} wrapping
	 *            signer informations
	 * @param sigBytes
	 *            the digest encrypted with signer private key.
	 * @param certBytes
	 *            the signer certificate.
	 * @return the {@link CMSSignedData} message.
	 */
	private CMSSignedData buildCMSSignedData(
			ExternalSignatureSignerInfoGenerator infoGen, byte[] sigBytes,
			byte[] certBytes) {

		CMSSignedData result = null;

		System.out.println("building CMSSignedData.");
		CMSProcessable msg = new CMSProcessableByteArray(DATA.getBytes());

		// questa versione del generatore è priva della classe interna per
		// la generazione delle SignerInfo, che è stata promossa a classe a
		// sè.
		ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();

		// Conterrà la lista dei certificati; come minimo dovrà
		// contenere i certificati dei firmatari; opzionale, ma
		// consigliabile,
		// l'aggiunta dei certificati root per completare le catene di
		// certificazione.
		ArrayList certList = new ArrayList();

		// get Certificate
		java.security.cert.CertificateFactory cf;
		try {
			cf = java.security.cert.CertificateFactory.getInstance("X.509");

			java.io.ByteArrayInputStream bais1 = new java.io.ByteArrayInputStream(
					certBytes);

			java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate) cf
					.generateCertificate(bais1);

			infoGen.setCertificate(javaCert);
			infoGen.setSignedBytes(sigBytes);

			certList.add(javaCert);

			gen.addSignerInf(infoGen);

			if (certList.size() != 0) {

				// Per passare i certificati al generatore li si incapsula in un
				// CertStore.
				CertStore store;

				store = CertStore.getInstance("Collection",
						new CollectionCertStoreParameters(certList), "BC");

				System.out.println("Adding certificates ... ");

				gen.addCertificatesAndCRLs(store);

				// Finalmente, si può creare il l'oggetto CMS.
				System.out.println("Generating CMSSignedData ");
				result = gen.generate(msg, true);

			}
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (CertStoreException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		} catch (CMSException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		return result;
	}

	/**
	 * Saves a CMS signed data file on the server file system; the extension
	 * should be ".p7m" according to italian rules.
	 * 
	 * @param s
	 *            the {@link CMSSignedData} object to save.
	 * @param filePath
	 *            full path of the file.
	 * @return true if the file was correctly saved, false otherwise.
	 */
	private boolean saveFile(CMSSignedData s, String filePath) {
		try {
			System.out.println("\nSAVING FILE TO: " + filePath);

			FileOutputStream fos = new FileOutputStream(filePath);
			fos.write(s.getEncoded());
			fos.flush();
			fos.close();

			return true;
		} catch (IOException e3) {
			System.out.println("IO Error: " + e3);
			return false;
		}
	}

	/**
	 * Creates a {@link ExternalSignatureSignerInfoGenerator} with a
	 * <code>MD5</code> digest algorithm and <code>RSA</code> encryption
	 * algorithm.
	 * 
	 * @return the <code>ExternalSignatureSignerInfoGenerator</code> object
	 */
	private ExternalSignatureSignerInfoGenerator buildSignerInfoGenerator() {
		System.out.println("Building SignerInfoGenerator.");

		ExternalSignatureSignerInfoGenerator gen = new ExternalSignatureSignerInfoGenerator(
				CMSSignedDataGenerator.DIGEST_SHA256,
				CMSSignedDataGenerator.ENCRYPTION_RSA);
		return gen;

	}

	/**
	 * A BASE64 encoding function, using the <code>sun.misc.BASE64Encoder</code>
	 * implementation.
	 * 
	 * @param bytes
	 *            the bytes to encode.
	 * @return the <code>BASE64</code> encoding of <code>bytes</code>.
	 */
	private String base64Encode(byte[] bytes) {
		sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
		return encoder.encode(bytes);
	}

	/**
	 * Uses the provided {@link ExternalSignatureSignerInfoGenerator} for
	 * calculating the authenticated attributes bytes to be digested-encrypted
	 * by the signer. Note that the attributes include a timestamp, so the
	 * result is time-dependent!
	 * 
	 * @param signerGenerator
	 *            the <code>ExternalSignatureSignerInfoGenerator</code> object
	 *            that does the job.
	 * @return the bytes to be signed.
	 */
	private byte[] getAuthenticatedAttributesBytes(
			ExternalSignatureSignerInfoGenerator signerGenerator) {

		System.out.println("Building AuthenticatedAttributes.");
		byte[] bytesToSign = null;
		try {
			CMSProcessable msg = new CMSProcessableByteArray(DATA.getBytes());
			bytesToSign = signerGenerator.getBytesToSign(
					PKCSObjectIdentifiers.data, msg, "BC");
		} catch (Exception e) {
			System.out.println(e);
		}
		return bytesToSign;
	}

	/**
	 * A text message resulting from a dump of provided authenticated attributes
	 * data. Shows, among other things, the embedded timestamp attribute.
	 * 
	 * @param bytes
	 *            the ASN.1 DER set of authenticated attributes.
	 * @return the attributes textual dump.
	 */
	private String getAuthenticatedAttributesPrintout(byte[] bytes) {
		StringWriter printout = new StringWriter();
		PrintWriter pw = new PrintWriter(printout);
		try {

			ASN1StreamParser a1p = new ASN1StreamParser(bytes);

			System.out.println("ASN1 parser built: " + a1p);

			DERSetParser signedAttributesParser = (DERSetParser) a1p
					.readObject();

			System.out.println("DERSetParser object read: "
					+ signedAttributesParser);

			ASN1Set set = ASN1Set.getInstance(signedAttributesParser
					.getDERObject());

			AttributeTable attr = new AttributeTable(set);

			System.out.println("Attribute table created: " + attr);

			Iterator iter = attr.toHashtable().values().iterator();

			pw.println("Listing authenticated attributes:");
			int count = 1;
			while (iter.hasNext()) {
				Attribute a = (Attribute) iter.next();

				pw.println("Attribute " + count + ":");
				if (a.getAttrType().getId()
						.equals(CMSAttributes.signingTime.getId())) {
					Time time = Time.getInstance(a.getAttrValues().getObjectAt(
							0));
					pw.println("Authenticated time (SERVER local time): "
							+ time.getDate());
				}
				if (a.getAttrType().getId()
						.equals(CMSAttributes.contentType.getId())) {
					if (CMSObjectIdentifiers.data.getId().equals(
							DERObjectIdentifier.getInstance(
									a.getAttrValues().getObjectAt(0)).getId()))
						pw.println("Content Type: PKCS7_DATA");
				}
				if (a.getAttrType().getId()
						.equals(CMSAttributes.messageDigest.getId())) {
					byte[] md = DEROctetString.getInstance(
							a.getAttrValues().getObjectAt(0)).getOctets();
					pw.println("Message Digest (SHA-256 hash of data content): "
							+ formatAsString(md, " "));
				}
				if (a.getAttrType().getId()
						.equals(PKCSObjectIdentifiers.id_aa_signingCertificateV2
								.getId())) {
					pw.println("Signing Certificate V2");
				}
				
				pw.println("\nAttribute dump follows:");
				pw.println(ASN1Dump.dumpAsString(a) + "\n");

				count++;
			}
		} catch (Exception e) {
			System.out.println(e);
			pw.println(e);
			return null;
		}
		pw.flush();

		return printout.toString();

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

	/**
	 * Adds BouncyCastle provider at servlet initialization time.
	 */
	public void init() throws ServletException {
		System.out.println("Insert BC provider...");
		Security.insertProviderAt(new BouncyCastleProvider(), 2);
	}
}