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
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/installer/Installer.java,v 1.6 2014/08/01 08:49:46 resoli Exp $
 * $Revision: 1.6 $
 * $Date: 2014/08/01 08:49:46 $
 */

package it.trento.comune.j4sign.installer;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.swing.JDialog;
import javax.swing.JOptionPane;

/**
 * @author resolir
 * 
 *         TODO To change the template for this generated type comment go to
 *         Window - Preferences - Java - Code Style - Code Templates
 */
public class Installer {

	private static final short OS_WINDOWS = 0;
	private static final short OS_LINUX = 1;
	private static final short OS_MAC = 2;
	private static final short OS_UNSUPPORTED = -1;

	private static final short ARCH_X86 = 0;
	private static final short ARCH_AMD64 = 1;

	protected short os;
	protected short arch;
	private String targetDir = null;

	private String osName = null;
	String osArch = null;

	public Installer() {

		this.osName = System.getProperty("os.name");
		this.osArch = System.getProperty("os.arch");

		if (osArch.contains("x86"))
			this.arch = ARCH_X86;
		else if (osArch.contains("amd64"))
			this.arch = ARCH_AMD64;

		if (osName.toLowerCase().indexOf("win") > -1) {
			this.os = OS_WINDOWS;
		} else if (osName.toLowerCase().indexOf("linux") > -1) {
			this.os = OS_LINUX;
		} else if (osName.toLowerCase().indexOf("mac") > -1) {
			this.os = OS_MAC;
		} else
			this.os = OS_UNSUPPORTED;

		String extDirs = System.getProperty("java.ext.dirs");
		String extDir = extDirs;
		if (extDirs != null) {
			int separatorIndex = -1;
			if ((os == OS_LINUX) && extDirs.contains(":"))
				separatorIndex = extDirs.indexOf(":");
			if ((os == OS_WINDOWS) && extDirs.contains(";"))
				separatorIndex = extDirs.indexOf(";");

			if (separatorIndex != -1) {
				extDir = extDirs.substring(separatorIndex + 1);

				
				showTwoThirdsOption( 
						"'"
								+ extDirs
								+ "'\n"
								+ "L'installazione delle librerie verrà effettuata nella seconda directory:\n'"
								+ extDir + "'","Rilevata più di una directory per le estensioni", JOptionPane.INFORMATION_MESSAGE);
				
				
			} else {

				showTwoThirdsOption("L'installazione delle librerie verrà effettuata nella directory:\n'"
								+ extDir + "'",
						"Rilevata una directory per le estensioni",
						JOptionPane.INFORMATION_MESSAGE);
			}

			File extDirAsFile = new File(extDir);
			if (!extDirAsFile.exists())
				if (!extDirAsFile.mkdirs())
					JOptionPane.showMessageDialog(
									null,
									"Errore",
									"Impossibile creare la directory per le estensioni",
									JOptionPane.ERROR_MESSAGE);

			if (extDirAsFile.exists())
				this.targetDir = extDir;
		}
	}

	public boolean install() throws IOException {

		installFile("SmartCardAccess-signed.jar");

		switch (os) {
		case OS_WINDOWS:
			switch (arch) {
			case ARCH_X86:
				installFile("lib32/OCFPCSC1.dll");
				installFile("lib32/pkcs11wrapper.dll");
				break;
			case ARCH_AMD64:
				this.os = OS_UNSUPPORTED;
				break;
			}
			break;
		case OS_LINUX:
			switch (arch) {
			case ARCH_X86:
				installFile("lib32/libOCFPCSC1.so");
				installFile("lib32/libpkcs11wrapper.so");
				break;
			case ARCH_AMD64:
				installFile("lib64/libOCFPCSC1.so");
				installFile("lib64/libpkcs11wrapper.so");
				break;
			}
			break;
		case OS_MAC:
			// quali librerie?
			this.os = OS_UNSUPPORTED;
			break;
		default:
			this.os = OS_UNSUPPORTED;
			break;
		}

		if (this.os == OS_UNSUPPORTED) {

			System.out
					.println("==== Smart Card Access Extension NOT installed! ====");
			showTwoThirdsOption("Sistema '" + this.osName + " "
					+ this.osArch + "' non supportato!",
					"Installation complete.", JOptionPane.ERROR_MESSAGE);

			return false;
		}

		return true;

	}

	public String getTargetDir() {
		return targetDir;
	}

	private void installFile(String name) throws IOException {

		if (this.targetDir == null) {
			System.out
					.println("Errore: Impossibile installare, directory estensioni non utilizzabile.");
			showTwoThirdsOption("Impossibile installare",
							"Impossibile installare, la directory estensioni non è utilizzabile.",
							JOptionPane.ERROR_MESSAGE);
			throw new IOException();
		}

		String s = System.getProperty("file.separator");

		// Cuts lib32 - lib64 prefix from destination name
		String destName = name.substring(name.indexOf("/") + 1);

		File f = new File(this.targetDir + s + destName);

		System.out.println("Installing '" + f.getAbsolutePath() + "'");

		boolean exists = f.isFile();

		InputStream in = getClass().getResourceAsStream(name);

		if (in != null) {

			BufferedInputStream bufIn = new BufferedInputStream(in);
			try {
				OutputStream fout = new BufferedOutputStream(
						new FileOutputStream(f));
				byte[] bytes = new byte[1024 * 10];
				for (int n = 0; n != -1; n = bufIn.read(bytes))
					fout.write(bytes, 0, n);

				fout.close();
			} catch (IOException ioe) {
				// We might get an IOException trying to overwrite an existing
				// file if there is another process using the DLL.
				// If this happens, ignore errors.
				if (!exists)
					throw ioe;
			}
		} else
			throw new IOException("Found no resource named: " + name);

	}

	public static void main(String[] args) {
		System.out
				.println("===== Smart Card Access Extension installation ====");

		Installer installer = new Installer();

		try {

			installer.install();

			System.out
					.println("==== Smart Card Access Extension installed. ====");
			
			showTwoThirdsOption("L'installazione e' stata completata\ncon successo!",
					"Installation complete.", JOptionPane.INFORMATION_MESSAGE);

		} catch (IOException e) {
			System.out.println("Error: " + e);
			System.out
					.println("==== Smart Card Access Extension NOT installed! ====");
			showTwoThirdsOption("L'installazione non si e' conclusa correttamente!",
					"Installation complete.", JOptionPane.ERROR_MESSAGE);

		}
	}
	
	private static void showTwoThirdsOption(String msg, String title, int type) {
		
		JOptionPane installOptionPane = new JOptionPane(msg, type);

		JDialog dialog = installOptionPane
				.createDialog(title);

		Dimension screenDimension = Toolkit.getDefaultToolkit().getScreenSize();
		Dimension dialogDimension = dialog.getSize();

		dialog.setLocation((screenDimension.width - dialogDimension.width) / 2,
				2 * screenDimension.height / 3 - dialogDimension.height / 2);

		dialog.setVisible(true);
	}
	
}