package it.trento.comune.j4sign.examples;
/**
 * Inserire qui la descrizione del tipo.
 * Data di creazione: (18/01/01 14.02.58)
 * @author: 
 */
class JTextAreaOutputStream extends java.io.OutputStream {
	private javax.swing.JTextArea log = null;
	private java.lang.StringBuffer buffer = null;
/**
 * Commento del constructor LogAreaWriter.
 */
protected JTextAreaOutputStream() {
	super();
}
/**
 * Inserire qui la descrizione del metodo.
 * Data di creazione: (18/01/01 14.04.23)
 * @param logArea javax.swing.JTextArea
 */
public JTextAreaOutputStream(javax.swing.JTextArea logArea) {
	log = logArea;
	buffer = new StringBuffer();
}
/**
 * Inserire qui la descrizione del metodo.
 * Data di creazione: (18/01/01 15.57.19)
 */
public void close() {
	flush();
}
/**
 * Inserire qui la descrizione del metodo.
 * Data di creazione: (18/01/01 15.51.03)
 */
public void flush() {
	log.append(buffer.toString());
	//per scrollare alla fine del testo!!!! 
	log.setCaretPosition(log.getDocument().getLength());

	buffer.delete(0, buffer.length());
}
/**
 * Inserire qui la descrizione del metodo.
 * Data di creazione: (18/01/01 14.09.04)
 * @param i int
 */
public void write(char[] cbuf, int off, int len) {
	buffer.append(cbuf, off, len);
}
/**
 * Inserire qui la descrizione del metodo.
 * Data di creazione: (18/01/01 14.09.04)
 * @param i int
 */
public void write(int i) {
	buffer.append(String.valueOf((char) (i & 0x000000ff)));
}
}
